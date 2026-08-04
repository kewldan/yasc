//! Versioned application-level encryption and secret-safe vault contracts.

#![forbid(unsafe_code)]

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use thiserror::Error;
use uuid::Uuid;
use yasc_domain::CredentialId;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const VAULT_FORMAT_VERSION: u32 = 1;
pub const VAULT_KEY_VERSION: u32 = 1;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;
const VERIFIER_PLAINTEXT: &[u8] = b"YASC vault verifier v1";

/// Secret bytes that clear their allocation on drop and never reveal contents through `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretBytes")
            .field(&format_args!("[REDACTED; {} bytes]", self.0.len()))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretKind {
    SshPrivateKey,
    Password,
    Passphrase,
    TotpSeed,
    RdpPassword,
}

impl SecretKind {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::SshPrivateKey => 1,
            Self::Password => 2,
            Self::Passphrase => 3,
            Self::TotpSeed => 4,
            Self::RdpPassword => 5,
        }
    }

    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::SshPrivateKey),
            2 => Some(Self::Password),
            3 => Some(Self::Passphrase),
            4 => Some(Self::TotpSeed),
            5 => Some(Self::RdpPassword),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretRef {
    pub id: Uuid,
    pub credential_id: CredentialId,
    pub kind: SecretKind,
}

impl SecretRef {
    #[must_use]
    pub fn new(credential_id: CredentialId, kind: SecretKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            credential_id,
            kind,
        }
    }
}

/// Stored KDF parameters. Creation uses the recommended profile; reads are bounded against DoS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultKdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl VaultKdfParams {
    #[must_use]
    pub const fn recommended() -> Self {
        Self {
            memory_kib: Params::DEFAULT_M_COST,
            iterations: Params::DEFAULT_T_COST,
            parallelism: Params::DEFAULT_P_COST,
        }
    }

    fn validate(self) -> Result<(), VaultError> {
        const MAX_MEMORY_KIB: u32 = 1024 * 1024;
        const MAX_ITERATIONS: u32 = 20;
        const MAX_PARALLELISM: u32 = 16;
        if self.memory_kib < 8
            || self.memory_kib > MAX_MEMORY_KIB
            || self.iterations == 0
            || self.iterations > MAX_ITERATIONS
            || self.parallelism == 0
            || self.parallelism > MAX_PARALLELISM
            || self.memory_kib < self.parallelism.saturating_mul(8)
        {
            return Err(VaultError::InvalidKdfParameters);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredVaultHeader {
    pub format_version: u32,
    pub kdf: VaultKdfParams,
    pub salt: Vec<u8>,
    pub verifier_nonce: Vec<u8>,
    pub verifier_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSecretEnvelope {
    pub id: Uuid,
    pub credential_id: CredentialId,
    pub kind: SecretKind,
    pub format_version: u32,
    pub key_version: u32,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Persistence boundary. Implementations store envelopes atomically and never receive plaintext.
pub trait VaultStore {
    fn load_vault_header(&self) -> Result<Option<StoredVaultHeader>, VaultStoreError>;
    fn save_vault_header(&mut self, header: &StoredVaultHeader) -> Result<(), VaultStoreError>;
    fn load_secret_envelope(
        &self,
        id: Uuid,
    ) -> Result<Option<StoredSecretEnvelope>, VaultStoreError>;
    fn save_secret_envelope(
        &mut self,
        envelope: &StoredSecretEnvelope,
    ) -> Result<(), VaultStoreError>;
    fn tombstone_secret(&mut self, id: Uuid) -> Result<bool, VaultStoreError>;
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("vault persistence operation failed")]
pub struct VaultStoreError;

/// An encrypted vault whose key exists in memory only while unlocked.
pub struct EncryptedVault<S> {
    store: S,
    header: StoredVaultHeader,
    key: Option<SecretBytes>,
}

impl<S: VaultStore> EncryptedVault<S> {
    pub fn create(store: S, password: SecretBytes) -> Result<Self, VaultError> {
        Self::create_with_params(store, password, VaultKdfParams::recommended())
    }

    fn create_with_params(
        mut store: S,
        password: SecretBytes,
        kdf: VaultKdfParams,
    ) -> Result<Self, VaultError> {
        if password.is_empty() {
            return Err(VaultError::InvalidUnlockMaterial);
        }
        if store.load_vault_header()?.is_some() {
            return Err(VaultError::AlreadyInitialized);
        }
        kdf.validate()?;

        let mut salt = vec![0_u8; SALT_LENGTH];
        getrandom::fill(&mut salt).map_err(|_| VaultError::RandomFailure)?;
        let key = derive_key(&password, &salt, kdf)?;
        let mut verifier_nonce = vec![0_u8; NONCE_LENGTH];
        getrandom::fill(&mut verifier_nonce).map_err(|_| VaultError::RandomFailure)?;
        let verifier_ciphertext = encrypt(
            &key,
            &verifier_nonce,
            VERIFIER_PLAINTEXT,
            &header_aad(VAULT_FORMAT_VERSION, kdf, &salt),
        )?;
        let header = StoredVaultHeader {
            format_version: VAULT_FORMAT_VERSION,
            kdf,
            salt,
            verifier_nonce,
            verifier_ciphertext,
        };
        store.save_vault_header(&header)?;

        Ok(Self {
            store,
            header,
            key: Some(key),
        })
    }

    pub fn open(store: S) -> Result<Self, VaultError> {
        let header = store
            .load_vault_header()?
            .ok_or(VaultError::NotInitialized)?;
        validate_header(&header)?;
        Ok(Self {
            store,
            header,
            key: None,
        })
    }

    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    fn unlocked_key(&self) -> Result<&SecretBytes, VaultError> {
        self.key.as_ref().ok_or(VaultError::Locked)
    }
}

impl<S: VaultStore> VaultBackend for EncryptedVault<S> {
    fn state(&self) -> VaultState {
        if self.key.is_some() {
            VaultState::Unlocked
        } else {
            VaultState::Locked
        }
    }

    fn unlock(&mut self, password: SecretBytes) -> Result<(), VaultError> {
        if password.is_empty() {
            return Err(VaultError::InvalidUnlockMaterial);
        }
        validate_header(&self.header)?;
        let key = derive_key(&password, &self.header.salt, self.header.kdf)?;
        let plaintext = decrypt(
            &key,
            &self.header.verifier_nonce,
            &self.header.verifier_ciphertext,
            &header_aad(
                self.header.format_version,
                self.header.kdf,
                &self.header.salt,
            ),
        )
        .map_err(|_| VaultError::InvalidUnlockMaterial)?;
        if plaintext != VERIFIER_PLAINTEXT {
            return Err(VaultError::InvalidUnlockMaterial);
        }
        self.key = Some(key);
        Ok(())
    }

    fn lock(&mut self) -> Result<(), VaultError> {
        self.key = None;
        Ok(())
    }

    fn store(
        &mut self,
        credential_id: CredentialId,
        kind: SecretKind,
        secret: SecretBytes,
    ) -> Result<SecretRef, VaultError> {
        if secret.is_empty() {
            return Err(VaultError::EmptySecret);
        }
        let reference = SecretRef::new(credential_id, kind);
        let key = self.unlocked_key()?;
        let mut nonce = vec![0_u8; NONCE_LENGTH];
        getrandom::fill(&mut nonce).map_err(|_| VaultError::RandomFailure)?;
        let envelope = StoredSecretEnvelope {
            id: reference.id,
            credential_id,
            kind,
            format_version: VAULT_FORMAT_VERSION,
            key_version: VAULT_KEY_VERSION,
            ciphertext: encrypt(
                key,
                &nonce,
                secret.expose_secret(),
                &secret_aad(reference, VAULT_FORMAT_VERSION, VAULT_KEY_VERSION),
            )?,
            nonce,
        };
        self.store.save_secret_envelope(&envelope)?;
        Ok(reference)
    }

    fn read(&self, reference: SecretRef) -> Result<SecretBytes, VaultError> {
        let key = self.unlocked_key()?;
        let envelope = self
            .store
            .load_secret_envelope(reference.id)?
            .ok_or(VaultError::NotFound)?;
        validate_envelope(&envelope, reference)?;
        let plaintext = decrypt(
            key,
            &envelope.nonce,
            &envelope.ciphertext,
            &secret_aad(reference, envelope.format_version, envelope.key_version),
        )?;
        Ok(SecretBytes::new(plaintext))
    }

    fn remove(&mut self, reference: SecretRef) -> Result<(), VaultError> {
        self.unlocked_key()?;
        if !self.store.tombstone_secret(reference.id)? {
            return Err(VaultError::NotFound);
        }
        Ok(())
    }
}

/// Backend contract. Implementations must encrypt persisted values before storage.
pub trait VaultBackend {
    fn state(&self) -> VaultState;
    fn unlock(&mut self, unlock_material: SecretBytes) -> Result<(), VaultError>;
    fn lock(&mut self) -> Result<(), VaultError>;
    fn store(
        &mut self,
        credential_id: CredentialId,
        kind: SecretKind,
        secret: SecretBytes,
    ) -> Result<SecretRef, VaultError>;
    fn read(&self, secret: SecretRef) -> Result<SecretBytes, VaultError>;
    fn remove(&mut self, secret: SecretRef) -> Result<(), VaultError>;
}

fn validate_header(header: &StoredVaultHeader) -> Result<(), VaultError> {
    if header.format_version > VAULT_FORMAT_VERSION {
        return Err(VaultError::NewerFormat {
            found: header.format_version,
            supported: VAULT_FORMAT_VERSION,
        });
    }
    if header.format_version != VAULT_FORMAT_VERSION
        || header.salt.len() != SALT_LENGTH
        || header.verifier_nonce.len() != NONCE_LENGTH
        || header.verifier_ciphertext.len() < 16
    {
        return Err(VaultError::InvalidEnvelope);
    }
    header.kdf.validate()
}

fn validate_envelope(
    envelope: &StoredSecretEnvelope,
    reference: SecretRef,
) -> Result<(), VaultError> {
    if envelope.format_version > VAULT_FORMAT_VERSION {
        return Err(VaultError::NewerFormat {
            found: envelope.format_version,
            supported: VAULT_FORMAT_VERSION,
        });
    }
    if envelope.id != reference.id
        || envelope.credential_id != reference.credential_id
        || envelope.kind != reference.kind
        || envelope.format_version != VAULT_FORMAT_VERSION
        || envelope.key_version != VAULT_KEY_VERSION
        || envelope.nonce.len() != NONCE_LENGTH
        || envelope.ciphertext.len() < 16
    {
        return Err(VaultError::InvalidEnvelope);
    }
    Ok(())
}

fn derive_key(
    password: &SecretBytes,
    salt: &[u8],
    parameters: VaultKdfParams,
) -> Result<SecretBytes, VaultError> {
    parameters.validate()?;
    let params = Params::new(
        parameters.memory_kib,
        parameters.iterations,
        parameters.parallelism,
        Some(KEY_LENGTH),
    )
    .map_err(|_| VaultError::InvalidKdfParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = vec![0_u8; KEY_LENGTH];
    argon2
        .hash_password_into(password.expose_secret(), salt, &mut key)
        .map_err(|_| VaultError::KdfFailure)?;
    Ok(SecretBytes::new(key))
}

fn encrypt(
    key: &SecretBytes,
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| VaultError::InvalidEnvelope)?;
    let nonce = XNonce::try_from(nonce).map_err(|_| VaultError::InvalidEnvelope)?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::EncryptionFailed)
}

fn decrypt(
    key: &SecretBytes,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| VaultError::InvalidEnvelope)?;
    let nonce = XNonce::try_from(nonce).map_err(|_| VaultError::InvalidEnvelope)?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)
}

fn header_aad(format_version: u32, kdf: VaultKdfParams, salt: &[u8]) -> Vec<u8> {
    let mut aad = b"YASC\0vault-header\0".to_vec();
    aad.extend_from_slice(&format_version.to_be_bytes());
    aad.extend_from_slice(&kdf.memory_kib.to_be_bytes());
    aad.extend_from_slice(&kdf.iterations.to_be_bytes());
    aad.extend_from_slice(&kdf.parallelism.to_be_bytes());
    aad.extend_from_slice(salt);
    aad
}

fn secret_aad(reference: SecretRef, format_version: u32, key_version: u32) -> Vec<u8> {
    let mut aad = b"YASC\0secret-envelope\0".to_vec();
    aad.extend_from_slice(&format_version.to_be_bytes());
    aad.extend_from_slice(&key_version.to_be_bytes());
    aad.extend_from_slice(reference.id.as_bytes());
    aad.extend_from_slice(reference.credential_id.as_uuid().as_bytes());
    aad.push(reference.kind.code());
    aad
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("vault is not initialized")]
    NotInitialized,
    #[error("vault is already initialized")]
    AlreadyInitialized,
    #[error("secret was not found")]
    NotFound,
    #[error("secret cannot be empty")]
    EmptySecret,
    #[error("unlock material is invalid")]
    InvalidUnlockMaterial,
    #[error("vault KDF parameters are invalid or unsafe")]
    InvalidKdfParameters,
    #[error("vault key derivation failed")]
    KdfFailure,
    #[error("secure random generation failed")]
    RandomFailure,
    #[error("vault format version {found} is newer than supported version {supported}")]
    NewerFormat { found: u32, supported: u32 },
    #[error("vault envelope structure is invalid")]
    InvalidEnvelope,
    #[error("vault data failed authentication")]
    AuthenticationFailed,
    #[error("vault encryption failed")]
    EncryptionFailed,
    #[error(transparent)]
    Store(#[from] VaultStoreError),
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Default)]
    struct MemoryStore {
        header: Option<StoredVaultHeader>,
        secrets: HashMap<Uuid, StoredSecretEnvelope>,
    }

    impl VaultStore for MemoryStore {
        fn load_vault_header(&self) -> Result<Option<StoredVaultHeader>, VaultStoreError> {
            Ok(self.header.clone())
        }

        fn save_vault_header(&mut self, header: &StoredVaultHeader) -> Result<(), VaultStoreError> {
            if self.header.is_some() {
                return Err(VaultStoreError);
            }
            self.header = Some(header.clone());
            Ok(())
        }

        fn load_secret_envelope(
            &self,
            id: Uuid,
        ) -> Result<Option<StoredSecretEnvelope>, VaultStoreError> {
            Ok(self.secrets.get(&id).cloned())
        }

        fn save_secret_envelope(
            &mut self,
            envelope: &StoredSecretEnvelope,
        ) -> Result<(), VaultStoreError> {
            self.secrets.insert(envelope.id, envelope.clone());
            Ok(())
        }

        fn tombstone_secret(&mut self, id: Uuid) -> Result<bool, VaultStoreError> {
            Ok(self.secrets.remove(&id).is_some())
        }
    }

    fn fast_kdf() -> VaultKdfParams {
        VaultKdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn new_vault() -> EncryptedVault<MemoryStore> {
        EncryptedVault::create_with_params(
            MemoryStore::default(),
            SecretBytes::new(b"test password".to_vec()),
            fast_kdf(),
        )
        .unwrap()
    }

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretBytes::new(b"correct horse battery staple".to_vec());
        let output = format!("{secret:?}");

        assert!(output.contains("REDACTED"));
        assert!(!output.contains("correct horse"));
    }

    #[test]
    fn explicit_zeroize_clears_exposed_bytes() {
        let mut secret = SecretBytes::new(vec![1, 2, 3, 4]);

        secret.zeroize();

        assert!(secret.expose_secret().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn lock_blocks_reads_and_correct_password_unlocks() {
        let mut vault = new_vault();
        let credential_id = CredentialId::new();
        let reference = vault
            .store(
                credential_id,
                SecretKind::Password,
                SecretBytes::new(b"s3cret".to_vec()),
            )
            .unwrap();

        vault.lock().unwrap();
        assert_eq!(vault.read(reference).unwrap_err(), VaultError::Locked);
        assert_eq!(
            vault
                .unlock(SecretBytes::new(b"wrong password".to_vec()))
                .unwrap_err(),
            VaultError::InvalidUnlockMaterial
        );
        vault
            .unlock(SecretBytes::new(b"test password".to_vec()))
            .unwrap();
        assert_eq!(vault.read(reference).unwrap().expose_secret(), b"s3cret");
    }

    #[test]
    fn ciphertext_tampering_is_detected() {
        let mut vault = new_vault();
        let reference = vault
            .store(
                CredentialId::new(),
                SecretKind::SshPrivateKey,
                SecretBytes::new(b"private key bytes".to_vec()),
            )
            .unwrap();
        let mut store = vault.into_store();
        store.secrets.get_mut(&reference.id).unwrap().ciphertext[0] ^= 1;

        let mut reopened = EncryptedVault::open(store).unwrap();
        reopened
            .unlock(SecretBytes::new(b"test password".to_vec()))
            .unwrap();
        assert_eq!(
            reopened.read(reference).unwrap_err(),
            VaultError::AuthenticationFailed
        );
    }

    #[test]
    fn metadata_substitution_is_detected() {
        let mut vault = new_vault();
        let reference = vault
            .store(
                CredentialId::new(),
                SecretKind::Password,
                SecretBytes::new(b"database password".to_vec()),
            )
            .unwrap();
        let mut store = vault.into_store();
        let envelope = store.secrets.get_mut(&reference.id).unwrap();
        envelope.kind = SecretKind::Passphrase;

        let mut reopened = EncryptedVault::open(store).unwrap();
        reopened
            .unlock(SecretBytes::new(b"test password".to_vec()))
            .unwrap();
        assert_eq!(
            reopened.read(reference).unwrap_err(),
            VaultError::InvalidEnvelope
        );
    }

    #[test]
    fn header_parameter_tampering_blocks_unlock() {
        let vault = new_vault();
        let mut store = vault.into_store();
        store.header.as_mut().unwrap().kdf.iterations += 1;

        let mut reopened = EncryptedVault::open(store).unwrap();
        assert_eq!(
            reopened
                .unlock(SecretBytes::new(b"test password".to_vec()))
                .unwrap_err(),
            VaultError::InvalidUnlockMaterial
        );
    }

    #[test]
    fn newer_vault_format_is_rejected() {
        let vault = new_vault();
        let mut store = vault.into_store();
        store.header.as_mut().unwrap().format_version = VAULT_FORMAT_VERSION + 1;

        assert!(matches!(
            EncryptedVault::open(store),
            Err(VaultError::NewerFormat { .. })
        ));
    }
}
