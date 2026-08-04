//! Secret-safe credential lifecycle contracts.

#![forbid(unsafe_code)]

use std::fmt;

use thiserror::Error;
use uuid::Uuid;
use yasc_domain::CredentialId;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("secret was not found")]
    NotFound,
    #[error("unlock material is invalid")]
    InvalidUnlockMaterial,
    #[error("vault format version {found} is newer than supported version {supported}")]
    NewerFormat { found: u32, supported: u32 },
    #[error("vault data failed authentication")]
    AuthenticationFailed,
    #[error("vault backend operation failed")]
    BackendFailure,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
