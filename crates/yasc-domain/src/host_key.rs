use std::{collections::BTreeSet, fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::HostId;

macro_rules! define_id {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

define_id!(HostKeyId);
define_id!(HostKeyEventId);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostKeyAlgorithm(String);

impl HostKeyAlgorithm {
    pub fn new(value: impl Into<String>) -> Result<Self, HostKeyError> {
        let value = value.into();
        if value.is_empty()
            || value.starts_with('-')
            || value.chars().any(|character| {
                character.is_whitespace() || character.is_control() || character == ','
            })
        {
            return Err(HostKeyError::InvalidAlgorithm);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostKeyAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for HostKeyAlgorithm {
    type Err = HostKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostKeyFingerprint(String);

impl HostKeyFingerprint {
    #[must_use]
    pub fn sha256(key_blob: &[u8]) -> Self {
        let digest = Sha256::digest(key_blob);
        Self(format!(
            "SHA256:{}",
            general_purpose::STANDARD_NO_PAD.encode(digest)
        ))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostKeyFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for HostKeyFingerprint {
    type Err = HostKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let encoded = value
            .strip_prefix("SHA256:")
            .ok_or(HostKeyError::InvalidFingerprint)?;
        let decoded = general_purpose::STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| HostKeyError::InvalidFingerprint)?;
        if decoded.len() != 32 {
            return Err(HostKeyError::InvalidFingerprint);
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyMaterial {
    pub algorithm: HostKeyAlgorithm,
    #[serde(skip_serializing)]
    pub key_blob: Vec<u8>,
    pub fingerprint: HostKeyFingerprint,
}

impl HostKeyMaterial {
    pub fn new(
        algorithm: HostKeyAlgorithm,
        key_blob: impl Into<Vec<u8>>,
    ) -> Result<Self, HostKeyError> {
        let key_blob = key_blob.into();
        if key_blob.is_empty() {
            return Err(HostKeyError::EmptyKeyBlob);
        }
        let fingerprint = HostKeyFingerprint::sha256(&key_blob);
        Ok(Self {
            algorithm,
            key_blob,
            fingerprint,
        })
    }

    pub fn from_openssh_base64(
        algorithm: HostKeyAlgorithm,
        encoded: &str,
    ) -> Result<Self, HostKeyError> {
        let key_blob = general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| HostKeyError::InvalidKeyBlobEncoding)?;
        let algorithm_length = key_blob
            .get(..4)
            .and_then(|length| <[u8; 4]>::try_from(length).ok())
            .map(u32::from_be_bytes)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or(HostKeyError::InvalidKeyBlobEncoding)?;
        let algorithm_end = 4usize
            .checked_add(algorithm_length)
            .ok_or(HostKeyError::InvalidKeyBlobEncoding)?;
        let embedded_algorithm = key_blob
            .get(4..algorithm_end)
            .and_then(|value| std::str::from_utf8(value).ok())
            .ok_or(HostKeyError::InvalidKeyBlobEncoding)?;
        if embedded_algorithm != algorithm.as_str() {
            return Err(HostKeyError::KeyAlgorithmMismatch);
        }
        if key_blob
            .get(algorithm_end..algorithm_end.saturating_add(4))
            .is_none()
        {
            return Err(HostKeyError::InvalidKeyBlobEncoding);
        }
        Self::new(algorithm, key_blob)
    }

    pub fn restore(
        algorithm: HostKeyAlgorithm,
        key_blob: Vec<u8>,
        fingerprint: HostKeyFingerprint,
    ) -> Result<Self, HostKeyError> {
        if key_blob.is_empty() || HostKeyFingerprint::sha256(&key_blob) != fingerprint {
            return Err(HostKeyError::FingerprintMismatch);
        }
        Ok(Self {
            algorithm,
            key_blob,
            fingerprint,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeySource {
    Presented,
    KnownHostsImport,
    DnsSshfp,
    CertificateAuthority,
    UpdateHostKeys,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyObservation {
    pub material: HostKeyMaterial,
    pub source: HostKeySource,
    pub certificate_authority: Option<HostKeyFingerprint>,
    pub authenticated_by: Option<HostKeyFingerprint>,
}

impl HostKeyObservation {
    #[must_use]
    pub const fn presented(material: HostKeyMaterial) -> Self {
        Self {
            material,
            source: HostKeySource::Presented,
            certificate_authority: None,
            authenticated_by: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyPolicyMode {
    Strict,
    AskOnFirstUse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyPolicy {
    pub mode: HostKeyPolicyMode,
    pub allow_update_host_keys: bool,
    pub trusted_certificate_authorities: BTreeSet<HostKeyFingerprint>,
    pub revoked_certificate_authorities: BTreeSet<HostKeyFingerprint>,
}

impl HostKeyPolicy {
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            mode: HostKeyPolicyMode::Strict,
            allow_update_host_keys: false,
            trusted_certificate_authorities: BTreeSet::new(),
            revoked_certificate_authorities: BTreeSet::new(),
        }
    }

    #[must_use]
    pub const fn ask_on_first_use() -> Self {
        Self {
            mode: HostKeyPolicyMode::AskOnFirstUse,
            allow_update_host_keys: false,
            trusted_certificate_authorities: BTreeSet::new(),
            revoked_certificate_authorities: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyRecordState {
    Trusted,
    Superseded,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyRecord {
    pub id: HostKeyId,
    pub host_id: HostId,
    pub material: HostKeyMaterial,
    pub state: HostKeyRecordState,
    pub source: HostKeySource,
    pub first_seen_at_unix: i64,
    pub last_seen_at_unix: i64,
    pub superseded_by: Option<HostKeyId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyEventKind {
    TrustedFirstUse,
    RotatedManual,
    LearnedUpdate,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyEvent {
    pub id: HostKeyEventId,
    pub host_id: HostId,
    pub fingerprint: HostKeyFingerprint,
    pub previous_fingerprint: Option<HostKeyFingerprint>,
    pub kind: HostKeyEventKind,
    pub source: HostKeySource,
    pub occurred_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum HostKeyDecision {
    AcceptKnown {
        record_id: HostKeyId,
    },
    AcceptCertificate {
        authority: HostKeyFingerprint,
    },
    AcceptAuthenticatedUpdate {
        authenticated_by: HostKeyFingerprint,
    },
    ConfirmFirstUse,
    RejectUnknownStrict,
    RejectChanged {
        active_fingerprints: Vec<HostKeyFingerprint>,
    },
    RejectRevoked,
    RejectUntrustedCertificate,
}

impl HostKeyDecision {
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(
            self,
            Self::AcceptKnown { .. }
                | Self::AcceptCertificate { .. }
                | Self::AcceptAuthenticatedUpdate { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyHistory {
    host_id: HostId,
    records: Vec<HostKeyRecord>,
}

impl HostKeyHistory {
    #[must_use]
    pub const fn new(host_id: HostId) -> Self {
        Self {
            host_id,
            records: Vec::new(),
        }
    }

    pub fn restore(host_id: HostId, records: Vec<HostKeyRecord>) -> Result<Self, HostKeyError> {
        let mut fingerprints = BTreeSet::new();
        for record in &records {
            if record.host_id != host_id
                || record.first_seen_at_unix < 0
                || record.last_seen_at_unix < record.first_seen_at_unix
                || !fingerprints.insert(record.material.fingerprint.clone())
            {
                return Err(HostKeyError::InvalidHistory);
            }
        }
        Ok(Self { host_id, records })
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub fn records(&self) -> &[HostKeyRecord] {
        &self.records
    }

    #[must_use]
    pub fn evaluate(
        &self,
        observation: &HostKeyObservation,
        policy: &HostKeyPolicy,
    ) -> HostKeyDecision {
        if self.records.iter().any(|record| {
            record.material.fingerprint == observation.material.fingerprint
                && record.state == HostKeyRecordState::Revoked
        }) {
            return HostKeyDecision::RejectRevoked;
        }

        if let Some(authority) = &observation.certificate_authority {
            if policy.revoked_certificate_authorities.contains(authority) {
                return HostKeyDecision::RejectRevoked;
            }
            if policy.trusted_certificate_authorities.contains(authority) {
                return HostKeyDecision::AcceptCertificate {
                    authority: authority.clone(),
                };
            }
            return HostKeyDecision::RejectUntrustedCertificate;
        }

        if let Some(record) = self.records.iter().find(|record| {
            record.material.fingerprint == observation.material.fingerprint
                && record.state == HostKeyRecordState::Trusted
        }) {
            return HostKeyDecision::AcceptKnown {
                record_id: record.id,
            };
        }

        if observation.source == HostKeySource::UpdateHostKeys
            && policy.allow_update_host_keys
            && let Some(authenticated_by) = &observation.authenticated_by
            && self.records.iter().any(|record| {
                record.material.fingerprint == *authenticated_by
                    && record.state == HostKeyRecordState::Trusted
            })
        {
            return HostKeyDecision::AcceptAuthenticatedUpdate {
                authenticated_by: authenticated_by.clone(),
            };
        }

        let active_fingerprints = self
            .records
            .iter()
            .filter(|record| record.state == HostKeyRecordState::Trusted)
            .map(|record| record.material.fingerprint.clone())
            .collect::<Vec<_>>();
        if active_fingerprints.is_empty() {
            return match policy.mode {
                HostKeyPolicyMode::Strict => HostKeyDecision::RejectUnknownStrict,
                HostKeyPolicyMode::AskOnFirstUse => HostKeyDecision::ConfirmFirstUse,
            };
        }

        HostKeyDecision::RejectChanged {
            active_fingerprints,
        }
    }

    pub fn trust_first_use(
        &mut self,
        observation: HostKeyObservation,
        now_unix: i64,
    ) -> Result<HostKeyEvent, HostKeyError> {
        validate_timestamp(now_unix)?;
        if self
            .records
            .iter()
            .any(|record| record.state == HostKeyRecordState::Trusted)
        {
            return Err(HostKeyError::ExistingTrustedKey);
        }
        if self.records.iter().any(|record| {
            record.material.fingerprint == observation.material.fingerprint
                && record.state == HostKeyRecordState::Revoked
        }) {
            return Err(HostKeyError::RevokedKey);
        }
        let fingerprint = observation.material.fingerprint.clone();
        self.insert_trusted(observation.material, observation.source, now_unix)?;
        Ok(HostKeyEvent {
            id: HostKeyEventId::new(),
            host_id: self.host_id,
            fingerprint,
            previous_fingerprint: None,
            kind: HostKeyEventKind::TrustedFirstUse,
            source: observation.source,
            occurred_at_unix: now_unix,
        })
    }

    pub fn trust_manual_change(
        &mut self,
        observation: HostKeyObservation,
        expected_current: &HostKeyFingerprint,
        now_unix: i64,
    ) -> Result<HostKeyEvent, HostKeyError> {
        validate_timestamp(now_unix)?;
        let current_index = self
            .records
            .iter()
            .position(|record| {
                record.material.fingerprint == *expected_current
                    && record.state == HostKeyRecordState::Trusted
            })
            .ok_or(HostKeyError::ExpectedTrustedKeyMissing)?;
        if self.records.iter().any(|record| {
            record.material.fingerprint == observation.material.fingerprint
                && record.state == HostKeyRecordState::Revoked
        }) {
            return Err(HostKeyError::RevokedKey);
        }
        if self
            .records
            .iter()
            .any(|record| record.material.fingerprint == observation.material.fingerprint)
        {
            return Err(HostKeyError::DuplicateFingerprint);
        }

        let replacement_id = HostKeyId::new();
        self.records[current_index].state = HostKeyRecordState::Superseded;
        self.records[current_index].last_seen_at_unix = now_unix;
        self.records[current_index].superseded_by = Some(replacement_id);
        let fingerprint = observation.material.fingerprint.clone();
        self.records.push(HostKeyRecord {
            id: replacement_id,
            host_id: self.host_id,
            material: observation.material,
            state: HostKeyRecordState::Trusted,
            source: HostKeySource::Manual,
            first_seen_at_unix: now_unix,
            last_seen_at_unix: now_unix,
            superseded_by: None,
        });
        Ok(HostKeyEvent {
            id: HostKeyEventId::new(),
            host_id: self.host_id,
            fingerprint,
            previous_fingerprint: Some(expected_current.clone()),
            kind: HostKeyEventKind::RotatedManual,
            source: HostKeySource::Manual,
            occurred_at_unix: now_unix,
        })
    }

    pub fn trust_authenticated_update(
        &mut self,
        observation: HostKeyObservation,
        policy: &HostKeyPolicy,
        now_unix: i64,
    ) -> Result<HostKeyEvent, HostKeyError> {
        validate_timestamp(now_unix)?;
        let HostKeyDecision::AcceptAuthenticatedUpdate { authenticated_by } =
            self.evaluate(&observation, policy)
        else {
            return Err(HostKeyError::UnauthenticatedUpdate);
        };
        let fingerprint = observation.material.fingerprint.clone();
        self.insert_trusted(
            observation.material,
            HostKeySource::UpdateHostKeys,
            now_unix,
        )?;
        Ok(HostKeyEvent {
            id: HostKeyEventId::new(),
            host_id: self.host_id,
            fingerprint,
            previous_fingerprint: Some(authenticated_by),
            kind: HostKeyEventKind::LearnedUpdate,
            source: HostKeySource::UpdateHostKeys,
            occurred_at_unix: now_unix,
        })
    }

    pub fn revoke(
        &mut self,
        fingerprint: &HostKeyFingerprint,
        now_unix: i64,
    ) -> Result<HostKeyEvent, HostKeyError> {
        validate_timestamp(now_unix)?;
        let record = self
            .records
            .iter_mut()
            .find(|record| record.material.fingerprint == *fingerprint)
            .ok_or(HostKeyError::KeyNotFound)?;
        if record.state == HostKeyRecordState::Revoked {
            return Err(HostKeyError::AlreadyRevoked);
        }
        record.state = HostKeyRecordState::Revoked;
        record.last_seen_at_unix = now_unix.max(record.last_seen_at_unix);
        Ok(HostKeyEvent {
            id: HostKeyEventId::new(),
            host_id: self.host_id,
            fingerprint: fingerprint.clone(),
            previous_fingerprint: None,
            kind: HostKeyEventKind::Revoked,
            source: HostKeySource::Manual,
            occurred_at_unix: now_unix,
        })
    }

    fn insert_trusted(
        &mut self,
        material: HostKeyMaterial,
        source: HostKeySource,
        now_unix: i64,
    ) -> Result<HostKeyId, HostKeyError> {
        if self
            .records
            .iter()
            .any(|record| record.material.fingerprint == material.fingerprint)
        {
            return Err(HostKeyError::DuplicateFingerprint);
        }
        let id = HostKeyId::new();
        self.records.push(HostKeyRecord {
            id,
            host_id: self.host_id,
            material,
            state: HostKeyRecordState::Trusted,
            source,
            first_seen_at_unix: now_unix,
            last_seen_at_unix: now_unix,
            superseded_by: None,
        });
        Ok(id)
    }
}

fn validate_timestamp(timestamp: i64) -> Result<(), HostKeyError> {
    if timestamp < 0 {
        return Err(HostKeyError::InvalidTimestamp);
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostKeyError {
    #[error("host-key algorithm is invalid")]
    InvalidAlgorithm,
    #[error("host-key fingerprint is invalid")]
    InvalidFingerprint,
    #[error("host-key blob cannot be empty")]
    EmptyKeyBlob,
    #[error("host-key blob is not valid OpenSSH base64")]
    InvalidKeyBlobEncoding,
    #[error("declared host-key algorithm does not match the OpenSSH key blob")]
    KeyAlgorithmMismatch,
    #[error("stored host-key fingerprint does not match its key blob")]
    FingerprintMismatch,
    #[error("host-key history is invalid")]
    InvalidHistory,
    #[error("timestamp is invalid")]
    InvalidTimestamp,
    #[error("a trusted host key already exists")]
    ExistingTrustedKey,
    #[error("the host key is revoked")]
    RevokedKey,
    #[error("expected current trusted host key was not found")]
    ExpectedTrustedKeyMissing,
    #[error("UpdateHostKeys observation was not authenticated by an active trusted key")]
    UnauthenticatedUpdate,
    #[error("host key was not found")]
    KeyNotFound,
    #[error("host key is already revoked")]
    AlreadyRevoked,
    #[error("host-key fingerprint already exists in history")]
    DuplicateFingerprint,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material(seed: u8, algorithm: &str) -> HostKeyMaterial {
        HostKeyMaterial::new(algorithm.parse().unwrap(), vec![seed; 32]).unwrap()
    }

    fn observation(seed: u8, algorithm: &str) -> HostKeyObservation {
        HostKeyObservation::presented(material(seed, algorithm))
    }

    #[test]
    fn strict_rejects_unknown_and_tofu_requires_confirmation() {
        let history = HostKeyHistory::new(HostId::new());
        let observation = observation(1, "ssh-ed25519");

        assert_eq!(
            history.evaluate(&observation, &HostKeyPolicy::strict()),
            HostKeyDecision::RejectUnknownStrict
        );
        assert_eq!(
            history.evaluate(&observation, &HostKeyPolicy::ask_on_first_use()),
            HostKeyDecision::ConfirmFirstUse
        );
    }

    #[test]
    fn known_key_is_accepted_and_changed_key_is_rejected() {
        let mut history = HostKeyHistory::new(HostId::new());
        history
            .trust_first_use(observation(1, "ssh-ed25519"), 10)
            .unwrap();

        assert!(matches!(
            history.evaluate(&observation(1, "ssh-ed25519"), &HostKeyPolicy::strict()),
            HostKeyDecision::AcceptKnown { .. }
        ));
        assert!(matches!(
            history.evaluate(&observation(2, "ssh-ed25519"), &HostKeyPolicy::strict()),
            HostKeyDecision::RejectChanged { .. }
        ));
    }

    #[test]
    fn revoked_key_is_never_accepted() {
        let mut history = HostKeyHistory::new(HostId::new());
        let observation = observation(1, "ssh-ed25519");
        history.trust_first_use(observation.clone(), 10).unwrap();
        history
            .revoke(&observation.material.fingerprint, 20)
            .unwrap();

        assert_eq!(
            history.evaluate(&observation, &HostKeyPolicy::ask_on_first_use()),
            HostKeyDecision::RejectRevoked
        );
        assert_eq!(
            history.revoke(&observation.material.fingerprint, 30),
            Err(HostKeyError::AlreadyRevoked)
        );
    }

    #[test]
    fn update_host_keys_requires_authenticated_active_key() {
        let mut history = HostKeyHistory::new(HostId::new());
        let first = observation(1, "ssh-ed25519");
        history.trust_first_use(first.clone(), 10).unwrap();
        let mut update = observation(2, "ssh-rsa");
        update.source = HostKeySource::UpdateHostKeys;
        let mut policy = HostKeyPolicy::strict();
        policy.allow_update_host_keys = true;

        assert_eq!(
            history.evaluate(&update, &policy),
            HostKeyDecision::RejectChanged {
                active_fingerprints: vec![first.material.fingerprint.clone()]
            }
        );
        update.authenticated_by = Some(first.material.fingerprint.clone());
        assert!(matches!(
            history.evaluate(&update, &policy),
            HostKeyDecision::AcceptAuthenticatedUpdate { .. }
        ));
        history
            .trust_authenticated_update(update.clone(), &policy, 20)
            .unwrap();
        assert!(matches!(
            history.evaluate(&update, &policy),
            HostKeyDecision::AcceptKnown { .. }
        ));
    }

    #[test]
    fn manual_rotation_supersedes_only_expected_key() {
        let mut history = HostKeyHistory::new(HostId::new());
        let first = observation(1, "ssh-ed25519");
        history.trust_first_use(first.clone(), 10).unwrap();
        let replacement = observation(2, "ssh-ed25519");
        history
            .trust_manual_change(replacement.clone(), &first.material.fingerprint, 20)
            .unwrap();

        assert!(matches!(
            history.evaluate(&first, &HostKeyPolicy::strict()),
            HostKeyDecision::RejectChanged { .. }
        ));
        assert!(matches!(
            history.evaluate(&replacement, &HostKeyPolicy::strict()),
            HostKeyDecision::AcceptKnown { .. }
        ));
        assert_eq!(history.records[0].state, HostKeyRecordState::Superseded);
    }

    #[test]
    fn manual_rotation_rejects_duplicate_without_mutating_history() {
        let mut history = HostKeyHistory::new(HostId::new());
        let first = observation(1, "ssh-ed25519");
        history.trust_first_use(first.clone(), 10).unwrap();

        assert_eq!(
            history.trust_manual_change(first.clone(), &first.material.fingerprint, 20),
            Err(HostKeyError::DuplicateFingerprint)
        );
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].state, HostKeyRecordState::Trusted);
        assert_eq!(history.records[0].last_seen_at_unix, 10);
    }

    #[test]
    fn trusted_ca_accepts_certificate_and_revocation_wins() {
        let history = HostKeyHistory::new(HostId::new());
        let mut observation = observation(3, "ssh-ed25519-cert-v01@openssh.com");
        let authority = HostKeyFingerprint::sha256(b"authority");
        observation.certificate_authority = Some(authority.clone());
        let mut policy = HostKeyPolicy::strict();
        policy
            .trusted_certificate_authorities
            .insert(authority.clone());

        assert_eq!(
            history.evaluate(&observation, &policy),
            HostKeyDecision::AcceptCertificate {
                authority: authority.clone()
            }
        );
        policy.revoked_certificate_authorities.insert(authority);
        assert_eq!(
            history.evaluate(&observation, &policy),
            HostKeyDecision::RejectRevoked
        );
    }

    #[test]
    fn restoring_mismatched_fingerprint_fails() {
        let error = HostKeyMaterial::restore(
            "ssh-ed25519".parse().unwrap(),
            vec![1; 32],
            HostKeyFingerprint::sha256(&[2; 32]),
        )
        .unwrap_err();

        assert_eq!(error, HostKeyError::FingerprintMismatch);
    }

    #[test]
    fn openssh_blob_requires_matching_embedded_algorithm() {
        let material = material(1, "ssh-ed25519");
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&material.key_blob);
        let encoded = general_purpose::STANDARD.encode(&blob);

        assert!(
            HostKeyMaterial::from_openssh_base64("ssh-ed25519".parse().unwrap(), &encoded).is_ok()
        );
        assert_eq!(
            HostKeyMaterial::from_openssh_base64("ssh-rsa".parse().unwrap(), &encoded),
            Err(HostKeyError::KeyAlgorithmMismatch)
        );
        assert_eq!(
            HostKeyMaterial::from_openssh_base64(
                "ssh-ed25519".parse().unwrap(),
                &general_purpose::STANDARD.encode(b"short")
            ),
            Err(HostKeyError::InvalidKeyBlobEncoding)
        );
    }
}
