//! Stable product types and validation rules shared by every YASC application.

#![forbid(unsafe_code)]

mod credential;
mod host;
mod host_key;

pub use credential::{
    Credential, CredentialCapabilities, CredentialCapabilityError, CredentialGrant,
    CredentialGrantError, CredentialId, CredentialProviderKind, CredentialUsage, Custody, GrantId,
    Synchronization,
};
pub use host::{Host, HostError, HostId, SshTarget, TargetParseError};
pub use host_key::{
    HostKeyAlgorithm, HostKeyDecision, HostKeyError, HostKeyEvent, HostKeyEventId,
    HostKeyEventKind, HostKeyFingerprint, HostKeyHistory, HostKeyId, HostKeyMaterial,
    HostKeyObservation, HostKeyPolicy, HostKeyPolicyMode, HostKeyRecord, HostKeyRecordState,
    HostKeySource,
};
