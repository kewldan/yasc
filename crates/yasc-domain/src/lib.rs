//! Stable product types and validation rules shared by every YASC application.

#![forbid(unsafe_code)]

mod credential;
mod host;

pub use credential::{
    Credential, CredentialCapabilities, CredentialCapabilityError, CredentialGrant,
    CredentialGrantError, CredentialId, CredentialProviderKind, CredentialUsage, Custody, GrantId,
    Synchronization,
};
pub use host::{Host, HostError, HostId, SshTarget, TargetParseError};
