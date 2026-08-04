use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

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
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
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

define_id!(CredentialId);
define_id!(GrantId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Custody {
    Exportable,
    HardwareBound,
    ExternalProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Synchronization {
    LocalOnly,
    PrivateSynced,
    ServerDelegated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialUsage {
    DirectSsh,
    MediatedSsh,
    Automation,
    RdpNla,
    AgentForwarding,
    Export,
    Sharing,
    Rotation,
    Recovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProviderKind {
    LocalVault,
    NativeKeystore,
    OpenSshAgent,
    Pageant,
    Pkcs11,
    Fido,
    ExternalPasswordManager,
    ServerDelegation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalKeyReference {
    pub algorithm: String,
    pub public_key_blob: Vec<u8>,
    pub comment: Option<String>,
}

impl ExternalKeyReference {
    pub fn new(
        algorithm: impl Into<String>,
        public_key_blob: impl Into<Vec<u8>>,
        comment: Option<String>,
    ) -> Result<Self, CredentialCapabilityError> {
        let algorithm = algorithm.into();
        let public_key_blob = public_key_blob.into();
        if algorithm.is_empty()
            || algorithm.len() > 128
            || algorithm.chars().any(char::is_control)
            || public_key_blob.is_empty()
            || public_key_blob.len() > 64 * 1024
            || comment
                .as_ref()
                .is_some_and(|value| value.len() > 1024 || value.chars().any(char::is_control))
        {
            return Err(CredentialCapabilityError::InvalidExternalKeyReference);
        }
        Ok(Self {
            algorithm,
            public_key_blob,
            comment,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialCapabilities {
    pub custody: Custody,
    pub synchronization: Synchronization,
    pub allowed_usages: BTreeSet<CredentialUsage>,
}

impl CredentialCapabilities {
    pub fn new(
        custody: Custody,
        synchronization: Synchronization,
        allowed_usages: impl IntoIterator<Item = CredentialUsage>,
    ) -> Result<Self, CredentialCapabilityError> {
        let allowed_usages = allowed_usages.into_iter().collect::<BTreeSet<_>>();
        if allowed_usages.is_empty() {
            return Err(CredentialCapabilityError::NoAllowedUsage);
        }
        if custody != Custody::Exportable && synchronization != Synchronization::LocalOnly {
            return Err(CredentialCapabilityError::NonExportableCannotSync);
        }
        if custody != Custody::Exportable && allowed_usages.contains(&CredentialUsage::Export) {
            return Err(CredentialCapabilityError::NonExportableCannotBeExported);
        }
        if synchronization == Synchronization::PrivateSynced
            && allowed_usages.contains(&CredentialUsage::MediatedSsh)
        {
            return Err(CredentialCapabilityError::PrivateSyncCannotMediate);
        }

        Ok(Self {
            custody,
            synchronization,
            allowed_usages,
        })
    }

    #[must_use]
    pub fn allows(&self, usage: CredentialUsage) -> bool {
        self.allowed_usages.contains(&usage)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CredentialCapabilityError {
    #[error("a credential must allow at least one usage")]
    NoAllowedUsage,
    #[error("hardware-bound and external-provider credentials must remain local-only")]
    NonExportableCannotSync,
    #[error("a non-exportable credential cannot grant export usage")]
    NonExportableCannotBeExported,
    #[error("private synchronization does not authorize mediated SSH")]
    PrivateSyncCannotMediate,
    #[error("external key reference metadata is invalid")]
    InvalidExternalKeyReference,
    #[error("credential provider and external key reference do not agree")]
    ProviderReferenceMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub id: CredentialId,
    pub label: String,
    pub provider: CredentialProviderKind,
    pub capabilities: CredentialCapabilities,
    #[serde(default)]
    pub external_key: Option<ExternalKeyReference>,
}

impl Credential {
    #[must_use]
    pub fn new(
        label: impl Into<String>,
        provider: CredentialProviderKind,
        capabilities: CredentialCapabilities,
    ) -> Self {
        Self {
            id: CredentialId::new(),
            label: label.into(),
            provider,
            capabilities,
            external_key: None,
        }
    }

    pub fn new_external_key(
        label: impl Into<String>,
        provider: CredentialProviderKind,
        capabilities: CredentialCapabilities,
        external_key: ExternalKeyReference,
    ) -> Result<Self, CredentialCapabilityError> {
        let credential = Self {
            id: CredentialId::new(),
            label: label.into(),
            provider,
            capabilities,
            external_key: Some(external_key),
        };
        credential.validate_provider_reference()?;
        Ok(credential)
    }

    pub fn validate_provider_reference(&self) -> Result<(), CredentialCapabilityError> {
        match (self.provider, self.external_key.is_some()) {
            (CredentialProviderKind::OpenSshAgent | CredentialProviderKind::Pageant, true)
            | (CredentialProviderKind::LocalVault, false) => Ok(()),
            (CredentialProviderKind::OpenSshAgent | CredentialProviderKind::Pageant, false)
            | (CredentialProviderKind::LocalVault, true) => {
                Err(CredentialCapabilityError::ProviderReferenceMismatch)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialGrant {
    pub id: GrantId,
    pub credential_id: CredentialId,
    pub host_ids: BTreeSet<crate::HostId>,
    pub usages: BTreeSet<CredentialUsage>,
    pub expires_at_unix: Option<i64>,
    pub requires_approval: bool,
    pub requires_step_up: bool,
}

impl CredentialGrant {
    pub fn new(
        credential_id: CredentialId,
        host_ids: impl IntoIterator<Item = crate::HostId>,
        usages: impl IntoIterator<Item = CredentialUsage>,
    ) -> Result<Self, CredentialGrantError> {
        let host_ids = host_ids.into_iter().collect::<BTreeSet<_>>();
        let usages = usages.into_iter().collect::<BTreeSet<_>>();
        if host_ids.is_empty() {
            return Err(CredentialGrantError::NoHosts);
        }
        if usages.is_empty() {
            return Err(CredentialGrantError::NoUsages);
        }

        Ok(Self {
            id: GrantId::new(),
            credential_id,
            host_ids,
            usages,
            expires_at_unix: None,
            requires_approval: false,
            requires_step_up: false,
        })
    }

    pub fn validate_against(
        &self,
        capabilities: &CredentialCapabilities,
    ) -> Result<(), CredentialGrantError> {
        if let Some(denied) = self
            .usages
            .iter()
            .find(|usage| !capabilities.allows(**usage))
        {
            return Err(CredentialGrantError::UsageNotAllowed(*denied));
        }
        Ok(())
    }

    #[must_use]
    pub fn authorizes(&self, host_id: crate::HostId, usage: CredentialUsage, at_unix: i64) -> bool {
        self.host_ids.contains(&host_id)
            && self.usages.contains(&usage)
            && self
                .expires_at_unix
                .is_none_or(|expires_at| at_unix < expires_at)
            && !self.requires_approval
            && !self.requires_step_up
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CredentialGrantError {
    #[error("a credential grant must target at least one host")]
    NoHosts,
    #[error("a credential grant must allow at least one usage")]
    NoUsages,
    #[error("credential capability does not allow {0:?}")]
    UsageNotAllowed(CredentialUsage),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_private_synced_direct_ssh_key() {
        let capabilities = CredentialCapabilities::new(
            Custody::Exportable,
            Synchronization::PrivateSynced,
            [CredentialUsage::DirectSsh],
        )
        .unwrap();

        assert!(capabilities.allows(CredentialUsage::DirectSsh));
    }

    #[test]
    fn rejects_hardware_bound_server_delegation() {
        let error = CredentialCapabilities::new(
            Custody::HardwareBound,
            Synchronization::ServerDelegated,
            [CredentialUsage::MediatedSsh],
        )
        .unwrap_err();

        assert_eq!(error, CredentialCapabilityError::NonExportableCannotSync);
    }

    #[test]
    fn rejects_grant_outside_credential_capabilities() {
        let capabilities = CredentialCapabilities::new(
            Custody::ExternalProvider,
            Synchronization::LocalOnly,
            [CredentialUsage::DirectSsh],
        )
        .unwrap();
        let grant = CredentialGrant::new(
            CredentialId::new(),
            [crate::HostId::new()],
            [CredentialUsage::Automation],
        )
        .unwrap();

        assert_eq!(
            grant.validate_against(&capabilities),
            Err(CredentialGrantError::UsageNotAllowed(
                CredentialUsage::Automation
            ))
        );
    }

    #[test]
    fn grant_denies_expired_or_interactive_authorization_requirements() {
        let host_id = crate::HostId::new();
        let credential_id = CredentialId::new();
        let mut grant =
            CredentialGrant::new(credential_id, [host_id], [CredentialUsage::DirectSsh]).unwrap();

        assert!(grant.authorizes(host_id, CredentialUsage::DirectSsh, 9));
        grant.expires_at_unix = Some(10);
        assert!(!grant.authorizes(host_id, CredentialUsage::DirectSsh, 10));
        grant.expires_at_unix = None;
        grant.requires_approval = true;
        assert!(!grant.authorizes(host_id, CredentialUsage::DirectSsh, 9));
    }

    #[test]
    fn external_agent_key_requires_non_exportable_reference_metadata() {
        let capabilities = CredentialCapabilities::new(
            Custody::ExternalProvider,
            Synchronization::LocalOnly,
            [CredentialUsage::DirectSsh],
        )
        .unwrap();
        let reference = ExternalKeyReference::new(
            "ssh-ed25519",
            vec![1, 2, 3],
            Some("workstation agent".to_owned()),
        )
        .unwrap();
        let credential = Credential::new_external_key(
            "Agent key",
            CredentialProviderKind::OpenSshAgent,
            capabilities,
            reference.clone(),
        )
        .unwrap();

        assert_eq!(credential.external_key, Some(reference));
        assert!(credential.validate_provider_reference().is_ok());
    }

    #[test]
    fn local_vault_cannot_claim_an_external_key_reference() {
        let capabilities = CredentialCapabilities::new(
            Custody::Exportable,
            Synchronization::LocalOnly,
            [CredentialUsage::DirectSsh],
        )
        .unwrap();
        let reference = ExternalKeyReference::new("ssh-ed25519", vec![1], None).unwrap();

        assert_eq!(
            Credential::new_external_key(
                "Invalid",
                CredentialProviderKind::LocalVault,
                capabilities,
                reference,
            )
            .unwrap_err(),
            CredentialCapabilityError::ProviderReferenceMismatch
        );
    }

    #[test]
    fn legacy_local_vault_payload_defaults_to_no_external_reference() {
        let credential = Credential::new(
            "Legacy",
            CredentialProviderKind::LocalVault,
            CredentialCapabilities::new(
                Custody::Exportable,
                Synchronization::LocalOnly,
                [CredentialUsage::DirectSsh],
            )
            .unwrap(),
        );
        let mut payload = serde_json::to_value(&credential).unwrap();
        payload.as_object_mut().unwrap().remove("external_key");

        let restored: Credential = serde_json::from_value(payload).unwrap();

        assert_eq!(restored, credential);
        assert!(restored.validate_provider_reference().is_ok());
    }
}
