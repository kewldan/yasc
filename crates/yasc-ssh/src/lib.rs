//! Product-facing SSH contracts. Protocol engines will implement these boundaries.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use yasc_domain::{CredentialId, SshTarget};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshEngine {
    NativeRust,
}

/// A secret-free description of a connection before network I/O begins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionPlan {
    pub target: SshTarget,
    pub mode: ConnectionMode,
    pub engine: SshEngine,
    pub credential_id: Option<CredentialId>,
}

impl ConnectionPlan {
    #[must_use]
    pub const fn direct(target: SshTarget) -> Self {
        Self {
            target,
            mode: ConnectionMode::Direct,
            engine: SshEngine::NativeRust,
            credential_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_plan_is_local_and_contains_no_credential() {
        let target = "root@example.com".parse().unwrap();
        let plan = ConnectionPlan::direct(target);

        assert_eq!(plan.mode, ConnectionMode::Direct);
        assert_eq!(plan.engine, SshEngine::NativeRust);
        assert_eq!(plan.credential_id, None);
    }
}
