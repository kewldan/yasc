//! Product-facing SSH contracts and the controlled OpenSSH compatibility engine.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
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
    OpenSshCompatibility,
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
        Self::direct_with_engine(target, SshEngine::NativeRust)
    }

    #[must_use]
    pub const fn direct_with_engine(target: SshTarget, engine: SshEngine) -> Self {
        Self {
            target,
            mode: ConnectionMode::Direct,
            engine,
            credential_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPolicy {
    Strict,
    AcceptNew,
}

/// Inputs accepted by the OpenSSH adapter. Every value becomes a distinct process argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSshRequest {
    pub target: SshTarget,
    pub config_file: Option<PathBuf>,
    pub identity_file: Option<PathBuf>,
    pub host_key_policy: HostKeyPolicy,
}

impl OpenSshRequest {
    #[must_use]
    pub const fn new(target: SshTarget) -> Self {
        Self {
            target,
            config_file: None,
            identity_file: None,
            host_key_policy: HostKeyPolicy::Strict,
        }
    }

    #[must_use]
    pub fn plan(&self) -> ConnectionPlan {
        ConnectionPlan::direct_with_engine(self.target.clone(), SshEngine::OpenSshCompatibility)
    }

    #[must_use]
    pub fn arguments(&self, inspect_only: bool) -> Vec<OsString> {
        let mut arguments = Vec::new();
        if inspect_only {
            arguments.push(OsString::from("-G"));
        }
        arguments.push(OsString::from("-F"));
        arguments.push(
            self.config_file
                .as_deref()
                .map_or_else(default_empty_config, |path| path.as_os_str().to_os_string()),
        );
        arguments.push(OsString::from("-o"));
        arguments.push(OsString::from(match self.host_key_policy {
            HostKeyPolicy::Strict => "StrictHostKeyChecking=yes",
            HostKeyPolicy::AcceptNew => "StrictHostKeyChecking=accept-new",
        }));
        if let Some(identity_file) = &self.identity_file {
            arguments.push(OsString::from("-o"));
            arguments.push(OsString::from("IdentitiesOnly=yes"));
            arguments.push(OsString::from("-i"));
            arguments.push(identity_file.as_os_str().to_os_string());
        }
        if self.target.port_is_explicit() {
            arguments.push(OsString::from("-p"));
            arguments.push(OsString::from(self.target.port().to_string()));
        }
        if let Some(username) = self.target.username() {
            arguments.push(OsString::from("-l"));
            arguments.push(OsString::from(username));
        }
        arguments.push(OsString::from("--"));
        arguments.push(OsString::from(self.target.host()));
        arguments
    }
}

#[cfg(windows)]
fn default_empty_config() -> OsString {
    OsString::from("NUL")
}

#[cfg(not(windows))]
fn default_empty_config() -> OsString {
    OsString::from("none")
}

#[derive(Debug, Clone)]
pub struct OpenSshEngine {
    executable: PathBuf,
}

impl OpenSshEngine {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
        }
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn effective_config(
        &self,
        request: &OpenSshRequest,
    ) -> Result<EffectiveConfig, OpenSshError> {
        let mut command = self.command(request, true);
        let output = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map_err(|source| OpenSshError::Launch {
                operation: "effective-config",
                source,
            })?;
        if !output.status.success() {
            return Err(OpenSshError::CommandFailed {
                operation: "effective-config",
                status: output.status.code(),
            });
        }
        let stdout = String::from_utf8(output.stdout).map_err(|_| OpenSshError::NonUtf8Output)?;
        EffectiveConfig::parse(&stdout)
    }

    pub fn connect(&self, request: &OpenSshRequest) -> Result<ExitStatus, OpenSshError> {
        self.command(request, false)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|source| OpenSshError::Launch {
                operation: "connect",
                source,
            })
    }

    fn command(&self, request: &OpenSshRequest, inspect_only: bool) -> Command {
        let mut command = Command::new(&self.executable);
        command.args(request.arguments(inspect_only));
        command.env_clear();
        command.envs(controlled_environment());
        command
    }
}

fn controlled_environment() -> Vec<(OsString, OsString)> {
    const ALLOWED: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TERM",
        "COLORTERM",
        "LANG",
        "SSH_AUTH_SOCK",
        "USERPROFILE",
        "USERNAME",
        "HOMEDRIVE",
        "HOMEPATH",
        "SYSTEMROOT",
        "WINDIR",
        "PROGRAMDATA",
        "COMSPEC",
        "TEMP",
        "TMP",
        "APPDATA",
        "LOCALAPPDATA",
    ];

    env::vars_os()
        .filter(|(key, _)| {
            let key = key.to_string_lossy();
            ALLOWED.iter().any(|allowed| key == *allowed) || key.starts_with("LC_")
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveConfig {
    values: BTreeMap<String, Vec<String>>,
}

impl EffectiveConfig {
    pub fn parse(output: &str) -> Result<Self, OpenSshError> {
        let mut values = BTreeMap::<String, Vec<String>>::new();
        for (index, line) in output.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once(char::is_whitespace)
                .ok_or(OpenSshError::InvalidConfigLine { line: index + 1 })?;
            let value = value.trim_start();
            if key.is_empty() || value.is_empty() {
                return Err(OpenSshError::InvalidConfigLine { line: index + 1 });
            }
            values
                .entry(key.to_ascii_lowercase())
                .or_default()
                .push(value.to_owned());
        }
        Ok(Self { values })
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values
            .get(&key.to_ascii_lowercase())
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    #[must_use]
    pub fn get_all(&self, key: &str) -> &[String] {
        self.values
            .get(&key.to_ascii_lowercase())
            .map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn redacted_entries(&self) -> Vec<EffectiveConfigEntry> {
        self.values
            .iter()
            .flat_map(|(key, values)| {
                values.iter().map(move |value| EffectiveConfigEntry {
                    key: key.clone(),
                    value: if is_sensitive_config_key(key) {
                        "[REDACTED]".to_owned()
                    } else {
                        value.clone()
                    },
                    redacted: is_sensitive_config_key(key),
                })
            })
            .collect()
    }
}

fn is_sensitive_config_key(key: &str) -> bool {
    matches!(
        key,
        "proxycommand" | "localcommand" | "remotecommand" | "setenv"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveConfigEntry {
    pub key: String,
    pub value: String,
    pub redacted: bool,
}

#[derive(Debug, Error)]
pub enum OpenSshError {
    #[error("failed to launch OpenSSH for {operation}: {source}")]
    Launch {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("OpenSSH {operation} failed with exit code {status:?}")]
    CommandFailed {
        operation: &'static str,
        status: Option<i32>,
    },
    #[error("OpenSSH produced non-UTF-8 effective configuration")]
    NonUtf8Output,
    #[error("OpenSSH effective configuration contains an invalid line at {line}")]
    InvalidConfigLine { line: usize },
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

    #[test]
    fn arguments_are_structured_and_end_with_separator_and_host() {
        let mut request = OpenSshRequest::new("admin@example.com:2222".parse().unwrap());
        request.config_file = Some(PathBuf::from("/tmp/ssh config"));
        request.identity_file = Some(PathBuf::from("/tmp/key;touch-pwned"));
        let arguments = request.arguments(false);

        assert_eq!(arguments.last().unwrap(), "example.com");
        assert_eq!(arguments[arguments.len() - 2], "--");
        assert!(arguments.contains(&OsString::from("/tmp/key;touch-pwned")));
        assert!(!arguments.iter().any(|argument| argument == "sh"));
    }

    #[test]
    fn implicit_port_does_not_override_configuration() {
        let request = OpenSshRequest::new("prod-db".parse().unwrap());
        let arguments = request.arguments(false);

        assert!(!arguments.iter().any(|argument| argument == "-p"));
    }

    #[test]
    fn parser_preserves_repeated_values_and_redacts_commands() {
        let config = EffectiveConfig::parse(
            "hostname example.com\nidentityfile ~/.ssh/id_ed25519\nidentityfile ~/.ssh/id_rsa\nproxycommand token=secret helper %h\n",
        )
        .unwrap();

        assert_eq!(config.get("hostname"), Some("example.com"));
        assert_eq!(config.get_all("identityfile").len(), 2);
        let proxy = config
            .redacted_entries()
            .into_iter()
            .find(|entry| entry.key == "proxycommand")
            .unwrap();
        assert_eq!(proxy.value, "[REDACTED]");
        assert!(proxy.redacted);
    }

    #[test]
    fn installed_openssh_effective_config_matches_target() {
        let engine = OpenSshEngine::new("ssh");
        let request = OpenSshRequest::new("integration@example.com:2200".parse().unwrap());
        let config = match engine.effective_config(&request) {
            Ok(config) => config,
            Err(OpenSshError::Launch { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return;
            }
            Err(error) => panic!("installed OpenSSH failed effective-config evaluation: {error}"),
        };

        assert_eq!(config.get("hostname"), Some("example.com"));
        assert_eq!(config.get("port"), Some("2200"));
        assert_eq!(config.get("user"), Some("integration"));
    }

    #[test]
    fn installed_openssh_applies_fixture_precedence_and_redaction() {
        let engine = OpenSshEngine::new("ssh");
        let mut request = OpenSshRequest::new("prod-db".parse().unwrap());
        request.config_file =
            Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/basic.conf"));
        let config = match engine.effective_config(&request) {
            Ok(config) => config,
            Err(OpenSshError::Launch { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return;
            }
            Err(error) => panic!("installed OpenSSH failed fixture evaluation: {error}"),
        };

        assert_eq!(config.get("hostname"), Some("192.0.2.10"));
        assert_eq!(config.get("port"), Some("2201"));
        assert_eq!(config.get("user"), Some("deploy"));
        let proxy = config
            .redacted_entries()
            .into_iter()
            .find(|entry| entry.key == "proxycommand")
            .unwrap();
        assert_eq!(proxy.value, "[REDACTED]");
    }
}
