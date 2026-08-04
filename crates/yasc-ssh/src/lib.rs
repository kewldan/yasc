//! Product-facing SSH contracts and the controlled OpenSSH compatibility engine.

#![forbid(unsafe_code)]

mod native;

pub use native::{
    AgentIdentityInfo, DynamicAgentClient, NativeAgentCommandRequest, NativeAgentSftpRequest,
    NativeAgentShellRequest, NativeCommandOutput, NativeCommandRequest, NativeHostKeyProbe,
    NativeSftpRequest, NativeSftpSession, NativeShellIo, NativeShellOutput, NativeShellRequest,
    NativeSshEngine, NativeSshError, SftpEntry, SftpEntryKind, SftpUploadResult, TerminalSize,
    connect_agent, external_key_fingerprint, list_agent_identities, validate_private_key,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs,
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
            .stderr(Stdio::piped())
            .output()
            .map_err(|source| OpenSshError::Launch {
                operation: "effective-config",
                source,
            })?;
        if !output.status.success() {
            return Err(OpenSshError::CommandFailed {
                operation: "effective-config",
                status: output.status.code(),
                diagnostic: safe_diagnostic(&output.stderr),
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

    /// Discovers literal `Host` aliases, resolves their current OpenSSH configuration, and marks
    /// entries whose routing or host-identity semantics cannot be represented by a plain inventory
    /// target. No product state is changed by this operation.
    pub fn inventory_preview(
        &self,
        config_file: &Path,
    ) -> Result<OpenSshInventoryPreview, OpenSshError> {
        let contents =
            fs::read_to_string(config_file).map_err(|source| OpenSshError::ReadImportConfig {
                path: config_file.to_owned(),
                source,
            })?;
        let discovery = discover_literal_hosts(&contents)?;
        let mut candidates = Vec::new();
        let mut skipped_patterns = discovery.skipped_patterns;
        for alias in discovery.aliases {
            let alias_target = match alias.parse::<SshTarget>() {
                Ok(target) => target,
                Err(_) => {
                    skipped_patterns.push(OpenSshSkippedPattern {
                        pattern: alias,
                        reason: OpenSshSkipReason::InvalidAlias,
                    });
                    continue;
                }
            };
            let mut request = OpenSshRequest::new(alias_target);
            request.config_file = Some(config_file.to_owned());
            let effective = self.effective_config(&request)?;
            candidates.push(OpenSshImportCandidate::from_effective(alias, &effective)?);
        }
        let mut notices = vec![OpenSshImportNotice::CredentialsNotImported];
        if discovery.has_conditional_blocks {
            notices.push(OpenSshImportNotice::ConditionalBlocksEvaluatedForCurrentContext);
        }
        Ok(OpenSshInventoryPreview {
            candidates,
            skipped_patterns,
            notices,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenSshInventoryPreview {
    pub candidates: Vec<OpenSshImportCandidate>,
    pub skipped_patterns: Vec<OpenSshSkippedPattern>,
    pub notices: Vec<OpenSshImportNotice>,
}

impl OpenSshInventoryPreview {
    #[must_use]
    pub fn importable_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| candidate.blockers.is_empty())
            .count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenSshImportCandidate {
    pub alias: String,
    pub target: SshTarget,
    pub blockers: Vec<OpenSshImportBlocker>,
}

impl OpenSshImportCandidate {
    fn from_effective(alias: String, config: &EffectiveConfig) -> Result<Self, OpenSshError> {
        let hostname = config
            .get("hostname")
            .ok_or_else(|| OpenSshError::MissingImportValue {
                alias: alias.clone(),
                key: "hostname",
            })?;
        let port = config
            .get("port")
            .ok_or_else(|| OpenSshError::MissingImportValue {
                alias: alias.clone(),
                key: "port",
            })?
            .parse::<u16>()
            .map_err(|_| OpenSshError::InvalidImportTarget {
                alias: alias.clone(),
            })?;
        if port == 0 {
            return Err(OpenSshError::InvalidImportTarget { alias });
        }
        let user = config.get("user");
        let host = if hostname.contains(':') && !hostname.starts_with('[') {
            format!("[{hostname}]")
        } else {
            hostname.to_owned()
        };
        let mut value = user.map_or(host.clone(), |user| format!("{user}@{host}"));
        if port != 22 {
            value.push(':');
            value.push_str(&port.to_string());
        }
        let target = value
            .parse::<SshTarget>()
            .map_err(|_| OpenSshError::InvalidImportTarget {
                alias: alias.clone(),
            })?;
        let mut blockers = Vec::new();
        if config.get("proxycommand").is_some() {
            blockers.push(OpenSshImportBlocker::ProxyCommand);
        }
        if config.get("proxyjump").is_some() {
            blockers.push(OpenSshImportBlocker::ProxyJump);
        }
        if config.get("hostkeyalias").is_some() {
            blockers.push(OpenSshImportBlocker::HostKeyAlias);
        }
        if config.get("knownhostscommand").is_some() {
            blockers.push(OpenSshImportBlocker::KnownHostsCommand);
        }
        if config
            .get("canonicalizehostname")
            .is_some_and(|value| !value.eq_ignore_ascii_case("false"))
        {
            blockers.push(OpenSshImportBlocker::HostnameCanonicalization);
        }
        Ok(Self {
            alias,
            target,
            blockers,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSshImportBlocker {
    ProxyCommand,
    ProxyJump,
    HostKeyAlias,
    KnownHostsCommand,
    HostnameCanonicalization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenSshSkippedPattern {
    pub pattern: String,
    pub reason: OpenSshSkipReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSshSkipReason {
    DynamicPattern,
    InvalidAlias,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenSshImportNotice {
    CredentialsNotImported,
    ConditionalBlocksEvaluatedForCurrentContext,
}

struct HostDiscovery {
    aliases: BTreeSet<String>,
    skipped_patterns: Vec<OpenSshSkippedPattern>,
    has_conditional_blocks: bool,
}

fn discover_literal_hosts(contents: &str) -> Result<HostDiscovery, OpenSshError> {
    let mut aliases = BTreeSet::new();
    let mut skipped_patterns = Vec::new();
    let mut has_conditional_blocks = false;
    for (index, raw_line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((directive, value)) = split_openssh_directive(line) else {
            continue;
        };
        if directive.eq_ignore_ascii_case("include") {
            return Err(OpenSshError::UnsafeImportDirective {
                line: line_number,
                directive: "Include",
            });
        }
        if directive.eq_ignore_ascii_case("match") {
            has_conditional_blocks = true;
            if value.split_ascii_whitespace().any(|token| {
                token.eq_ignore_ascii_case("exec")
                    || token
                        .get(..5)
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("exec="))
            }) {
                return Err(OpenSshError::UnsafeImportDirective {
                    line: line_number,
                    directive: "Match exec",
                });
            }
            continue;
        }
        if !directive.eq_ignore_ascii_case("host") {
            continue;
        }
        for pattern in value
            .split_ascii_whitespace()
            .take_while(|token| !token.starts_with('#'))
        {
            if pattern == "*" {
                continue;
            }
            if pattern.contains(['*', '?', '!', '[', ']']) || pattern.contains(['\'', '"']) {
                skipped_patterns.push(OpenSshSkippedPattern {
                    pattern: pattern.to_owned(),
                    reason: OpenSshSkipReason::DynamicPattern,
                });
            } else {
                aliases.insert(pattern.to_owned());
            }
        }
    }
    Ok(HostDiscovery {
        aliases,
        skipped_patterns,
        has_conditional_blocks,
    })
}

fn split_openssh_directive(line: &str) -> Option<(&str, &str)> {
    let key_end = line
        .find(|character: char| character.is_ascii_whitespace() || character == '=')
        .unwrap_or(line.len());
    let directive = &line[..key_end];
    let value = line[key_end..]
        .trim_start_matches(|character: char| character.is_ascii_whitespace())
        .strip_prefix('=')
        .unwrap_or(&line[key_end..])
        .trim_start();
    (!directive.is_empty() && !value.is_empty()).then_some((directive, value))
}

fn controlled_environment() -> Vec<(OsString, OsString)> {
    env::vars_os()
        .filter(|(key, _)| is_allowed_environment_key(&key.to_string_lossy()))
        .collect()
}

fn is_allowed_environment_key(key: &str) -> bool {
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
    ALLOWED
        .iter()
        .any(|allowed| key.eq_ignore_ascii_case(allowed))
        || key
            .get(..3)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("LC_"))
}

fn safe_diagnostic(stderr: &[u8]) -> String {
    const MAX_DIAGNOSTIC_CHARS: usize = 1024;
    let mut lines = String::from_utf8_lossy(stderr)
        .lines()
        .map(|line| {
            let lowercase = line.to_ascii_lowercase();
            if ["proxycommand", "localcommand", "remotecommand", "setenv"]
                .iter()
                .any(|key| lowercase.contains(key))
            {
                "[REDACTED OPENSSH CONFIG ERROR]".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    for variable in ["HOME", "USERPROFILE"] {
        if let Some(home) = env::var_os(variable) {
            lines = lines.replace(&home.to_string_lossy().into_owned(), "~");
        }
    }
    lines.chars().take(MAX_DIAGNOSTIC_CHARS).collect()
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
    #[error("failed to read OpenSSH import configuration {path}: {source}")]
    ReadImportConfig {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "OpenSSH inventory import refuses {directive} at line {line}; preview would not be safely complete"
    )]
    UnsafeImportDirective {
        line: usize,
        directive: &'static str,
    },
    #[error("OpenSSH effective configuration for {alias} is missing {key}")]
    MissingImportValue { alias: String, key: &'static str },
    #[error("OpenSSH effective configuration for {alias} is not a valid inventory target")]
    InvalidImportTarget { alias: String },
    #[error("failed to launch OpenSSH for {operation}: {source}")]
    Launch {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("OpenSSH {operation} failed with exit code {status:?}: {diagnostic}")]
    CommandFailed {
        operation: &'static str,
        status: Option<i32>,
        diagnostic: String,
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
    fn arguments_are_structured_and_end_with_host() {
        let mut request = OpenSshRequest::new("admin@example.com:2222".parse().unwrap());
        request.config_file = Some(PathBuf::from("/tmp/ssh config"));
        request.identity_file = Some(PathBuf::from("/tmp/key;touch-pwned"));
        let arguments = request.arguments(false);

        assert_eq!(arguments.last().unwrap(), "example.com");
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
    fn inventory_discovery_keeps_literal_aliases_and_reports_patterns() {
        let discovery = discover_literal_hosts(
            r#"
                Host *
                    ServerAliveInterval 30
                Host production prod-backup *.internal !retired
                    HostName 192.0.2.10
                Match user deploy
                    Compression yes
            "#,
        )
        .unwrap();

        assert_eq!(
            discovery.aliases,
            ["prod-backup".to_owned(), "production".to_owned()]
                .into_iter()
                .collect()
        );
        assert_eq!(
            discovery.skipped_patterns,
            vec![
                OpenSshSkippedPattern {
                    pattern: "*.internal".to_owned(),
                    reason: OpenSshSkipReason::DynamicPattern,
                },
                OpenSshSkippedPattern {
                    pattern: "!retired".to_owned(),
                    reason: OpenSshSkipReason::DynamicPattern,
                },
            ]
        );
        assert!(discovery.has_conditional_blocks);
    }

    #[test]
    fn inventory_discovery_refuses_unscanned_or_executable_configuration() {
        assert!(matches!(
            discover_literal_hosts("Include conf.d/*.conf\nHost production\n"),
            Err(OpenSshError::UnsafeImportDirective {
                line: 1,
                directive: "Include"
            })
        ));
        assert!(matches!(
            discover_literal_hosts("Match exec \"helper %h\"\nHost production\n"),
            Err(OpenSshError::UnsafeImportDirective {
                line: 1,
                directive: "Match exec"
            })
        ));
    }

    #[test]
    fn inventory_candidate_blocks_unrepresented_route_and_trust_semantics() {
        let config = EffectiveConfig::parse(
            "user deploy\nhostname 192.0.2.10\nport 2200\nproxyjump bastion\nhostkeyalias canonical-host\ncanonicalizehostname false\n",
        )
        .unwrap();

        let candidate =
            OpenSshImportCandidate::from_effective("production".to_owned(), &config).unwrap();

        assert_eq!(candidate.target.to_string(), "deploy@192.0.2.10:2200");
        assert_eq!(
            candidate.blockers,
            vec![
                OpenSshImportBlocker::ProxyJump,
                OpenSshImportBlocker::HostKeyAlias,
            ]
        );
    }

    #[test]
    fn diagnostics_redact_commands_and_home_directory() {
        let home = env::var("HOME").unwrap_or_default();
        let stderr = format!("{home}/.ssh/config: ProxyCommand token=secret");

        let diagnostic = safe_diagnostic(stderr.as_bytes());

        assert!(!diagnostic.contains("token=secret"));
        assert!(home.is_empty() || !diagnostic.contains(&home));
    }

    #[test]
    fn environment_allowlist_is_case_insensitive_for_windows() {
        assert!(is_allowed_environment_key("Path"));
        assert!(is_allowed_environment_key("SystemRoot"));
        assert!(is_allowed_environment_key("UserProfile"));
        assert!(is_allowed_environment_key("lc_messages"));
        assert!(!is_allowed_environment_key("SSH_ASKPASS"));
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
