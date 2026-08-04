use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::{
    ChannelMsg, Disconnect, client,
    keys::{
        PrivateKeyWithHashAlg,
        agent::{AgentIdentity, client::AgentClient},
        ssh_key,
    },
};
use russh_sftp::{
    client::{RawSftpSession, SftpSession, error::Error as SftpError},
    protocol::{FileType, OpenFlags, StatusCode},
};
use serde::Serialize;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    time::timeout,
};
use uuid::Uuid;
use yasc_domain::{
    CredentialProviderKind, ExternalKeyReference, HostKeyAlgorithm, HostKeyDecision, HostKeyError,
    HostKeyHistory, HostKeyMaterial, HostKeyObservation, HostKeyPolicy, SshTarget,
};
use yasc_vault::SecretBytes;

pub type DynamicAgentClient =
    AgentClient<Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentIdentityInfo {
    pub algorithm: String,
    pub public_key_blob: Vec<u8>,
    pub comment: String,
    pub fingerprint: String,
}

impl AgentIdentityInfo {
    pub fn external_reference(&self) -> Result<ExternalKeyReference, NativeSshError> {
        ExternalKeyReference::new(
            self.algorithm.clone(),
            self.public_key_blob.clone(),
            (!self.comment.is_empty()).then(|| self.comment.clone()),
        )
        .map_err(Into::into)
    }
}

pub async fn list_agent_identities<S>(
    client: &mut AgentClient<S>,
) -> Result<Vec<AgentIdentityInfo>, NativeSshError>
where
    S: russh::keys::agent::client::AgentStream + Send + Unpin,
{
    let identities = client.request_identities().await?;
    identities
        .into_iter()
        .filter_map(|identity| match identity {
            AgentIdentity::PublicKey { key, comment } => Some((key, comment)),
            AgentIdentity::Certificate { .. } => None,
        })
        .map(|(key, comment)| {
            Ok(AgentIdentityInfo {
                algorithm: key.algorithm().to_string(),
                public_key_blob: key.to_bytes()?,
                fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                comment,
            })
        })
        .collect()
}

pub fn external_key_fingerprint(
    reference: &ExternalKeyReference,
) -> Result<String, NativeSshError> {
    let key = ssh_key::PublicKey::from_bytes(&reference.public_key_blob)?;
    if key.algorithm().to_string() != reference.algorithm {
        return Err(NativeSshError::AgentIdentityNotFound);
    }
    Ok(key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

#[cfg(unix)]
pub async fn connect_agent(
    provider: CredentialProviderKind,
) -> Result<DynamicAgentClient, NativeSshError> {
    match provider {
        CredentialProviderKind::OpenSshAgent => Ok(AgentClient::connect_env().await?.dynamic()),
        _ => Err(NativeSshError::UnsupportedAgentProvider(provider)),
    }
}

#[cfg(windows)]
pub async fn connect_agent(
    provider: CredentialProviderKind,
) -> Result<DynamicAgentClient, NativeSshError> {
    match provider {
        CredentialProviderKind::OpenSshAgent => {
            let path = std::env::var_os("SSH_AUTH_SOCK")
                .unwrap_or_else(|| r"\\.\pipe\openssh-ssh-agent".into());
            Ok(AgentClient::connect_named_pipe(path).await?.dynamic())
        }
        CredentialProviderKind::Pageant => Ok(AgentClient::connect_pageant().await?.dynamic()),
        _ => Err(NativeSshError::UnsupportedAgentProvider(provider)),
    }
}

/// Verifies that private-key material can be decoded without retaining it or contacting a host.
pub fn validate_private_key(
    private_key: &SecretBytes,
    passphrase: Option<&SecretBytes>,
) -> Result<(), NativeSshError> {
    decode_private_key(private_key, passphrase).map(|_| ())
}

fn decode_private_key(
    private_key: &SecretBytes,
    passphrase: Option<&SecretBytes>,
) -> Result<ssh_key::PrivateKey, NativeSshError> {
    let private_key_text = std::str::from_utf8(private_key.expose_secret())
        .map_err(|_| NativeSshError::PrivateKeyNotUtf8)?;
    let passphrase = passphrase
        .map(|value| {
            std::str::from_utf8(value.expose_secret())
                .map_err(|_| NativeSshError::PassphraseNotUtf8)
        })
        .transpose()?;
    russh::keys::decode_secret_key(private_key_text, passphrase).map_err(Into::into)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeHostKeyProbe {
    pub observation: HostKeyObservation,
    pub decision: HostKeyDecision,
}

#[derive(Debug, Clone)]
pub struct NativeSshEngine {
    handshake_timeout: Duration,
}

pub struct NativeCommandRequest {
    target: SshTarget,
    username: String,
    private_key: SecretBytes,
    private_key_passphrase: Option<SecretBytes>,
    command: Vec<u8>,
    timeout: Duration,
    max_output_bytes: usize,
}

pub struct NativeAgentCommandRequest {
    target: SshTarget,
    username: String,
    external_key: ExternalKeyReference,
    command: Vec<u8>,
    timeout: Duration,
    max_output_bytes: usize,
}

pub struct NativeSftpRequest {
    target: SshTarget,
    username: String,
    private_key: SecretBytes,
    private_key_passphrase: Option<SecretBytes>,
}

pub struct NativeAgentSftpRequest {
    target: SshTarget,
    username: String,
    external_key: ExternalKeyReference,
}

impl NativeSftpRequest {
    pub fn new(
        target: SshTarget,
        username: impl Into<String>,
        private_key: SecretBytes,
    ) -> Result<Self, NativeSshError> {
        let username = username.into();
        validate_username(&username)?;
        if private_key.is_empty() {
            return Err(NativeSshError::EmptyPrivateKey);
        }
        Ok(Self {
            target,
            username,
            private_key,
            private_key_passphrase: None,
        })
    }

    #[must_use]
    pub fn with_passphrase(mut self, passphrase: SecretBytes) -> Self {
        self.private_key_passphrase = Some(passphrase);
        self
    }
}

impl NativeAgentSftpRequest {
    pub fn new(
        target: SshTarget,
        username: impl Into<String>,
        external_key: ExternalKeyReference,
    ) -> Result<Self, NativeSshError> {
        let username = username.into();
        validate_username(&username)?;
        let public_key = ssh_key::PublicKey::from_bytes(&external_key.public_key_blob)?;
        if public_key.algorithm().to_string() != external_key.algorithm {
            return Err(NativeSshError::AgentIdentityNotFound);
        }
        Ok(Self {
            target,
            username,
            external_key,
        })
    }
}

impl std::fmt::Debug for NativeSftpRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeSftpRequest")
            .field("target", &self.target)
            .field("username", &self.username)
            .field("private_key", &"[REDACTED]")
            .field(
                "private_key_passphrase",
                &self.private_key_passphrase.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl std::fmt::Debug for NativeAgentSftpRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAgentSftpRequest")
            .field("target", &self.target)
            .field("username", &self.username)
            .field("external_key", &self.external_key)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SftpEntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpEntry {
    pub name: String,
    pub path: String,
    pub kind: SftpEntryKind,
    pub size: Option<u64>,
    pub modified_unix_seconds: Option<u32>,
    pub permissions: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpUploadResult {
    pub remote_path: String,
    pub bytes_written: usize,
}

pub struct NativeSftpSession {
    handle: client::Handle<NativeHostKeyHandler>,
    sftp: SftpSession,
    host_key_decision: HostKeyDecision,
}

impl std::fmt::Debug for NativeSftpSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeSftpSession")
            .field("host_key_decision", &self.host_key_decision)
            .finish_non_exhaustive()
    }
}

impl NativeSftpSession {
    #[must_use]
    pub const fn host_key_decision(&self) -> &HostKeyDecision {
        &self.host_key_decision
    }

    pub async fn list_directory(
        &self,
        remote_path: &str,
        max_entries: usize,
    ) -> Result<Vec<SftpEntry>, NativeSshError> {
        validate_remote_path(remote_path, true)?;
        if max_entries == 0 {
            return Err(NativeSshError::InvalidSftpEntryLimit);
        }
        let mut channel = self.handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        wait_for_request_success(&mut channel, NativeSshError::SftpSubsystemRejected).await?;
        let raw = RawSftpSession::new(channel.into_stream());
        raw.init().await?;
        let directory = raw.opendir(remote_path).await?;
        let mut entries = Vec::new();
        loop {
            let batch = match raw.readdir(&directory.handle).await {
                Ok(batch) => batch,
                Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => break,
                Err(error) => return Err(error.into()),
            };
            for entry in batch.files {
                if matches!(entry.filename.as_str(), "." | "..") {
                    continue;
                }
                validate_remote_entry_name(&entry.filename)?;
                if entries.len() == max_entries {
                    let _ = raw.close(&directory.handle).await;
                    let _ = raw.close_session();
                    return Err(NativeSshError::SftpEntryLimitExceeded { limit: max_entries });
                }
                let metadata = entry.attrs;
                let kind = match metadata.file_type() {
                    FileType::Dir => SftpEntryKind::Directory,
                    FileType::File => SftpEntryKind::File,
                    FileType::Symlink => SftpEntryKind::Symlink,
                    FileType::Other => SftpEntryKind::Other,
                };
                let path = join_remote_path(remote_path, &entry.filename);
                entries.push(SftpEntry {
                    name: entry.filename,
                    path,
                    kind,
                    size: metadata.size,
                    modified_unix_seconds: metadata.mtime,
                    permissions: metadata
                        .permissions
                        .map(|_| metadata.permissions().to_string()),
                });
            }
        }
        raw.close(directory.handle).await?;
        raw.close_session()?;
        entries.sort_by(|left, right| {
            let left_group = !matches!(left.kind, SftpEntryKind::Directory);
            let right_group = !matches!(right.kind, SftpEntryKind::Directory);
            left_group
                .cmp(&right_group)
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(entries)
    }

    pub async fn download(
        &self,
        remote_path: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, NativeSshError> {
        validate_remote_path(remote_path, false)?;
        if max_bytes == 0 {
            return Err(NativeSshError::InvalidSftpByteLimit);
        }
        let mut file = self.sftp.open(remote_path).await?;
        let mut output = Vec::new();
        let mut chunk = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut chunk).await?;
            if count == 0 {
                break;
            }
            if output
                .len()
                .checked_add(count)
                .is_none_or(|total| total > max_bytes)
            {
                let _ = file.close().await;
                return Err(NativeSshError::SftpByteLimitExceeded { limit: max_bytes });
            }
            output.extend_from_slice(&chunk[..count]);
        }
        file.close().await?;
        Ok(output)
    }

    /// Uploads to a unique sibling temporary file and publishes it with SFTP v3 rename. The
    /// destination is never removed or truncated, so servers honoring the v3 no-overwrite rename
    /// contract fail safely when the destination already exists.
    pub async fn upload_new(
        &self,
        remote_path: &str,
        contents: &[u8],
        max_bytes: usize,
    ) -> Result<SftpUploadResult, NativeSshError> {
        validate_remote_path(remote_path, false)?;
        if max_bytes == 0 {
            return Err(NativeSshError::InvalidSftpByteLimit);
        }
        if contents.len() > max_bytes {
            return Err(NativeSshError::SftpByteLimitExceeded { limit: max_bytes });
        }
        if self.sftp.try_exists(remote_path).await? {
            return Err(NativeSshError::SftpDestinationExists(
                remote_path.to_owned(),
            ));
        }
        let temporary_path = temporary_upload_path(remote_path);
        let result = async {
            let mut file = self
                .sftp
                .open_with_flags(
                    temporary_path.clone(),
                    OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                )
                .await?;
            let write_result = async {
                file.write_all(contents).await?;
                file.flush().await?;
                file.sync_all().await?;
                Ok::<_, NativeSshError>(())
            }
            .await;
            let close_result = file.close().await;
            write_result?;
            close_result?;
            self.sftp
                .rename(temporary_path.clone(), remote_path)
                .await?;
            Ok::<_, NativeSshError>(SftpUploadResult {
                remote_path: remote_path.to_owned(),
                bytes_written: contents.len(),
            })
        }
        .await;
        if result.is_err() {
            let _ = self.sftp.remove_file(temporary_path).await;
        }
        result
    }

    pub async fn close(self) -> Result<(), NativeSshError> {
        self.sftp.close().await?;
        self.handle
            .disconnect(Disconnect::ByApplication, "SFTP complete", "en")
            .await?;
        Ok(())
    }
}

fn validate_remote_path(path: &str, allow_directory: bool) -> Result<(), NativeSshError> {
    if path.is_empty()
        || path.len() > 4096
        || path
            .chars()
            .any(|character| character == '\0' || character.is_control())
        || (!allow_directory && path.ends_with('/'))
    {
        return Err(NativeSshError::InvalidSftpPath);
    }
    if !allow_directory {
        let name = path.rsplit('/').next().unwrap_or_default();
        if name.is_empty() || matches!(name, "." | "..") {
            return Err(NativeSshError::InvalidSftpPath);
        }
    }
    Ok(())
}

fn validate_remote_entry_name(name: &str) -> Result<(), NativeSshError> {
    if name.is_empty()
        || name.len() > 1024
        || name.contains('/')
        || name
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        return Err(NativeSshError::InvalidSftpEntryName);
    }
    Ok(())
}

fn temporary_upload_path(remote_path: &str) -> String {
    let parent = match remote_path.rsplit_once('/') {
        Some(("", _)) if remote_path.starts_with('/') => "/",
        Some((parent, _)) => parent,
        None => "",
    };
    let separator = if parent.is_empty() || parent.ends_with('/') {
        ""
    } else {
        "/"
    };
    format!("{parent}{separator}.yasc-upload-{}", Uuid::new_v4())
}

fn join_remote_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

impl NativeAgentCommandRequest {
    pub fn new(
        target: SshTarget,
        username: impl Into<String>,
        external_key: ExternalKeyReference,
        command: impl Into<Vec<u8>>,
    ) -> Result<Self, NativeSshError> {
        let username = username.into();
        let command = command.into();
        validate_username(&username)?;
        if command.is_empty() {
            return Err(NativeSshError::EmptyCommand);
        }
        let public_key = ssh_key::PublicKey::from_bytes(&external_key.public_key_blob)?;
        if public_key.algorithm().to_string() != external_key.algorithm {
            return Err(NativeSshError::AgentIdentityNotFound);
        }
        Ok(Self {
            target,
            username,
            external_key,
            command,
            timeout: Duration::from_secs(60),
            max_output_bytes: 1024 * 1024,
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, NativeSshError> {
        if timeout.is_zero() {
            return Err(NativeSshError::InvalidCommandTimeout);
        }
        self.timeout = timeout;
        Ok(self)
    }

    pub fn with_max_output_bytes(mut self, limit: usize) -> Result<Self, NativeSshError> {
        if limit == 0 {
            return Err(NativeSshError::InvalidOutputLimit);
        }
        self.max_output_bytes = limit;
        Ok(self)
    }
}

impl std::fmt::Debug for NativeAgentCommandRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAgentCommandRequest")
            .field("target", &self.target)
            .field("username", &self.username)
            .field("external_key", &self.external_key)
            .field("command", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("max_output_bytes", &self.max_output_bytes)
            .finish()
    }
}

impl NativeCommandRequest {
    pub fn new(
        target: SshTarget,
        username: impl Into<String>,
        private_key: SecretBytes,
        command: impl Into<Vec<u8>>,
    ) -> Result<Self, NativeSshError> {
        let username = username.into();
        let command = command.into();
        validate_username(&username)?;
        if private_key.is_empty() {
            return Err(NativeSshError::EmptyPrivateKey);
        }
        if command.is_empty() {
            return Err(NativeSshError::EmptyCommand);
        }
        Ok(Self {
            target,
            username,
            private_key,
            private_key_passphrase: None,
            command,
            timeout: Duration::from_secs(60),
            max_output_bytes: 1024 * 1024,
        })
    }

    #[must_use]
    pub fn with_passphrase(mut self, passphrase: SecretBytes) -> Self {
        self.private_key_passphrase = Some(passphrase);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, NativeSshError> {
        if timeout.is_zero() {
            return Err(NativeSshError::InvalidCommandTimeout);
        }
        self.timeout = timeout;
        Ok(self)
    }

    pub fn with_max_output_bytes(mut self, limit: usize) -> Result<Self, NativeSshError> {
        if limit == 0 {
            return Err(NativeSshError::InvalidOutputLimit);
        }
        self.max_output_bytes = limit;
        Ok(self)
    }
}

fn validate_username(username: &str) -> Result<(), NativeSshError> {
    if username.trim().is_empty() || username.chars().any(char::is_control) {
        return Err(NativeSshError::InvalidUsername);
    }
    Ok(())
}

impl std::fmt::Debug for NativeCommandRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeCommandRequest")
            .field("target", &self.target)
            .field("username", &self.username)
            .field("private_key", &"[REDACTED]")
            .field(
                "private_key_passphrase",
                &self.private_key_passphrase.as_ref().map(|_| "[REDACTED]"),
            )
            .field("command", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("max_output_bytes", &self.max_output_bytes)
            .finish()
    }
}

pub struct NativeCommandOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: u32,
    host_key_decision: HostKeyDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TerminalSize {
    pub columns: u32,
    pub rows: u32,
    pub pixel_width: u32,
    pub pixel_height: u32,
}

impl TerminalSize {
    pub fn new(columns: u32, rows: u32) -> Result<Self, NativeSshError> {
        if columns == 0 || rows == 0 {
            return Err(NativeSshError::InvalidTerminalSize);
        }
        Ok(Self {
            columns,
            rows,
            pixel_width: 0,
            pixel_height: 0,
        })
    }

    #[must_use]
    pub const fn with_pixels(mut self, pixel_width: u32, pixel_height: u32) -> Self {
        self.pixel_width = pixel_width;
        self.pixel_height = pixel_height;
        self
    }
}

pub struct NativeShellRequest {
    target: SshTarget,
    username: String,
    private_key: SecretBytes,
    private_key_passphrase: Option<SecretBytes>,
    terminal_type: String,
    initial_size: TerminalSize,
}

pub struct NativeAgentShellRequest {
    target: SshTarget,
    username: String,
    external_key: ExternalKeyReference,
    terminal_type: String,
    initial_size: TerminalSize,
}

pub struct NativeShellIo<R, O, E> {
    input: R,
    output: O,
    error_output: E,
    size_changes: watch::Receiver<TerminalSize>,
}

impl<R, O, E> NativeShellIo<R, O, E> {
    #[must_use]
    pub const fn new(
        input: R,
        output: O,
        error_output: E,
        size_changes: watch::Receiver<TerminalSize>,
    ) -> Self {
        Self {
            input,
            output,
            error_output,
            size_changes,
        }
    }
}

impl NativeShellRequest {
    pub fn new(
        target: SshTarget,
        username: impl Into<String>,
        private_key: SecretBytes,
        initial_size: TerminalSize,
    ) -> Result<Self, NativeSshError> {
        let username = username.into();
        validate_username(&username)?;
        if private_key.is_empty() {
            return Err(NativeSshError::EmptyPrivateKey);
        }
        Ok(Self {
            target,
            username,
            private_key,
            private_key_passphrase: None,
            terminal_type: "xterm-256color".to_owned(),
            initial_size,
        })
    }

    #[must_use]
    pub fn with_passphrase(mut self, passphrase: SecretBytes) -> Self {
        self.private_key_passphrase = Some(passphrase);
        self
    }

    pub fn with_terminal_type(
        mut self,
        terminal_type: impl Into<String>,
    ) -> Result<Self, NativeSshError> {
        self.terminal_type = validate_terminal_type(terminal_type)?;
        Ok(self)
    }
}

impl NativeAgentShellRequest {
    pub fn new(
        target: SshTarget,
        username: impl Into<String>,
        external_key: ExternalKeyReference,
        initial_size: TerminalSize,
    ) -> Result<Self, NativeSshError> {
        let username = username.into();
        validate_username(&username)?;
        let public_key = ssh_key::PublicKey::from_bytes(&external_key.public_key_blob)?;
        if public_key.algorithm().to_string() != external_key.algorithm {
            return Err(NativeSshError::AgentIdentityNotFound);
        }
        Ok(Self {
            target,
            username,
            external_key,
            terminal_type: "xterm-256color".to_owned(),
            initial_size,
        })
    }

    pub fn with_terminal_type(
        mut self,
        terminal_type: impl Into<String>,
    ) -> Result<Self, NativeSshError> {
        self.terminal_type = validate_terminal_type(terminal_type)?;
        Ok(self)
    }
}

impl std::fmt::Debug for NativeAgentShellRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAgentShellRequest")
            .field("target", &self.target)
            .field("username", &self.username)
            .field("external_key", &self.external_key)
            .field("terminal_type", &self.terminal_type)
            .field("initial_size", &self.initial_size)
            .finish()
    }
}

fn validate_terminal_type(terminal_type: impl Into<String>) -> Result<String, NativeSshError> {
    let terminal_type = terminal_type.into();
    if terminal_type.is_empty()
        || terminal_type.len() > 64
        || !terminal_type
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(NativeSshError::InvalidTerminalType);
    }
    Ok(terminal_type)
}

impl std::fmt::Debug for NativeShellRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeShellRequest")
            .field("target", &self.target)
            .field("username", &self.username)
            .field("private_key", &"[REDACTED]")
            .field(
                "private_key_passphrase",
                &self.private_key_passphrase.as_ref().map(|_| "[REDACTED]"),
            )
            .field("terminal_type", &self.terminal_type)
            .field("initial_size", &self.initial_size)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeShellOutput {
    exit_status: u32,
    host_key_decision: HostKeyDecision,
}

impl NativeShellOutput {
    #[must_use]
    pub const fn exit_status(&self) -> u32 {
        self.exit_status
    }

    #[must_use]
    pub const fn host_key_decision(&self) -> &HostKeyDecision {
        &self.host_key_decision
    }
}

impl NativeCommandOutput {
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    #[must_use]
    pub const fn exit_status(&self) -> u32 {
        self.exit_status
    }

    #[must_use]
    pub const fn host_key_decision(&self) -> &HostKeyDecision {
        &self.host_key_decision
    }
}

impl std::fmt::Debug for NativeCommandOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeCommandOutput")
            .field(
                "stdout",
                &format_args!("[REDACTED; {} bytes]", self.stdout.len()),
            )
            .field(
                "stderr",
                &format_args!("[REDACTED; {} bytes]", self.stderr.len()),
            )
            .field("exit_status", &self.exit_status)
            .field("host_key_decision", &self.host_key_decision)
            .finish()
    }
}

impl Default for NativeSshEngine {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

impl NativeSshEngine {
    #[must_use]
    pub const fn new(handshake_timeout: Duration) -> Self {
        Self { handshake_timeout }
    }

    /// Performs SSH key exchange, evaluates the exact presented server key, and disconnects before
    /// authentication. Rejected policy decisions are returned as probe results, not transport
    /// errors, so callers can show the specific fail-closed reason.
    pub async fn probe_host_key(
        &self,
        target: &SshTarget,
        history: &HostKeyHistory,
        policy: &HostKeyPolicy,
    ) -> Result<NativeHostKeyProbe, NativeSshError> {
        let captured = Arc::new(Mutex::new(None));
        let handler = NativeHostKeyHandler {
            history: history.clone(),
            policy: policy.clone(),
            captured: Arc::clone(&captured),
        };
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(self.handshake_timeout),
            ..Default::default()
        });
        let address = (target.host().to_owned(), target.port());

        match timeout(
            self.handshake_timeout,
            client::connect(config, address, handler),
        )
        .await
        {
            Err(_) => Err(NativeSshError::HandshakeTimeout),
            Ok(Ok(handle)) => {
                let _ = handle
                    .disconnect(Disconnect::ByApplication, "host-key probe complete", "en")
                    .await;
                take_probe(&captured)
            }
            Ok(Err(error)) => match take_probe(&captured) {
                Ok(probe) => Ok(probe),
                Err(NativeSshError::MissingHostKey) => Err(error),
                Err(other) => Err(other),
            },
        }
    }

    /// Opens a native SSH connection with fail-closed host-key verification, authenticates with an
    /// in-memory private key, executes one remote command, and captures bounded output.
    pub async fn execute_command(
        &self,
        request: NativeCommandRequest,
        history: &HostKeyHistory,
        policy: &HostKeyPolicy,
    ) -> Result<NativeCommandOutput, NativeSshError> {
        let command_timeout = request.timeout;
        timeout(
            command_timeout,
            self.execute_command_inner(request, history, policy),
        )
        .await
        .map_err(|_| NativeSshError::CommandTimeout)?
    }

    pub async fn execute_agent_command<S>(
        &self,
        request: NativeAgentCommandRequest,
        agent: &mut AgentClient<S>,
        history: &HostKeyHistory,
        policy: &HostKeyPolicy,
    ) -> Result<NativeCommandOutput, NativeSshError>
    where
        S: russh::keys::agent::client::AgentStream + Send + Unpin,
    {
        let command_timeout = request.timeout;
        timeout(
            command_timeout,
            self.execute_agent_command_inner(request, agent, history, policy),
        )
        .await
        .map_err(|_| NativeSshError::CommandTimeout)?
    }

    async fn execute_agent_command_inner<S>(
        &self,
        request: NativeAgentCommandRequest,
        agent: &mut AgentClient<S>,
        history: &HostKeyHistory,
        policy: &HostKeyPolicy,
    ) -> Result<NativeCommandOutput, NativeSshError>
    where
        S: russh::keys::agent::client::AgentStream + Send + Unpin,
    {
        let public_key = ssh_key::PublicKey::from_bytes(&request.external_key.public_key_blob)?;
        let identities = agent.request_identities().await?;
        if !identities.iter().any(|identity| {
            matches!(identity, AgentIdentity::PublicKey { key, .. } if key == &public_key)
        }) {
            return Err(NativeSshError::AgentIdentityNotFound);
        }
        let captured = Arc::new(Mutex::new(None));
        let handler = NativeHostKeyHandler {
            history: history.clone(),
            policy: policy.clone(),
            captured: Arc::clone(&captured),
        };
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(request.timeout),
            ..Default::default()
        });
        let address = (request.target.host().to_owned(), request.target.port());
        let connect_result = timeout(
            self.handshake_timeout,
            client::connect(config, address, handler),
        )
        .await
        .map_err(|_| NativeSshError::HandshakeTimeout)?;
        let (mut handle, probe) = match connect_result {
            Ok(handle) => (handle, take_probe(&captured)?),
            Err(error) => match take_probe(&captured) {
                Ok(probe) if !probe.decision.is_accepted() => {
                    return Err(NativeSshError::HostKeyRejected(probe.decision));
                }
                Ok(_) | Err(NativeSshError::MissingHostKey) => return Err(error),
                Err(other) => return Err(other),
            },
        };
        if !probe.decision.is_accepted() {
            return Err(NativeSshError::HostKeyRejected(probe.decision));
        }
        let rsa_hash = handle.best_supported_rsa_hash().await?.flatten();
        let authentication = handle
            .authenticate_publickey_with(request.username, public_key, rsa_hash, agent)
            .await
            .map_err(NativeSshError::AgentAuthentication)?;
        if !authentication.success() {
            return Err(NativeSshError::AuthenticationRejected);
        }

        let mut channel = handle.channel_open_session().await?;
        channel.exec(true, request.command).await?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;
        let mut exit_signal = None;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    append_bounded(&mut stdout, &data, stderr.len(), request.max_output_bytes)?;
                }
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    append_bounded(&mut stderr, &data, stdout.len(), request.max_output_bytes)?;
                }
                ChannelMsg::ExitStatus {
                    exit_status: status,
                } => exit_status = Some(status),
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    exit_signal = Some(format!("{signal_name:?}"));
                }
                ChannelMsg::Failure => return Err(NativeSshError::CommandRequestRejected),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        let _ = handle
            .disconnect(Disconnect::ByApplication, "agent command complete", "en")
            .await;
        if let Some(signal) = exit_signal {
            return Err(NativeSshError::RemoteCommandSignaled(signal));
        }
        let exit_status = exit_status.ok_or(NativeSshError::MissingExitStatus)?;
        Ok(NativeCommandOutput {
            stdout,
            stderr,
            exit_status,
            host_key_decision: probe.decision,
        })
    }

    async fn execute_command_inner(
        &self,
        request: NativeCommandRequest,
        history: &HostKeyHistory,
        policy: &HostKeyPolicy,
    ) -> Result<NativeCommandOutput, NativeSshError> {
        let private_key = decode_private_key(
            &request.private_key,
            request.private_key_passphrase.as_ref(),
        )?;
        let captured = Arc::new(Mutex::new(None));
        let handler = NativeHostKeyHandler {
            history: history.clone(),
            policy: policy.clone(),
            captured: Arc::clone(&captured),
        };
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(request.timeout),
            ..Default::default()
        });
        let address = (request.target.host().to_owned(), request.target.port());
        let connect_result = timeout(
            self.handshake_timeout,
            client::connect(config, address, handler),
        )
        .await
        .map_err(|_| NativeSshError::HandshakeTimeout)?;
        let (mut handle, probe) = match connect_result {
            Ok(handle) => (handle, take_probe(&captured)?),
            Err(error) => match take_probe(&captured) {
                Ok(probe) if !probe.decision.is_accepted() => {
                    return Err(NativeSshError::HostKeyRejected(probe.decision));
                }
                Ok(_) | Err(NativeSshError::MissingHostKey) => return Err(error),
                Err(other) => return Err(other),
            },
        };
        if !probe.decision.is_accepted() {
            return Err(NativeSshError::HostKeyRejected(probe.decision));
        }

        let rsa_hash = handle.best_supported_rsa_hash().await?.flatten();
        let authentication = handle
            .authenticate_publickey(
                request.username,
                PrivateKeyWithHashAlg::new(Arc::new(private_key), rsa_hash),
            )
            .await?;
        if !authentication.success() {
            return Err(NativeSshError::AuthenticationRejected);
        }

        let mut channel = handle.channel_open_session().await?;
        channel.exec(true, request.command).await?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;
        let mut exit_signal = None;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    append_bounded(&mut stdout, &data, stderr.len(), request.max_output_bytes)?;
                }
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    append_bounded(&mut stderr, &data, stdout.len(), request.max_output_bytes)?;
                }
                ChannelMsg::ExitStatus {
                    exit_status: status,
                } => exit_status = Some(status),
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    exit_signal = Some(format!("{signal_name:?}"));
                }
                ChannelMsg::Failure => return Err(NativeSshError::CommandRequestRejected),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        let _ = handle
            .disconnect(Disconnect::ByApplication, "command complete", "en")
            .await;
        if let Some(signal) = exit_signal {
            return Err(NativeSshError::RemoteCommandSignaled(signal));
        }
        let exit_status = exit_status.ok_or(NativeSshError::MissingExitStatus)?;
        Ok(NativeCommandOutput {
            stdout,
            stderr,
            exit_status,
            host_key_decision: probe.decision,
        })
    }

    /// Opens an authenticated native SSH session, requests a PTY and shell, then streams terminal
    /// bytes without buffering terminal contents in the engine.
    pub async fn run_shell<R, O, E>(
        &self,
        request: NativeShellRequest,
        history: &HostKeyHistory,
        policy: &HostKeyPolicy,
        io: NativeShellIo<R, O, E>,
    ) -> Result<NativeShellOutput, NativeSshError>
    where
        R: AsyncRead + Unpin,
        O: AsyncWrite + Unpin,
        E: AsyncWrite + Unpin,
    {
        let private_key = decode_private_key(
            &request.private_key,
            request.private_key_passphrase.as_ref(),
        )?;
        let captured = Arc::new(Mutex::new(None));
        let handler = NativeHostKeyHandler {
            history: history.clone(),
            policy: policy.clone(),
            captured: Arc::clone(&captured),
        };
        let config = Arc::new(client::Config::default());
        let address = (request.target.host().to_owned(), request.target.port());
        let connect_result = timeout(
            self.handshake_timeout,
            client::connect(config, address, handler),
        )
        .await
        .map_err(|_| NativeSshError::HandshakeTimeout)?;
        let (mut handle, probe) = match connect_result {
            Ok(handle) => (handle, take_probe(&captured)?),
            Err(error) => match take_probe(&captured) {
                Ok(probe) if !probe.decision.is_accepted() => {
                    return Err(NativeSshError::HostKeyRejected(probe.decision));
                }
                Ok(_) | Err(NativeSshError::MissingHostKey) => return Err(error),
                Err(other) => return Err(other),
            },
        };
        if !probe.decision.is_accepted() {
            return Err(NativeSshError::HostKeyRejected(probe.decision));
        }

        let rsa_hash = handle.best_supported_rsa_hash().await?.flatten();
        let authentication = handle
            .authenticate_publickey(
                request.username,
                PrivateKeyWithHashAlg::new(Arc::new(private_key), rsa_hash),
            )
            .await?;
        if !authentication.success() {
            return Err(NativeSshError::AuthenticationRejected);
        }

        run_authenticated_shell(
            handle,
            probe,
            request.terminal_type,
            request.initial_size,
            io,
        )
        .await
    }

    /// Opens an authenticated native SSH session through an external key agent, then uses the same
    /// PTY, resize and byte-streaming path as locally held private keys.
    pub async fn run_agent_shell<S, R, O, E>(
        &self,
        request: NativeAgentShellRequest,
        agent: &mut AgentClient<S>,
        history: &HostKeyHistory,
        policy: &HostKeyPolicy,
        io: NativeShellIo<R, O, E>,
    ) -> Result<NativeShellOutput, NativeSshError>
    where
        S: russh::keys::agent::client::AgentStream + Send + Unpin,
        R: AsyncRead + Unpin,
        O: AsyncWrite + Unpin,
        E: AsyncWrite + Unpin,
    {
        let public_key = ssh_key::PublicKey::from_bytes(&request.external_key.public_key_blob)?;
        let identities = agent.request_identities().await?;
        if !identities.iter().any(|identity| {
            matches!(identity, AgentIdentity::PublicKey { key, .. } if key == &public_key)
        }) {
            return Err(NativeSshError::AgentIdentityNotFound);
        }
        let captured = Arc::new(Mutex::new(None));
        let handler = NativeHostKeyHandler {
            history: history.clone(),
            policy: policy.clone(),
            captured: Arc::clone(&captured),
        };
        let config = Arc::new(client::Config::default());
        let address = (request.target.host().to_owned(), request.target.port());
        let connect_result = timeout(
            self.handshake_timeout,
            client::connect(config, address, handler),
        )
        .await
        .map_err(|_| NativeSshError::HandshakeTimeout)?;
        let (mut handle, probe) = match connect_result {
            Ok(handle) => (handle, take_probe(&captured)?),
            Err(error) => match take_probe(&captured) {
                Ok(probe) if !probe.decision.is_accepted() => {
                    return Err(NativeSshError::HostKeyRejected(probe.decision));
                }
                Ok(_) | Err(NativeSshError::MissingHostKey) => return Err(error),
                Err(other) => return Err(other),
            },
        };
        if !probe.decision.is_accepted() {
            return Err(NativeSshError::HostKeyRejected(probe.decision));
        }
        let rsa_hash = handle.best_supported_rsa_hash().await?.flatten();
        let authentication = handle
            .authenticate_publickey_with(request.username, public_key, rsa_hash, agent)
            .await
            .map_err(NativeSshError::AgentAuthentication)?;
        if !authentication.success() {
            return Err(NativeSshError::AuthenticationRejected);
        }

        run_authenticated_shell(
            handle,
            probe,
            request.terminal_type,
            request.initial_size,
            io,
        )
        .await
    }

    /// Opens an SFTP v3 session after the same fail-closed host-key verification used by terminal
    /// and command sessions.
    pub async fn connect_sftp(
        &self,
        request: NativeSftpRequest,
        history: &HostKeyHistory,
        policy: &HostKeyPolicy,
    ) -> Result<NativeSftpSession, NativeSshError> {
        let private_key = decode_private_key(
            &request.private_key,
            request.private_key_passphrase.as_ref(),
        )?;
        let captured = Arc::new(Mutex::new(None));
        let handler = NativeHostKeyHandler {
            history: history.clone(),
            policy: policy.clone(),
            captured: Arc::clone(&captured),
        };
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(self.handshake_timeout),
            ..Default::default()
        });
        let address = (request.target.host().to_owned(), request.target.port());
        let connect_result = timeout(
            self.handshake_timeout,
            client::connect(config, address, handler),
        )
        .await
        .map_err(|_| NativeSshError::HandshakeTimeout)?;
        let (mut handle, probe) = checked_connection(connect_result, &captured)?;
        let rsa_hash = handle.best_supported_rsa_hash().await?.flatten();
        let authentication = handle
            .authenticate_publickey(
                request.username,
                PrivateKeyWithHashAlg::new(Arc::new(private_key), rsa_hash),
            )
            .await?;
        if !authentication.success() {
            return Err(NativeSshError::AuthenticationRejected);
        }
        open_sftp_session(handle, probe).await
    }

    /// Opens SFTP while keeping private-key operations inside the selected external SSH agent.
    pub async fn connect_agent_sftp<S>(
        &self,
        request: NativeAgentSftpRequest,
        agent: &mut AgentClient<S>,
        history: &HostKeyHistory,
        policy: &HostKeyPolicy,
    ) -> Result<NativeSftpSession, NativeSshError>
    where
        S: russh::keys::agent::client::AgentStream + Send + Unpin,
    {
        let public_key = ssh_key::PublicKey::from_bytes(&request.external_key.public_key_blob)?;
        let identities = agent.request_identities().await?;
        if !identities.iter().any(|identity| {
            matches!(identity, AgentIdentity::PublicKey { key, .. } if key == &public_key)
        }) {
            return Err(NativeSshError::AgentIdentityNotFound);
        }
        let captured = Arc::new(Mutex::new(None));
        let handler = NativeHostKeyHandler {
            history: history.clone(),
            policy: policy.clone(),
            captured: Arc::clone(&captured),
        };
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(self.handshake_timeout),
            ..Default::default()
        });
        let address = (request.target.host().to_owned(), request.target.port());
        let connect_result = timeout(
            self.handshake_timeout,
            client::connect(config, address, handler),
        )
        .await
        .map_err(|_| NativeSshError::HandshakeTimeout)?;
        let (mut handle, probe) = checked_connection(connect_result, &captured)?;
        let rsa_hash = handle.best_supported_rsa_hash().await?.flatten();
        let authentication = handle
            .authenticate_publickey_with(request.username, public_key, rsa_hash, agent)
            .await
            .map_err(NativeSshError::AgentAuthentication)?;
        if !authentication.success() {
            return Err(NativeSshError::AuthenticationRejected);
        }
        open_sftp_session(handle, probe).await
    }
}

fn checked_connection(
    result: Result<client::Handle<NativeHostKeyHandler>, NativeSshError>,
    captured: &Mutex<Option<NativeHostKeyProbe>>,
) -> Result<(client::Handle<NativeHostKeyHandler>, NativeHostKeyProbe), NativeSshError> {
    match result {
        Ok(handle) => {
            let probe = take_probe(captured)?;
            if !probe.decision.is_accepted() {
                return Err(NativeSshError::HostKeyRejected(probe.decision));
            }
            Ok((handle, probe))
        }
        Err(error) => match take_probe(captured) {
            Ok(probe) if !probe.decision.is_accepted() => {
                Err(NativeSshError::HostKeyRejected(probe.decision))
            }
            Ok(_) | Err(NativeSshError::MissingHostKey) => Err(error),
            Err(other) => Err(other),
        },
    }
}

async fn open_sftp_session(
    handle: client::Handle<NativeHostKeyHandler>,
    probe: NativeHostKeyProbe,
) -> Result<NativeSftpSession, NativeSshError> {
    let mut channel = handle.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    wait_for_request_success(&mut channel, NativeSshError::SftpSubsystemRejected).await?;
    let sftp = SftpSession::new(channel.into_stream()).await?;
    Ok(NativeSftpSession {
        handle,
        sftp,
        host_key_decision: probe.decision,
    })
}

async fn run_authenticated_shell<R, O, E>(
    handle: client::Handle<NativeHostKeyHandler>,
    probe: NativeHostKeyProbe,
    terminal_type: String,
    initial_size: TerminalSize,
    io: NativeShellIo<R, O, E>,
) -> Result<NativeShellOutput, NativeSshError>
where
    R: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let NativeShellIo {
        mut input,
        mut output,
        mut error_output,
        mut size_changes,
    } = io;

    let mut channel = handle.channel_open_session().await?;
    let size = initial_size;
    channel
        .request_pty(
            true,
            &terminal_type,
            size.columns,
            size.rows,
            size.pixel_width,
            size.pixel_height,
            &[],
        )
        .await?;
    wait_for_request_success(&mut channel, NativeSshError::PtyRequestRejected).await?;
    channel.request_shell(true).await?;
    wait_for_request_success(&mut channel, NativeSshError::ShellRequestRejected).await?;

    let (mut reader, writer) = channel.split();
    let mut input_buffer = vec![0_u8; 16 * 1024];
    let mut input_closed = false;
    let mut size_stream_open = true;
    let mut last_size = size;
    let mut exit_status = None;
    let mut exit_signal = None;
    loop {
        tokio::select! {
            input_result = input.read(&mut input_buffer), if !input_closed => {
                match input_result? {
                    0 => {
                        input_closed = true;
                        writer.eof().await?;
                    }
                    count => writer.data_bytes(input_buffer[..count].to_vec()).await?,
                }
            }
            changed = size_changes.changed(), if size_stream_open => {
                if changed.is_err() {
                    size_stream_open = false;
                } else {
                    let next = *size_changes.borrow_and_update();
                    if next != last_size {
                        writer.window_change(
                            next.columns,
                            next.rows,
                            next.pixel_width,
                            next.pixel_height,
                        ).await?;
                        last_size = next;
                    }
                }
            }
            message = reader.wait() => {
                let Some(message) = message else { break; };
                match message {
                    ChannelMsg::Data { data } => {
                        output.write_all(&data).await?;
                        output.flush().await?;
                    }
                    ChannelMsg::ExtendedData { data, ext: 1 } => {
                        error_output.write_all(&data).await?;
                        error_output.flush().await?;
                    }
                    ChannelMsg::ExtendedData { ext, .. } => {
                        return Err(NativeSshError::UnsupportedExtendedData(ext));
                    }
                    ChannelMsg::ExitStatus { exit_status: status } => {
                        exit_status = Some(status);
                        if !input_closed {
                            input_closed = true;
                            writer.eof().await?;
                        }
                    }
                    ChannelMsg::ExitSignal { signal_name, .. } => {
                        exit_signal = Some(format!("{signal_name:?}"));
                        if !input_closed {
                            input_closed = true;
                            writer.eof().await?;
                        }
                    }
                    ChannelMsg::Close => break,
                    ChannelMsg::Failure => return Err(NativeSshError::ShellRequestRejected),
                    _ => {}
                }
            }
        }
    }
    output.flush().await?;
    error_output.flush().await?;
    let _ = handle
        .disconnect(
            Disconnect::ByApplication,
            "interactive shell complete",
            "en",
        )
        .await;
    if let Some(signal) = exit_signal {
        return Err(NativeSshError::RemoteCommandSignaled(signal));
    }
    let exit_status = exit_status.ok_or(NativeSshError::MissingExitStatus)?;
    Ok(NativeShellOutput {
        exit_status,
        host_key_decision: probe.decision,
    })
}

async fn wait_for_request_success(
    channel: &mut russh::Channel<client::Msg>,
    rejected: NativeSshError,
) -> Result<(), NativeSshError> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure | ChannelMsg::Close) | None => return Err(rejected),
            Some(_) => {}
        }
    }
}

fn append_bounded(
    destination: &mut Vec<u8>,
    data: &[u8],
    other_length: usize,
    limit: usize,
) -> Result<(), NativeSshError> {
    let total = destination
        .len()
        .checked_add(other_length)
        .and_then(|current| current.checked_add(data.len()))
        .ok_or(NativeSshError::OutputLimitExceeded { limit })?;
    if total > limit {
        return Err(NativeSshError::OutputLimitExceeded { limit });
    }
    destination.extend_from_slice(data);
    Ok(())
}

struct NativeHostKeyHandler {
    history: HostKeyHistory,
    policy: HostKeyPolicy,
    captured: Arc<Mutex<Option<NativeHostKeyProbe>>>,
}

impl client::Handler for NativeHostKeyHandler {
    type Error = NativeSshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let algorithm = HostKeyAlgorithm::new(server_public_key.algorithm().to_string())?;
        let material = HostKeyMaterial::new(algorithm, server_public_key.to_bytes()?)?;
        let observation = HostKeyObservation::presented(material);
        let decision = self.history.evaluate(&observation, &self.policy);
        let accepted = decision.is_accepted();
        let probe = NativeHostKeyProbe {
            observation,
            decision,
        };
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| NativeSshError::ProbeStateUnavailable)?;
        if captured.replace(probe).is_some() {
            return Err(NativeSshError::DuplicateHostKeyCallback);
        }
        Ok(accepted)
    }
}

fn take_probe(
    captured: &Mutex<Option<NativeHostKeyProbe>>,
) -> Result<NativeHostKeyProbe, NativeSshError> {
    captured
        .lock()
        .map_err(|_| NativeSshError::ProbeStateUnavailable)?
        .take()
        .ok_or(NativeSshError::MissingHostKey)
}

#[derive(Debug, Error)]
pub enum NativeSshError {
    #[error("local terminal I/O failed: {0}")]
    LocalIo(#[from] std::io::Error),
    #[error("native SSH transport failed: {0}")]
    Transport(#[from] russh::Error),
    #[error("SFTP operation failed: {0}")]
    Sftp(#[from] russh_sftp::client::error::Error),
    #[error("presented SSH host key could not be encoded: {0}")]
    KeyEncoding(#[from] ssh_key::Error),
    #[error("SSH key provider operation failed: {0}")]
    PrivateKey(#[from] russh::keys::Error),
    #[error(transparent)]
    CredentialCapability(#[from] yasc_domain::CredentialCapabilityError),
    #[error(transparent)]
    HostKey(#[from] HostKeyError),
    #[error("native SSH host-key handshake timed out")]
    HandshakeTimeout,
    #[error("native SSH handshake completed without presenting a host key")]
    MissingHostKey,
    #[error("native SSH host-key probe state is unavailable")]
    ProbeStateUnavailable,
    #[error("native SSH transport presented more than one initial host key")]
    DuplicateHostKeyCallback,
    #[error("SSH username is invalid")]
    InvalidUsername,
    #[error("SSH private key cannot be empty")]
    EmptyPrivateKey,
    #[error("remote command cannot be empty")]
    EmptyCommand,
    #[error("command timeout must be greater than zero")]
    InvalidCommandTimeout,
    #[error("command output limit must be greater than zero")]
    InvalidOutputLimit,
    #[error("terminal dimensions must be greater than zero")]
    InvalidTerminalSize,
    #[error("terminal type must contain 1-64 safe ASCII characters")]
    InvalidTerminalType,
    #[error("SFTP path must be 1-4096 characters without control bytes or an invalid filename")]
    InvalidSftpPath,
    #[error("remote SFTP directory returned an invalid entry name")]
    InvalidSftpEntryName,
    #[error("SFTP directory entry limit must be greater than zero")]
    InvalidSftpEntryLimit,
    #[error("SFTP byte limit must be greater than zero")]
    InvalidSftpByteLimit,
    #[error("SSH private key must use a supported UTF-8 text format")]
    PrivateKeyNotUtf8,
    #[error("SSH private-key passphrase must be UTF-8")]
    PassphraseNotUtf8,
    #[error("host-key verification rejected the native session: {0:?}")]
    HostKeyRejected(HostKeyDecision),
    #[error("SSH public-key authentication was rejected")]
    AuthenticationRejected,
    #[error("SSH agent signing failed: {0}")]
    AgentAuthentication(russh::AgentAuthError),
    #[error("credential provider {0:?} is not an SSH agent on this platform")]
    UnsupportedAgentProvider(CredentialProviderKind),
    #[error("the selected public key is no longer available from the SSH agent")]
    AgentIdentityNotFound,
    #[error("remote command request was rejected")]
    CommandRequestRejected,
    #[error("remote server rejected the PTY request")]
    PtyRequestRejected,
    #[error("remote server rejected the interactive shell request")]
    ShellRequestRejected,
    #[error("remote server rejected the SFTP subsystem request")]
    SftpSubsystemRejected,
    #[error("remote shell returned unsupported extended data type {0}")]
    UnsupportedExtendedData(u32),
    #[error("remote command exceeded its timeout")]
    CommandTimeout,
    #[error("remote command output exceeded the {limit}-byte limit")]
    OutputLimitExceeded { limit: usize },
    #[error("remote directory exceeded the {limit}-entry limit")]
    SftpEntryLimitExceeded { limit: usize },
    #[error("remote file exceeded the {limit}-byte limit")]
    SftpByteLimitExceeded { limit: usize },
    #[error("remote destination already exists: {0}")]
    SftpDestinationExists(String),
    #[error("remote command ended without an exit status")]
    MissingExitStatus,
    #[error("remote command ended from signal {0}")]
    RemoteCommandSignaled(String),
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use russh::{
        Channel, ChannelId,
        keys::{PrivateKey, ssh_key::LineEnding},
        server,
        server::{Auth, ChannelOpenHandle, Server as _, Session},
    };
    use russh_sftp::protocol::{
        Attrs, Data, File, FileAttributes, Handle, Name, Status, StatusCode, Version,
    };
    use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
    use yasc_domain::{HostId, HostKeyDecision, HostKeyHistory, HostKeyPolicy};

    use super::*;

    #[derive(Clone)]
    struct TestServer {
        authorized_key: Option<ssh_key::PublicKey>,
        authentication_attempts: Arc<AtomicUsize>,
        shell: Option<Arc<Mutex<ShellFixture>>>,
        channels: Arc<tokio::sync::Mutex<HashMap<ChannelId, Channel<server::Msg>>>>,
        sftp: Option<Arc<tokio::sync::Mutex<SftpFixture>>>,
    }

    #[derive(Debug)]
    struct ShellFixture {
        accept_pty: bool,
        pty: Option<(String, u32, u32)>,
        window_changes: Vec<(u32, u32)>,
        input: Vec<u8>,
        shell_requests: usize,
    }

    impl ShellFixture {
        fn accepting() -> Self {
            Self {
                accept_pty: true,
                pty: None,
                window_changes: Vec::new(),
                input: Vec::new(),
                shell_requests: 0,
            }
        }
    }

    #[derive(Debug, Default)]
    struct SftpFixture {
        files: BTreeMap<String, Vec<u8>>,
        directories: Vec<String>,
    }

    struct TestSftpHandler {
        fixture: Arc<tokio::sync::Mutex<SftpFixture>>,
        directory_read: bool,
        handles: HashMap<String, String>,
    }

    impl TestSftpHandler {
        fn new(fixture: Arc<tokio::sync::Mutex<SftpFixture>>) -> Self {
            Self {
                fixture,
                directory_read: false,
                handles: HashMap::new(),
            }
        }

        fn status(id: u32) -> Status {
            Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".to_owned(),
                language_tag: "en".to_owned(),
            }
        }

        fn file_attributes(size: usize) -> FileAttributes {
            FileAttributes {
                size: Some(size as u64),
                permissions: Some(0o100_644),
                mtime: Some(1_700_000_000),
                ..Default::default()
            }
        }

        fn directory_attributes() -> FileAttributes {
            FileAttributes {
                size: Some(0),
                permissions: Some(0o40_755),
                mtime: Some(1_700_000_001),
                ..Default::default()
            }
        }
    }

    impl russh_sftp::server::Handler for TestSftpHandler {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        async fn init(
            &mut self,
            _: u32,
            _: HashMap<String, String>,
        ) -> Result<Version, Self::Error> {
            Ok(Version::new())
        }

        async fn open(
            &mut self,
            id: u32,
            filename: String,
            flags: OpenFlags,
            _: FileAttributes,
        ) -> Result<Handle, Self::Error> {
            let mut fixture = self.fixture.lock().await;
            let exists = fixture.files.contains_key(&filename);
            if flags.contains(OpenFlags::CREATE) {
                if exists && flags.contains(OpenFlags::EXCLUDE) {
                    return Err(StatusCode::Failure);
                }
                fixture.files.entry(filename.clone()).or_default();
            } else if !exists {
                return Err(StatusCode::NoSuchFile);
            }
            let handle = format!("file-{id}");
            self.handles.insert(handle.clone(), filename);
            Ok(Handle { id, handle })
        }

        async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
            self.handles.remove(&handle);
            Ok(Self::status(id))
        }

        async fn read(
            &mut self,
            id: u32,
            handle: String,
            offset: u64,
            len: u32,
        ) -> Result<Data, Self::Error> {
            let path = self.handles.get(&handle).ok_or(StatusCode::NoSuchFile)?;
            let fixture = self.fixture.lock().await;
            let contents = fixture.files.get(path).ok_or(StatusCode::NoSuchFile)?;
            let offset = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
            if offset >= contents.len() {
                return Err(StatusCode::Eof);
            }
            let end = offset.saturating_add(len as usize).min(contents.len());
            Ok(Data {
                id,
                data: contents[offset..end].to_vec(),
            })
        }

        async fn write(
            &mut self,
            id: u32,
            handle: String,
            offset: u64,
            data: Vec<u8>,
        ) -> Result<Status, Self::Error> {
            let path = self.handles.get(&handle).ok_or(StatusCode::NoSuchFile)?;
            let mut fixture = self.fixture.lock().await;
            let contents = fixture.files.get_mut(path).ok_or(StatusCode::NoSuchFile)?;
            let offset = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
            let end = offset.checked_add(data.len()).ok_or(StatusCode::Failure)?;
            if contents.len() < end {
                contents.resize(end, 0);
            }
            contents[offset..end].copy_from_slice(&data);
            Ok(Self::status(id))
        }

        async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
            let fixture = self.fixture.lock().await;
            if let Some(contents) = fixture.files.get(&path) {
                return Ok(Attrs {
                    id,
                    attrs: Self::file_attributes(contents.len()),
                });
            }
            if matches!(path.as_str(), "/" | ".") || fixture.directories.contains(&path) {
                return Ok(Attrs {
                    id,
                    attrs: Self::directory_attributes(),
                });
            }
            Err(StatusCode::NoSuchFile)
        }

        async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
            self.stat(id, path).await
        }

        async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
            let fixture = self.fixture.lock().await;
            if !matches!(path.as_str(), "/" | ".") && !fixture.directories.contains(&path) {
                return Err(StatusCode::NoSuchFile);
            }
            drop(fixture);
            self.directory_read = false;
            let handle = format!("dir-{id}");
            self.handles.insert(handle.clone(), path);
            Ok(Handle { id, handle })
        }

        async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
            let path = self.handles.get(&handle).ok_or(StatusCode::NoSuchFile)?;
            if self.directory_read {
                return Err(StatusCode::Eof);
            }
            self.directory_read = true;
            let fixture = self.fixture.lock().await;
            let prefix = if matches!(path.as_str(), "/" | ".") {
                "/"
            } else {
                path.as_str()
            };
            let mut files = Vec::new();
            for directory in &fixture.directories {
                if let Some(name) = direct_child(prefix, directory) {
                    files.push(File::new(name, Self::directory_attributes()));
                }
            }
            for (filename, contents) in &fixture.files {
                if let Some(name) = direct_child(prefix, filename) {
                    files.push(File::new(name, Self::file_attributes(contents.len())));
                }
            }
            Ok(Name { id, files })
        }

        async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
            let removed = self.fixture.lock().await.files.remove(&filename);
            removed
                .map(|_| Self::status(id))
                .ok_or(StatusCode::NoSuchFile)
        }

        async fn rename(
            &mut self,
            id: u32,
            oldpath: String,
            newpath: String,
        ) -> Result<Status, Self::Error> {
            let mut fixture = self.fixture.lock().await;
            if fixture.files.contains_key(&newpath) {
                return Err(StatusCode::Failure);
            }
            let contents = fixture
                .files
                .remove(&oldpath)
                .ok_or(StatusCode::NoSuchFile)?;
            fixture.files.insert(newpath, contents);
            Ok(Self::status(id))
        }
    }

    fn direct_child<'a>(parent: &str, path: &'a str) -> Option<&'a str> {
        let suffix = if parent == "/" {
            path.strip_prefix('/')?
        } else {
            path.strip_prefix(parent)?.strip_prefix('/')?
        };
        (!suffix.is_empty() && !suffix.contains('/')).then_some(suffix)
    }

    impl server::Server for TestServer {
        type Handler = Self;

        fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for TestServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _: &str,
            public_key: &ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            self.authentication_attempts.fetch_add(1, Ordering::SeqCst);
            Ok(if self.authorized_key.as_ref() == Some(public_key) {
                Auth::Accept
            } else {
                Auth::reject()
            })
        }

        async fn channel_open_session(
            &mut self,
            channel: Channel<server::Msg>,
            reply: ChannelOpenHandle,
            _: &mut Session,
        ) -> Result<(), Self::Error> {
            self.channels.lock().await.insert(channel.id(), channel);
            reply.accept().await;
            Ok(())
        }

        async fn subsystem_request(
            &mut self,
            channel: ChannelId,
            name: &str,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let Some(fixture) = self.sftp.clone().filter(|_| name == "sftp") else {
                session.channel_failure(channel)?;
                return Ok(());
            };
            let Some(channel) = self.channels.lock().await.remove(&channel) else {
                session.channel_failure(channel)?;
                return Ok(());
            };
            session.channel_success(channel.id())?;
            tokio::spawn(async move {
                russh_sftp::server::run(channel.into_stream(), TestSftpHandler::new(fixture)).await;
            });
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            command: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            if command != b"fixture-command" {
                session.channel_failure(channel)?;
                return Ok(());
            }
            session.channel_success(channel)?;
            session.data(channel, b"fixture stdout\n".as_slice())?;
            session.extended_data(channel, 1, b"fixture stderr\n".as_slice())?;
            session.exit_status_request(channel, 7)?;
            session.close(channel)?;
            Ok(())
        }

        async fn pty_request(
            &mut self,
            channel: ChannelId,
            term: &str,
            col_width: u32,
            row_height: u32,
            _: u32,
            _: u32,
            _: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let Some(shell) = &self.shell else {
                session.channel_failure(channel)?;
                return Ok(());
            };
            let mut shell = shell.lock().unwrap();
            shell.pty = Some((term.to_owned(), col_width, row_height));
            if shell.accept_pty {
                session.channel_success(channel)?;
            } else {
                session.channel_failure(channel)?;
            }
            Ok(())
        }

        async fn shell_request(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let Some(shell) = &self.shell else {
                session.channel_failure(channel)?;
                return Ok(());
            };
            shell.lock().unwrap().shell_requests += 1;
            session.channel_success(channel)?;
            Ok(())
        }

        async fn window_change_request(
            &mut self,
            _: ChannelId,
            col_width: u32,
            row_height: u32,
            _: u32,
            _: u32,
            _: &mut Session,
        ) -> Result<(), Self::Error> {
            if let Some(shell) = &self.shell {
                shell
                    .lock()
                    .unwrap()
                    .window_changes
                    .push((col_width, row_height));
            }
            Ok(())
        }

        async fn data(
            &mut self,
            _: ChannelId,
            data: &[u8],
            _: &mut Session,
        ) -> Result<(), Self::Error> {
            if let Some(shell) = &self.shell {
                shell.lock().unwrap().input.extend_from_slice(data);
            }
            Ok(())
        }

        async fn channel_eof(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            if self.shell.is_some() {
                session.data(channel, b"shell stdout\r\n".as_slice())?;
                session.extended_data(channel, 1, b"shell stderr\r\n".as_slice())?;
                session.exit_status_request(channel, 0)?;
                session.close(channel)?;
            }
            Ok(())
        }
    }

    async fn start_server(
        key: PrivateKey,
        authorized_key: Option<ssh_key::PublicKey>,
    ) -> (
        SocketAddr,
        russh::server::RunningServerHandle,
        JoinHandle<std::io::Result<()>>,
        Arc<AtomicUsize>,
    ) {
        start_server_with_shell(key, authorized_key, None).await
    }

    async fn start_server_with_shell(
        key: PrivateKey,
        authorized_key: Option<ssh_key::PublicKey>,
        shell: Option<Arc<Mutex<ShellFixture>>>,
    ) -> (
        SocketAddr,
        russh::server::RunningServerHandle,
        JoinHandle<std::io::Result<()>>,
        Arc<AtomicUsize>,
    ) {
        start_server_with_fixtures(key, authorized_key, shell, None).await
    }

    async fn start_server_with_fixtures(
        key: PrivateKey,
        authorized_key: Option<ssh_key::PublicKey>,
        shell: Option<Arc<Mutex<ShellFixture>>>,
        sftp: Option<Arc<tokio::sync::Mutex<SftpFixture>>>,
    ) -> (
        SocketAddr,
        russh::server::RunningServerHandle,
        JoinHandle<std::io::Result<()>>,
        Arc<AtomicUsize>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![key],
            ..Default::default()
        });
        let (handle_sender, handle_receiver) = oneshot::channel();
        let authentication_attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = Arc::clone(&authentication_attempts);
        let task = tokio::spawn(async move {
            let mut server = TestServer {
                authorized_key,
                authentication_attempts: server_attempts,
                shell,
                channels: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                sftp,
            };
            let running = server.run_on_socket(config, &listener);
            assert!(handle_sender.send(running.handle()).is_ok());
            running.await
        });
        let shutdown = handle_receiver.await.unwrap();
        (address, shutdown, task, authentication_attempts)
    }

    #[test]
    fn interactive_request_validates_terminal_metadata_and_redacts_key() {
        assert!(matches!(
            TerminalSize::new(0, 24),
            Err(NativeSshError::InvalidTerminalSize)
        ));
        let request = NativeShellRequest::new(
            "admin@example.com".parse().unwrap(),
            "admin",
            SecretBytes::new(b"private fixture value".to_vec()),
            TerminalSize::new(80, 24).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            request.with_terminal_type("xterm;unsafe"),
            Err(NativeSshError::InvalidTerminalType)
        ));
        let request = NativeShellRequest::new(
            "admin@example.com".parse().unwrap(),
            "admin",
            SecretBytes::new(b"private fixture value".to_vec()),
            TerminalSize::new(80, 24).unwrap(),
        )
        .unwrap();
        let diagnostic = format!("{request:?}");
        assert!(!diagnostic.contains("private fixture value"));
        assert!(diagnostic.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn real_handshake_is_rejected_then_accepted_by_persistent_policy() {
        let server_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let expected_fingerprint =
            yasc_domain::HostKeyFingerprint::sha256(&server_key.public_key().to_bytes().unwrap());
        let (address, shutdown, task, authentication_attempts) =
            start_server(server_key, None).await;
        let target = format!("127.0.0.1:{}", address.port())
            .parse::<SshTarget>()
            .unwrap();
        let mut history = HostKeyHistory::new(HostId::new());
        let engine = NativeSshEngine::new(Duration::from_secs(5));

        let first = engine
            .probe_host_key(&target, &history, &HostKeyPolicy::ask_on_first_use())
            .await
            .unwrap();
        assert_eq!(first.observation.material.fingerprint, expected_fingerprint);
        assert_eq!(first.decision, HostKeyDecision::ConfirmFirstUse);

        history.trust_first_use(first.observation, 10).unwrap();
        let known = engine
            .probe_host_key(&target, &history, &HostKeyPolicy::strict())
            .await
            .unwrap();
        assert!(matches!(
            known.decision,
            HostKeyDecision::AcceptKnown { .. }
        ));
        assert_eq!(authentication_attempts.load(Ordering::SeqCst), 0);

        shutdown.shutdown("test complete".to_owned());
        task.await.unwrap().unwrap();

        let changed_key =
            PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let (changed_address, changed_shutdown, changed_task, changed_authentication_attempts) =
            start_server(changed_key, None).await;
        let changed_target = format!("127.0.0.1:{}", changed_address.port())
            .parse::<SshTarget>()
            .unwrap();
        let changed = engine
            .probe_host_key(&changed_target, &history, &HostKeyPolicy::strict())
            .await
            .unwrap();
        assert!(matches!(
            changed.decision,
            HostKeyDecision::RejectChanged { .. }
        ));
        assert_eq!(changed_authentication_attempts.load(Ordering::SeqCst), 0);
        changed_shutdown.shutdown("test complete".to_owned());
        changed_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn authenticated_command_uses_verified_key_and_bounds_output() {
        let server_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let encoded_client_key = client_key.to_openssh(LineEnding::LF).unwrap();
        let (address, shutdown, task, authentication_attempts) =
            start_server(server_key.clone(), Some(client_key.public_key().clone())).await;
        let target = format!("127.0.0.1:{}", address.port())
            .parse::<SshTarget>()
            .unwrap();
        let mut history = HostKeyHistory::new(HostId::new());
        let server_material = HostKeyMaterial::new(
            HostKeyAlgorithm::new(server_key.public_key().algorithm().to_string()).unwrap(),
            server_key.public_key().to_bytes().unwrap(),
        )
        .unwrap();
        history
            .trust_first_use(HostKeyObservation::presented(server_material), 10)
            .unwrap();
        let request = NativeCommandRequest::new(
            target.clone(),
            "fixture-user",
            SecretBytes::new(encoded_client_key.as_bytes().to_vec()),
            b"fixture-command".to_vec(),
        )
        .unwrap();
        let engine = NativeSshEngine::new(Duration::from_secs(5));

        let output = engine
            .execute_command(request, &history, &HostKeyPolicy::strict())
            .await
            .unwrap();
        assert_eq!(output.stdout(), b"fixture stdout\n");
        assert_eq!(output.stderr(), b"fixture stderr\n");
        assert_eq!(output.exit_status(), 7);
        assert!(matches!(
            output.host_key_decision(),
            HostKeyDecision::AcceptKnown { .. }
        ));

        let bounded = NativeCommandRequest::new(
            target,
            "fixture-user",
            SecretBytes::new(encoded_client_key.as_bytes().to_vec()),
            b"fixture-command".to_vec(),
        )
        .unwrap()
        .with_max_output_bytes(4)
        .unwrap();
        assert!(matches!(
            engine
                .execute_command(bounded, &history, &HostKeyPolicy::strict())
                .await,
            Err(NativeSshError::OutputLimitExceeded { limit: 4 })
        ));

        let wrong_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let wrong_key = wrong_key.to_openssh(LineEnding::LF).unwrap();
        let rejected = NativeCommandRequest::new(
            format!("127.0.0.1:{}", address.port())
                .parse::<SshTarget>()
                .unwrap(),
            "fixture-user",
            SecretBytes::new(wrong_key.as_bytes().to_vec()),
            b"fixture-command".to_vec(),
        )
        .unwrap();
        assert!(matches!(
            engine
                .execute_command(rejected, &history, &HostKeyPolicy::strict())
                .await,
            Err(NativeSshError::AuthenticationRejected)
        ));
        assert_eq!(authentication_attempts.load(Ordering::SeqCst), 3);

        shutdown.shutdown("test complete".to_owned());
        task.await.unwrap().unwrap();
    }

    #[test]
    fn sftp_paths_and_limits_are_validated_before_network_io() {
        assert!(validate_remote_path("/srv/files", true).is_ok());
        assert!(validate_remote_path(".", true).is_ok());
        for path in ["", "/srv/file\0name", "/srv/file\nname", "/srv/", ".", ".."] {
            assert!(matches!(
                validate_remote_path(path, false),
                Err(NativeSshError::InvalidSftpPath)
            ));
        }
        for name in ["", "../escape", "nested/file", "line\nbreak"] {
            assert!(matches!(
                validate_remote_entry_name(name),
                Err(NativeSshError::InvalidSftpEntryName)
            ));
        }
        assert!(validate_remote_entry_name("safe file.txt").is_ok());
        assert!(temporary_upload_path("/srv/file.txt").starts_with("/srv/.yasc-upload-"));
        assert!(temporary_upload_path("/file.txt").starts_with("/.yasc-upload-"));
        assert!(temporary_upload_path("file.txt").starts_with(".yasc-upload-"));
    }

    #[tokio::test]
    async fn sftp_lists_bounds_download_and_publishes_new_files_without_overwrite() {
        let server_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let encoded_client_key = client_key.to_openssh(LineEnding::LF).unwrap();
        let fixture = Arc::new(tokio::sync::Mutex::new(SftpFixture {
            files: BTreeMap::from([
                ("/zeta.txt".to_owned(), b"unchanged".to_vec()),
                ("/large.bin".to_owned(), vec![7; 16]),
            ]),
            directories: vec!["/folder".to_owned()],
        }));
        let (address, shutdown, task, authentication_attempts) = start_server_with_fixtures(
            server_key.clone(),
            Some(client_key.public_key().clone()),
            None,
            Some(Arc::clone(&fixture)),
        )
        .await;
        let target = format!("127.0.0.1:{}", address.port())
            .parse::<SshTarget>()
            .unwrap();
        let mut history = HostKeyHistory::new(HostId::new());
        history
            .trust_first_use(
                HostKeyObservation::presented(
                    HostKeyMaterial::new(
                        HostKeyAlgorithm::new(server_key.public_key().algorithm().to_string())
                            .unwrap(),
                        server_key.public_key().to_bytes().unwrap(),
                    )
                    .unwrap(),
                ),
                10,
            )
            .unwrap();
        let request = NativeSftpRequest::new(
            target.clone(),
            "fixture-user",
            SecretBytes::new(encoded_client_key.as_bytes().to_vec()),
        )
        .unwrap();
        let engine = NativeSshEngine::new(Duration::from_secs(5));
        let session = engine
            .connect_sftp(request, &history, &HostKeyPolicy::strict())
            .await
            .unwrap();

        let entries = session.list_directory("/", 10).await.unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["folder", "large.bin", "zeta.txt"]
        );
        assert_eq!(entries[0].kind, SftpEntryKind::Directory);
        assert_eq!(entries[1].size, Some(16));
        assert!(matches!(
            session.list_directory("/", 2).await,
            Err(NativeSshError::SftpEntryLimitExceeded { limit: 2 })
        ));
        assert_eq!(
            session.download("/zeta.txt", 32).await.unwrap(),
            b"unchanged"
        );
        assert!(matches!(
            session.download("/large.bin", 8).await,
            Err(NativeSshError::SftpByteLimitExceeded { limit: 8 })
        ));

        let uploaded = session
            .upload_new("/new.txt", b"new payload", 32)
            .await
            .unwrap();
        assert_eq!(uploaded.bytes_written, 11);
        assert!(matches!(
            session.upload_new("/zeta.txt", b"replacement", 32).await,
            Err(NativeSshError::SftpDestinationExists(path)) if path == "/zeta.txt"
        ));
        assert!(matches!(
            session.upload_new("/too-large", b"12345", 4).await,
            Err(NativeSshError::SftpByteLimitExceeded { limit: 4 })
        ));
        session.close().await.unwrap();

        let fixture = fixture.lock().await;
        assert_eq!(fixture.files.get("/new.txt").unwrap(), b"new payload");
        assert_eq!(fixture.files.get("/zeta.txt").unwrap(), b"unchanged");
        assert!(
            fixture
                .files
                .keys()
                .all(|path| !path.contains(".yasc-upload-"))
        );
        drop(fixture);
        assert_eq!(authentication_attempts.load(Ordering::SeqCst), 1);

        let rejected = NativeSftpRequest::new(
            target,
            "fixture-user",
            SecretBytes::new(encoded_client_key.as_bytes().to_vec()),
        )
        .unwrap();
        assert!(matches!(
            engine
                .connect_sftp(
                    rejected,
                    &HostKeyHistory::new(HostId::new()),
                    &HostKeyPolicy::strict(),
                )
                .await,
            Err(NativeSshError::HostKeyRejected(_))
        ));
        assert_eq!(authentication_attempts.load(Ordering::SeqCst), 1);

        shutdown.shutdown("test complete".to_owned());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn sftp_signs_with_agent_and_rejects_a_missing_identity_before_connecting() {
        let server_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let fixture = Arc::new(tokio::sync::Mutex::new(SftpFixture {
            files: BTreeMap::from([("/agent.txt".to_owned(), b"agent payload".to_vec())]),
            directories: Vec::new(),
        }));
        let (address, shutdown, task, authentication_attempts) = start_server_with_fixtures(
            server_key.clone(),
            Some(client_key.public_key().clone()),
            None,
            Some(fixture),
        )
        .await;
        let mut history = HostKeyHistory::new(HostId::new());
        history
            .trust_first_use(
                HostKeyObservation::presented(
                    HostKeyMaterial::new(
                        HostKeyAlgorithm::new(server_key.public_key().algorithm().to_string())
                            .unwrap(),
                        server_key.public_key().to_bytes().unwrap(),
                    )
                    .unwrap(),
                ),
                10,
            )
            .unwrap();
        let (agent_client_stream, agent_server_stream) = tokio::io::duplex(64 * 1024);
        let listener = futures::stream::iter([Ok::<_, std::io::Error>(agent_server_stream)]);
        tokio::spawn(async move {
            russh::keys::agent::server::serve(listener, ())
                .await
                .unwrap();
        });
        let mut agent = AgentClient::connect(agent_client_stream);
        agent.add_identity(&client_key, &[]).await.unwrap();
        let selected = list_agent_identities(&mut agent).await.unwrap()[0]
            .external_reference()
            .unwrap();
        let request = NativeAgentSftpRequest::new(
            format!("127.0.0.1:{}", address.port())
                .parse::<SshTarget>()
                .unwrap(),
            "fixture-user",
            selected,
        )
        .unwrap();
        let engine = NativeSshEngine::new(Duration::from_secs(5));
        let session = engine
            .connect_agent_sftp(request, &mut agent, &history, &HostKeyPolicy::strict())
            .await
            .unwrap();
        assert_eq!(
            session.download("/agent.txt", 32).await.unwrap(),
            b"agent payload"
        );
        session.close().await.unwrap();
        assert_eq!(authentication_attempts.load(Ordering::SeqCst), 1);

        let missing_key =
            PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let missing_reference = ExternalKeyReference::new(
            missing_key.public_key().algorithm().to_string(),
            missing_key.public_key().to_bytes().unwrap(),
            None,
        )
        .unwrap();
        let missing_request = NativeAgentSftpRequest::new(
            "127.0.0.1:1".parse::<SshTarget>().unwrap(),
            "fixture-user",
            missing_reference,
        )
        .unwrap();
        assert!(matches!(
            engine
                .connect_agent_sftp(
                    missing_request,
                    &mut agent,
                    &HostKeyHistory::new(HostId::new()),
                    &HostKeyPolicy::strict(),
                )
                .await,
            Err(NativeSshError::AgentIdentityNotFound)
        ));

        shutdown.shutdown("test complete".to_owned());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn authenticated_command_signs_with_agent_without_private_key_export() {
        let server_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let (address, shutdown, task, authentication_attempts) =
            start_server(server_key.clone(), Some(client_key.public_key().clone())).await;
        let target = format!("127.0.0.1:{}", address.port())
            .parse::<SshTarget>()
            .unwrap();
        let mut history = HostKeyHistory::new(HostId::new());
        history
            .trust_first_use(
                HostKeyObservation::presented(
                    HostKeyMaterial::new(
                        HostKeyAlgorithm::new(server_key.public_key().algorithm().to_string())
                            .unwrap(),
                        server_key.public_key().to_bytes().unwrap(),
                    )
                    .unwrap(),
                ),
                10,
            )
            .unwrap();

        let (agent_client_stream, agent_server_stream) = tokio::io::duplex(64 * 1024);
        let listener = futures::stream::iter([Ok::<_, std::io::Error>(agent_server_stream)]);
        tokio::spawn(async move {
            russh::keys::agent::server::serve(listener, ())
                .await
                .unwrap();
        });
        let mut agent = AgentClient::connect(agent_client_stream);
        agent.add_identity(&client_key, &[]).await.unwrap();
        let identities = list_agent_identities(&mut agent).await.unwrap();
        assert_eq!(identities.len(), 1);
        let external_key = identities[0].external_reference().unwrap();
        let request = NativeAgentCommandRequest::new(
            target,
            "fixture-user",
            external_key,
            b"fixture-command".to_vec(),
        )
        .unwrap();

        let output = NativeSshEngine::new(Duration::from_secs(2))
            .execute_agent_command(request, &mut agent, &history, &HostKeyPolicy::strict())
            .await
            .unwrap();
        assert_eq!(output.stdout(), b"fixture stdout\n");
        assert_eq!(output.stderr(), b"fixture stderr\n");
        assert_eq!(output.exit_status(), 7);
        assert_eq!(authentication_attempts.load(Ordering::SeqCst), 1);

        shutdown.shutdown("test complete".to_owned());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn agent_command_rejects_a_missing_selected_identity_before_connecting() {
        let available_key =
            PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let selected_key =
            PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let (agent_client_stream, agent_server_stream) = tokio::io::duplex(64 * 1024);
        let listener = futures::stream::iter([Ok::<_, std::io::Error>(agent_server_stream)]);
        tokio::spawn(async move {
            russh::keys::agent::server::serve(listener, ())
                .await
                .unwrap();
        });
        let mut agent = AgentClient::connect(agent_client_stream);
        agent.add_identity(&available_key, &[]).await.unwrap();
        let external_key = ExternalKeyReference::new(
            selected_key.public_key().algorithm().to_string(),
            selected_key.public_key().to_bytes().unwrap(),
            None,
        )
        .unwrap();
        let request = NativeAgentCommandRequest::new(
            "127.0.0.1:1".parse::<SshTarget>().unwrap(),
            "fixture-user",
            external_key,
            b"fixture-command".to_vec(),
        )
        .unwrap();

        assert!(matches!(
            NativeSshEngine::new(Duration::from_millis(100))
                .execute_agent_command(
                    request,
                    &mut agent,
                    &HostKeyHistory::new(HostId::new()),
                    &HostKeyPolicy::strict(),
                )
                .await,
            Err(NativeSshError::AgentIdentityNotFound)
        ));
    }

    #[tokio::test]
    async fn interactive_shell_signs_with_agent_without_private_key_export() {
        let server_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let shell = Arc::new(Mutex::new(ShellFixture::accepting()));
        let (address, shutdown, task, authentication_attempts) = start_server_with_shell(
            server_key.clone(),
            Some(client_key.public_key().clone()),
            Some(Arc::clone(&shell)),
        )
        .await;
        let target = format!("127.0.0.1:{}", address.port())
            .parse::<SshTarget>()
            .unwrap();
        let mut history = HostKeyHistory::new(HostId::new());
        history
            .trust_first_use(
                HostKeyObservation::presented(
                    HostKeyMaterial::new(
                        HostKeyAlgorithm::new(server_key.public_key().algorithm().to_string())
                            .unwrap(),
                        server_key.public_key().to_bytes().unwrap(),
                    )
                    .unwrap(),
                ),
                10,
            )
            .unwrap();
        let (agent_client_stream, agent_server_stream) = tokio::io::duplex(64 * 1024);
        let listener = futures::stream::iter([Ok::<_, std::io::Error>(agent_server_stream)]);
        tokio::spawn(async move {
            russh::keys::agent::server::serve(listener, ())
                .await
                .unwrap();
        });
        let mut agent = AgentClient::connect(agent_client_stream);
        agent.add_identity(&client_key, &[]).await.unwrap();
        let external_key = list_agent_identities(&mut agent).await.unwrap()[0]
            .external_reference()
            .unwrap();
        let size = TerminalSize::new(80, 24).unwrap();
        let request = NativeAgentShellRequest::new(target, "fixture-user", external_key, size)
            .unwrap()
            .with_terminal_type("xterm-256color")
            .unwrap();
        let (output_writer, mut output_reader) = tokio::io::duplex(1024);
        let (error_writer, mut error_reader) = tokio::io::duplex(1024);
        let (_, size_receiver) = watch::channel(size);

        let result = timeout(
            Duration::from_secs(5),
            NativeSshEngine::new(Duration::from_secs(2)).run_agent_shell(
                request,
                &mut agent,
                &history,
                &HostKeyPolicy::strict(),
                NativeShellIo::new(
                    tokio::io::empty(),
                    output_writer,
                    error_writer,
                    size_receiver,
                ),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let mut stdout = Vec::new();
        output_reader.read_to_end(&mut stdout).await.unwrap();
        let mut stderr = Vec::new();
        error_reader.read_to_end(&mut stderr).await.unwrap();

        assert_eq!(result.exit_status(), 0);
        assert_eq!(stdout, b"shell stdout\r\n");
        assert_eq!(stderr, b"shell stderr\r\n");
        assert_eq!(authentication_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            shell.lock().unwrap().pty,
            Some(("xterm-256color".to_owned(), 80, 24))
        );

        shutdown.shutdown("test complete".to_owned());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn interactive_shell_streams_pty_io_resize_and_exit_status() {
        let server_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let encoded_client_key = client_key.to_openssh(LineEnding::LF).unwrap();
        let shell = Arc::new(Mutex::new(ShellFixture::accepting()));
        let (address, shutdown, task, authentication_attempts) = start_server_with_shell(
            server_key.clone(),
            Some(client_key.public_key().clone()),
            Some(Arc::clone(&shell)),
        )
        .await;
        let target = format!("127.0.0.1:{}", address.port())
            .parse::<SshTarget>()
            .unwrap();
        let mut history = HostKeyHistory::new(HostId::new());
        let server_material = HostKeyMaterial::new(
            HostKeyAlgorithm::new(server_key.public_key().algorithm().to_string()).unwrap(),
            server_key.public_key().to_bytes().unwrap(),
        )
        .unwrap();
        history
            .trust_first_use(HostKeyObservation::presented(server_material), 10)
            .unwrap();
        let initial_size = TerminalSize::new(80, 24).unwrap();
        let request = NativeShellRequest::new(
            target,
            "fixture-user",
            SecretBytes::new(encoded_client_key.as_bytes().to_vec()),
            initial_size,
        )
        .unwrap()
        .with_terminal_type("xterm-256color")
        .unwrap();
        let (mut input_writer, input_reader) = tokio::io::duplex(1024);
        let (output_writer, mut output_reader) = tokio::io::duplex(1024);
        let (error_writer, mut error_reader) = tokio::io::duplex(1024);
        let (size_sender, size_receiver) = watch::channel(initial_size);
        let driver_shell = Arc::clone(&shell);
        let driver_task = tokio::spawn(async move {
            loop {
                if driver_shell.lock().unwrap().shell_requests == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
            size_sender
                .send(TerminalSize::new(100, 40).unwrap())
                .unwrap();
            loop {
                if driver_shell
                    .lock()
                    .unwrap()
                    .window_changes
                    .contains(&(100, 40))
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
            input_writer.write_all(b"fixture input").await.unwrap();
            input_writer.shutdown().await.unwrap();
        });

        let result = timeout(
            Duration::from_secs(5),
            NativeSshEngine::new(Duration::from_secs(2)).run_shell(
                request,
                &history,
                &HostKeyPolicy::strict(),
                NativeShellIo::new(input_reader, output_writer, error_writer, size_receiver),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        driver_task.await.unwrap();
        let mut stdout = Vec::new();
        output_reader.read_to_end(&mut stdout).await.unwrap();
        let mut stderr = Vec::new();
        error_reader.read_to_end(&mut stderr).await.unwrap();

        assert_eq!(result.exit_status(), 0);
        assert!(matches!(
            result.host_key_decision(),
            HostKeyDecision::AcceptKnown { .. }
        ));
        assert_eq!(stdout, b"shell stdout\r\n");
        assert_eq!(stderr, b"shell stderr\r\n");
        assert_eq!(authentication_attempts.load(Ordering::SeqCst), 1);
        {
            let shell = shell.lock().unwrap();
            assert_eq!(shell.pty, Some(("xterm-256color".to_owned(), 80, 24)));
            assert_eq!(shell.window_changes, vec![(100, 40)]);
            assert_eq!(shell.input, b"fixture input");
            assert_eq!(shell.shell_requests, 1);
        }

        shutdown.shutdown("test complete".to_owned());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn interactive_shell_reports_pty_rejection() {
        let server_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let encoded_client_key = client_key.to_openssh(LineEnding::LF).unwrap();
        let shell = Arc::new(Mutex::new(ShellFixture {
            accept_pty: false,
            ..ShellFixture::accepting()
        }));
        let (address, shutdown, task, _) = start_server_with_shell(
            server_key.clone(),
            Some(client_key.public_key().clone()),
            Some(shell),
        )
        .await;
        let target = format!("127.0.0.1:{}", address.port())
            .parse::<SshTarget>()
            .unwrap();
        let mut history = HostKeyHistory::new(HostId::new());
        history
            .trust_first_use(
                HostKeyObservation::presented(
                    HostKeyMaterial::new(
                        HostKeyAlgorithm::new(server_key.public_key().algorithm().to_string())
                            .unwrap(),
                        server_key.public_key().to_bytes().unwrap(),
                    )
                    .unwrap(),
                ),
                10,
            )
            .unwrap();
        let size = TerminalSize::new(80, 24).unwrap();
        let request = NativeShellRequest::new(
            target,
            "fixture-user",
            SecretBytes::new(encoded_client_key.as_bytes().to_vec()),
            size,
        )
        .unwrap();
        let (_, size_receiver) = watch::channel(size);

        assert!(matches!(
            NativeSshEngine::new(Duration::from_secs(2))
                .run_shell(
                    request,
                    &history,
                    &HostKeyPolicy::strict(),
                    NativeShellIo::new(
                        tokio::io::empty(),
                        tokio::io::sink(),
                        tokio::io::sink(),
                        size_receiver,
                    ),
                )
                .await,
            Err(NativeSshError::PtyRequestRejected)
        ));

        shutdown.shutdown("test complete".to_owned());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn interactive_shell_rejects_unknown_host_before_authentication() {
        let server_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let encoded_client_key = client_key.to_openssh(LineEnding::LF).unwrap();
        let shell = Arc::new(Mutex::new(ShellFixture::accepting()));
        let (address, shutdown, task, authentication_attempts) = start_server_with_shell(
            server_key,
            Some(client_key.public_key().clone()),
            Some(shell),
        )
        .await;
        let target = format!("127.0.0.1:{}", address.port())
            .parse::<SshTarget>()
            .unwrap();
        let history = HostKeyHistory::new(HostId::new());
        let size = TerminalSize::new(80, 24).unwrap();
        let request = NativeShellRequest::new(
            target,
            "fixture-user",
            SecretBytes::new(encoded_client_key.as_bytes().to_vec()),
            size,
        )
        .unwrap();
        let (_, size_receiver) = watch::channel(size);

        assert!(matches!(
            NativeSshEngine::new(Duration::from_secs(2))
                .run_shell(
                    request,
                    &history,
                    &HostKeyPolicy::strict(),
                    NativeShellIo::new(
                        tokio::io::empty(),
                        tokio::io::sink(),
                        tokio::io::sink(),
                        size_receiver,
                    ),
                )
                .await,
            Err(NativeSshError::HostKeyRejected(
                HostKeyDecision::RejectUnknownStrict
            ))
        ));
        assert_eq!(authentication_attempts.load(Ordering::SeqCst), 0);

        shutdown.shutdown("test complete".to_owned());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connection_failure_is_not_misreported_as_missing_host_key() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let client_key = client_key.to_openssh(LineEnding::LF).unwrap();
        let request = NativeCommandRequest::new(
            format!("127.0.0.1:{}", address.port())
                .parse::<SshTarget>()
                .unwrap(),
            "fixture-user",
            SecretBytes::new(client_key.as_bytes().to_vec()),
            b"fixture-command".to_vec(),
        )
        .unwrap();
        let history = HostKeyHistory::new(HostId::new());

        let error = NativeSshEngine::new(Duration::from_secs(2))
            .execute_command(request, &history, &HostKeyPolicy::strict())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            NativeSshError::Transport(_) | NativeSshError::HandshakeTimeout
        ));
    }
}
