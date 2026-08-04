use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::{
    ChannelMsg, Disconnect, client,
    keys::{PrivateKeyWithHashAlg, ssh_key},
};
use serde::Serialize;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    time::timeout,
};
use yasc_domain::{
    HostKeyAlgorithm, HostKeyDecision, HostKeyError, HostKeyHistory, HostKeyMaterial,
    HostKeyObservation, HostKeyPolicy, SshTarget,
};
use yasc_vault::SecretBytes;

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
        let terminal_type = terminal_type.into();
        if terminal_type.is_empty()
            || terminal_type.len() > 64
            || !terminal_type
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(NativeSshError::InvalidTerminalType);
        }
        self.terminal_type = terminal_type;
        Ok(self)
    }
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
        let NativeShellIo {
            mut input,
            mut output,
            mut error_output,
            mut size_changes,
        } = io;
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

        let mut channel = handle.channel_open_session().await?;
        let size = request.initial_size;
        channel
            .request_pty(
                true,
                &request.terminal_type,
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
    #[error("presented SSH host key could not be encoded: {0}")]
    KeyEncoding(#[from] ssh_key::Error),
    #[error("SSH private key could not be decoded: {0}")]
    PrivateKey(#[from] russh::keys::Error),
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
    #[error("SSH private key must use a supported UTF-8 text format")]
    PrivateKeyNotUtf8,
    #[error("SSH private-key passphrase must be UTF-8")]
    PassphraseNotUtf8,
    #[error("host-key verification rejected the native session: {0:?}")]
    HostKeyRejected(HostKeyDecision),
    #[error("SSH public-key authentication was rejected")]
    AuthenticationRejected,
    #[error("remote command request was rejected")]
    CommandRequestRejected,
    #[error("remote server rejected the PTY request")]
    PtyRequestRejected,
    #[error("remote server rejected the interactive shell request")]
    ShellRequestRejected,
    #[error("remote shell returned unsupported extended data type {0}")]
    UnsupportedExtendedData(u32),
    #[error("remote command exceeded its timeout")]
    CommandTimeout,
    #[error("remote command output exceeded the {limit}-byte limit")]
    OutputLimitExceeded { limit: usize },
    #[error("remote command ended without an exit status")]
    MissingExitStatus,
    #[error("remote command ended from signal {0}")]
    RemoteCommandSignaled(String),
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use russh::{
        Channel, ChannelId,
        keys::{PrivateKey, ssh_key::LineEnding},
        server,
        server::{Auth, ChannelOpenHandle, Server as _, Session},
    };
    use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
    use yasc_domain::{HostId, HostKeyDecision, HostKeyHistory, HostKeyPolicy};

    use super::*;

    #[derive(Clone)]
    struct TestServer {
        authorized_key: Option<ssh_key::PublicKey>,
        authentication_attempts: Arc<AtomicUsize>,
        shell: Option<Arc<Mutex<ShellFixture>>>,
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
            _: Channel<server::Msg>,
            reply: ChannelOpenHandle,
            _: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
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
