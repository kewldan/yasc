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
use tokio::time::timeout;
use yasc_domain::{
    HostKeyAlgorithm, HostKeyDecision, HostKeyError, HostKeyHistory, HostKeyMaterial,
    HostKeyObservation, HostKeyPolicy, SshTarget,
};
use yasc_vault::SecretBytes;

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
        if username.trim().is_empty() || username.chars().any(char::is_control) {
            return Err(NativeSshError::InvalidUsername);
        }
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
        let private_key_text = std::str::from_utf8(request.private_key.expose_secret())
            .map_err(|_| NativeSshError::PrivateKeyNotUtf8)?;
        let passphrase = request
            .private_key_passphrase
            .as_ref()
            .map(|value| {
                std::str::from_utf8(value.expose_secret())
                    .map_err(|_| NativeSshError::PassphraseNotUtf8)
            })
            .transpose()?;
        let private_key = russh::keys::decode_secret_key(private_key_text, passphrase)?;
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
            };
            let running = server.run_on_socket(config, &listener);
            assert!(handle_sender.send(running.handle()).is_ok());
            running.await
        });
        let shutdown = handle_receiver.await.unwrap();
        (address, shutdown, task, authentication_attempts)
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

        assert!(matches!(
            NativeSshEngine::new(Duration::from_secs(2))
                .execute_command(request, &history, &HostKeyPolicy::strict())
                .await,
            Err(NativeSshError::Transport(_))
        ));
    }
}
