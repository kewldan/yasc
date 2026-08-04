use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::{Disconnect, client, keys::ssh_key};
use serde::Serialize;
use thiserror::Error;
use tokio::time::timeout;
use yasc_domain::{
    HostKeyAlgorithm, HostKeyDecision, HostKeyError, HostKeyHistory, HostKeyMaterial,
    HostKeyObservation, HostKeyPolicy, SshTarget,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeHostKeyProbe {
    pub observation: HostKeyObservation,
    pub decision: HostKeyDecision,
}

#[derive(Debug, Clone)]
pub struct NativeSshEngine {
    handshake_timeout: Duration,
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
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use russh::{keys::PrivateKey, server, server::Server as _};
    use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
    use yasc_domain::{HostId, HostKeyDecision, HostKeyHistory, HostKeyPolicy};

    use super::*;

    #[derive(Clone)]
    struct TestServer;

    impl server::Server for TestServer {
        type Handler = Self;

        fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for TestServer {
        type Error = russh::Error;
    }

    async fn start_server(
        key: PrivateKey,
    ) -> (
        SocketAddr,
        russh::server::RunningServerHandle,
        JoinHandle<std::io::Result<()>>,
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
        let task = tokio::spawn(async move {
            let mut server = TestServer;
            let running = server.run_on_socket(config, &listener);
            assert!(handle_sender.send(running.handle()).is_ok());
            running.await
        });
        let shutdown = handle_receiver.await.unwrap();
        (address, shutdown, task)
    }

    #[tokio::test]
    async fn real_handshake_is_rejected_then_accepted_by_persistent_policy() {
        let server_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let expected_fingerprint =
            yasc_domain::HostKeyFingerprint::sha256(&server_key.public_key().to_bytes().unwrap());
        let (address, shutdown, task) = start_server(server_key).await;
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

        shutdown.shutdown("test complete".to_owned());
        task.await.unwrap().unwrap();

        let changed_key =
            PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let (changed_address, changed_shutdown, changed_task) = start_server(changed_key).await;
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
        changed_shutdown.shutdown("test complete".to_owned());
        changed_task.await.unwrap().unwrap();
    }
}
