#![forbid(unsafe_code)]

use std::{
    collections::{BTreeSet, HashMap},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tauri::{Manager as _, ipc::Channel};
use thiserror::Error;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt, DuplexStream},
    sync::{Mutex as AsyncMutex, watch},
};
use uuid::Uuid;
use yasc_domain::{
    Credential, CredentialCapabilities, CredentialGrant, CredentialId, CredentialProviderKind,
    CredentialUsage, Custody, ExternalKeyReference, Host, HostId, HostKeyDecision, HostKeyPolicy,
    Synchronization,
};
use yasc_platform::{PlatformError, PlatformPaths};
use yasc_ssh::{
    LocalForwardSpec, NativeAgentLocalForwardRequest, NativeAgentSftpRequest,
    NativeAgentShellRequest, NativeHostKeyProbe, NativeLocalForwardSession,
    NativeLocalForwardSnapshot, NativeSftpSession, NativeShellIo, NativeSshEngine, NativeSshError,
    SftpEntry, SftpUploadResult, TerminalSize, connect_agent, external_key_fingerprint,
    list_agent_identities as query_agent_identities,
};
use yasc_storage::{PersistedCredential, SqliteStorage, StorageError};

struct DesktopState {
    database: Mutex<SqliteStorage>,
    sessions: Arc<AsyncMutex<HashMap<String, SessionControl>>>,
    local_forwards: Arc<AsyncMutex<HashMap<String, LocalForwardControl>>>,
}

#[derive(Clone)]
struct SessionControl {
    input: Arc<AsyncMutex<DuplexStream>>,
    size: watch::Sender<TerminalSize>,
}

struct LocalForwardControl {
    host_id: HostId,
    credential_id: CredentialId,
    session: NativeLocalForwardSession,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalForwardSummary {
    id: String,
    host_id: HostId,
    credential_id: CredentialId,
    local_address: String,
    remote_host: String,
    remote_port: u16,
    host_key_status: String,
    accepted_connections: u64,
    active_connections: usize,
    bytes_from_local: u64,
    bytes_to_local: u64,
    failed_connections: u64,
    running: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialSummary {
    id: CredentialId,
    label: String,
    provider: &'static str,
    host_ids: Vec<HostId>,
    external_key_fingerprint: Option<String>,
    usable_for_native_agent: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentIdentitySummary {
    algorithm: String,
    comment: String,
    fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HostKeyProbeSummary {
    fingerprint: String,
    algorithm: String,
    decision: String,
    accepted: bool,
    can_trust_first_use: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TerminalEvent {
    Data {
        stream: TerminalStream,
        data: Vec<u8>,
    },
    Exit {
        status: u32,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum TerminalStream {
    Stdout,
    Stderr,
}

#[derive(Clone)]
struct ChannelWriter {
    channel: Arc<Channel<TerminalEvent>>,
    stream: TerminalStream,
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.channel
            .send(TerminalEvent::Data {
                stream: self.stream,
                data: buffer.to_vec(),
            })
            .map_err(|error| io::Error::other(error.to_string()))?;
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Error)]
enum DesktopError {
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Host(#[from] yasc_domain::HostError),
    #[error(transparent)]
    HostKey(#[from] yasc_domain::HostKeyError),
    #[error(transparent)]
    Target(#[from] yasc_domain::TargetParseError),
    #[error(transparent)]
    NativeSsh(#[from] NativeSshError),
    #[error(transparent)]
    CredentialCapability(#[from] yasc_domain::CredentialCapabilityError),
    #[error(transparent)]
    CredentialGrant(#[from] yasc_domain::CredentialGrantError),
    #[error("local application state is unavailable")]
    StateUnavailable,
    #[error("host {0} was not found")]
    HostNotFound(HostId),
    #[error("credential {0} was not found")]
    CredentialNotFound(CredentialId),
    #[error("credential {credential_id} does not authorize direct SSH to host {host_id}")]
    CredentialUnauthorized {
        credential_id: CredentialId,
        host_id: HostId,
    },
    #[error("credential {0} has no external public-key reference")]
    MissingExternalKey(CredentialId),
    #[error("credential provider {0:?} is not supported by the Desktop MVP")]
    UnsupportedProvider(CredentialProviderKind),
    #[error("unknown external-agent provider {0}")]
    UnknownProvider(String),
    #[error("no agent identity has fingerprint {0}")]
    AgentFingerprintNotFound(String),
    #[error("inventory target must include an SSH username")]
    UsernameRequired,
    #[error("host key cannot be trusted from decision {0}")]
    HostKeyNotTrustable(String),
    #[error("session {0} was not found")]
    SessionNotFound(String),
    #[error("local forward {0} was not found")]
    LocalForwardNotFound(String),
    #[error("terminal input chunk exceeds 65536 bytes")]
    InputTooLarge,
    #[error("SFTP upload chunk exceeds 10485760 bytes")]
    SftpUploadTooLarge,
    #[error("system clock is outside the supported range")]
    InvalidClock,
    #[error("terminal I/O failed: {0}")]
    TerminalIo(#[from] io::Error),
}

impl Serialize for DesktopError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

fn database(state: &DesktopState) -> Result<MutexGuard<'_, SqliteStorage>, DesktopError> {
    state
        .database
        .lock()
        .map_err(|_| DesktopError::StateUnavailable)
}

fn unix_now() -> Result<i64, DesktopError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DesktopError::InvalidClock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| DesktopError::InvalidClock)
}

fn provider_name(provider: CredentialProviderKind) -> &'static str {
    match provider {
        CredentialProviderKind::LocalVault => "local_vault",
        CredentialProviderKind::NativeKeystore => "native_keystore",
        CredentialProviderKind::OpenSshAgent => "open_ssh_agent",
        CredentialProviderKind::Pageant => "pageant",
        CredentialProviderKind::Pkcs11 => "pkcs11",
        CredentialProviderKind::Fido => "fido",
        CredentialProviderKind::ExternalPasswordManager => "external_password_manager",
        CredentialProviderKind::ServerDelegation => "server_delegation",
    }
}

fn parse_agent_provider(value: &str) -> Result<CredentialProviderKind, DesktopError> {
    match value {
        "openssh" => Ok(CredentialProviderKind::OpenSshAgent),
        "pageant" => Ok(CredentialProviderKind::Pageant),
        _ => Err(DesktopError::UnknownProvider(value.to_owned())),
    }
}

fn summarize_credential(
    persisted: &PersistedCredential,
) -> Result<CredentialSummary, DesktopError> {
    let host_ids = persisted
        .grants
        .iter()
        .flat_map(|grant| grant.host_ids.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let external_key_fingerprint = persisted
        .credential
        .external_key
        .as_ref()
        .map(external_key_fingerprint)
        .transpose()?;
    Ok(CredentialSummary {
        id: persisted.credential.id,
        label: persisted.credential.label.clone(),
        provider: provider_name(persisted.credential.provider),
        host_ids,
        external_key_fingerprint,
        usable_for_native_agent: matches!(
            persisted.credential.provider,
            CredentialProviderKind::OpenSshAgent | CredentialProviderKind::Pageant
        ) && persisted
            .credential
            .capabilities
            .allows(CredentialUsage::DirectSsh),
    })
}

fn summarize_probe(probe: &NativeHostKeyProbe) -> HostKeyProbeSummary {
    let decision = match &probe.decision {
        HostKeyDecision::AcceptKnown { .. } => "accept_known",
        HostKeyDecision::AcceptCertificate { .. } => "accept_certificate",
        HostKeyDecision::AcceptAuthenticatedUpdate { .. } => "accept_authenticated_update",
        HostKeyDecision::ConfirmFirstUse => "confirm_first_use",
        HostKeyDecision::RejectUnknownStrict => "reject_unknown_strict",
        HostKeyDecision::RejectChanged { .. } => "reject_changed",
        HostKeyDecision::RejectRevoked => "reject_revoked",
        HostKeyDecision::RejectUntrustedCertificate => "reject_untrusted_certificate",
    };
    HostKeyProbeSummary {
        fingerprint: probe.observation.material.fingerprint.to_string(),
        algorithm: probe.observation.material.algorithm.to_string(),
        decision: decision.to_owned(),
        accepted: probe.decision.is_accepted(),
        can_trust_first_use: probe.decision == HostKeyDecision::ConfirmFirstUse,
    }
}

fn summarize_local_forward(
    id: &str,
    host_id: HostId,
    credential_id: CredentialId,
    snapshot: NativeLocalForwardSnapshot,
) -> LocalForwardSummary {
    LocalForwardSummary {
        id: id.to_owned(),
        host_id,
        credential_id,
        local_address: snapshot.local_address.to_string(),
        remote_host: snapshot.remote_host,
        remote_port: snapshot.remote_port,
        host_key_status: format!("{:?}", snapshot.host_key_decision),
        accepted_connections: snapshot.accepted_connections,
        active_connections: snapshot.active_connections,
        bytes_from_local: snapshot.bytes_from_local,
        bytes_to_local: snapshot.bytes_to_local,
        failed_connections: snapshot.failed_connections,
        running: snapshot.running,
    }
}

#[tauri::command]
fn list_hosts(state: tauri::State<'_, DesktopState>) -> Result<Vec<Host>, DesktopError> {
    Ok(database(&state)?.list_hosts()?)
}

#[tauri::command]
fn add_host(
    state: tauri::State<'_, DesktopState>,
    label: String,
    target: String,
    environment: Option<String>,
) -> Result<Host, DesktopError> {
    let mut host = Host::new(label, target.parse()?)?;
    host.environment = environment;
    database(&state)?.save_host(&host)?;
    Ok(host)
}

#[tauri::command]
fn list_credentials(
    state: tauri::State<'_, DesktopState>,
) -> Result<Vec<CredentialSummary>, DesktopError> {
    database(&state)?
        .list_credentials()?
        .iter()
        .map(summarize_credential)
        .collect()
}

#[tauri::command]
async fn list_agent_identities(
    provider: String,
) -> Result<Vec<AgentIdentitySummary>, DesktopError> {
    let mut agent = connect_agent(parse_agent_provider(&provider)?).await?;
    Ok(query_agent_identities(&mut agent)
        .await?
        .into_iter()
        .map(|identity| AgentIdentitySummary {
            algorithm: identity.algorithm,
            comment: identity.comment,
            fingerprint: identity.fingerprint,
        })
        .collect())
}

#[tauri::command]
async fn import_agent_credential(
    state: tauri::State<'_, DesktopState>,
    label: String,
    fingerprint: String,
    host_id: HostId,
    provider: String,
) -> Result<CredentialSummary, DesktopError> {
    if database(&state)?.find_host(host_id)?.is_none() {
        return Err(DesktopError::HostNotFound(host_id));
    }
    let provider = parse_agent_provider(&provider)?;
    let mut agent = connect_agent(provider).await?;
    let identity = query_agent_identities(&mut agent)
        .await?
        .into_iter()
        .find(|identity| identity.fingerprint == fingerprint)
        .ok_or_else(|| DesktopError::AgentFingerprintNotFound(fingerprint.clone()))?;
    let capabilities = CredentialCapabilities::new(
        Custody::ExternalProvider,
        Synchronization::LocalOnly,
        [CredentialUsage::DirectSsh],
    )?;
    let credential = Credential::new_external_key(
        label,
        provider,
        capabilities,
        identity.external_reference()?,
    )?;
    let grant = CredentialGrant::new(credential.id, [host_id], [CredentialUsage::DirectSsh])?;
    let persisted = PersistedCredential {
        credential,
        secret_refs: Vec::new(),
        grants: vec![grant],
    };
    database(&state)?.save_credential(
        &persisted.credential,
        &persisted.secret_refs,
        &persisted.grants,
    )?;
    summarize_credential(&persisted)
}

#[tauri::command]
async fn probe_host_key(
    state: tauri::State<'_, DesktopState>,
    host_id: HostId,
) -> Result<HostKeyProbeSummary, DesktopError> {
    let (host, history) = {
        let storage = database(&state)?;
        let host = storage
            .find_host(host_id)?
            .ok_or(DesktopError::HostNotFound(host_id))?;
        let history = storage.load_host_key_history(host_id)?;
        (host, history)
    };
    let probe = NativeSshEngine::default()
        .probe_host_key(&host.target, &history, &HostKeyPolicy::ask_on_first_use())
        .await?;
    Ok(summarize_probe(&probe))
}

#[tauri::command]
async fn trust_host_key(
    state: tauri::State<'_, DesktopState>,
    host_id: HostId,
) -> Result<HostKeyProbeSummary, DesktopError> {
    let (host, history) = {
        let storage = database(&state)?;
        let host = storage
            .find_host(host_id)?
            .ok_or(DesktopError::HostNotFound(host_id))?;
        let history = storage.load_host_key_history(host_id)?;
        (host, history)
    };
    let probe = NativeSshEngine::default()
        .probe_host_key(&host.target, &history, &HostKeyPolicy::ask_on_first_use())
        .await?;
    if probe.decision.is_accepted() {
        return Ok(summarize_probe(&probe));
    }
    if probe.decision != HostKeyDecision::ConfirmFirstUse {
        return Err(DesktopError::HostKeyNotTrustable(
            summarize_probe(&probe).decision,
        ));
    }
    let mut storage = database(&state)?;
    let mut latest = storage.load_host_key_history(host_id)?;
    let event = latest.trust_first_use(probe.observation.clone(), unix_now()?)?;
    storage.save_host_key_change(&latest, &event)?;
    Ok(HostKeyProbeSummary {
        accepted: true,
        can_trust_first_use: false,
        decision: "trusted_first_use".to_owned(),
        fingerprint: probe.observation.material.fingerprint.to_string(),
        algorithm: probe.observation.material.algorithm.to_string(),
    })
}

fn resolve_agent_session(
    storage: &SqliteStorage,
    host_id: HostId,
    credential_id: CredentialId,
) -> Result<
    (
        Host,
        yasc_domain::HostKeyHistory,
        CredentialProviderKind,
        ExternalKeyReference,
    ),
    DesktopError,
> {
    let host = storage
        .find_host(host_id)?
        .ok_or(DesktopError::HostNotFound(host_id))?;
    let history = storage.load_host_key_history(host_id)?;
    let persisted = storage
        .find_credential(credential_id)?
        .ok_or(DesktopError::CredentialNotFound(credential_id))?;
    let now = unix_now()?;
    if !persisted
        .credential
        .capabilities
        .allows(CredentialUsage::DirectSsh)
        || !persisted
            .grants
            .iter()
            .any(|grant| grant.authorizes(host_id, CredentialUsage::DirectSsh, now))
    {
        return Err(DesktopError::CredentialUnauthorized {
            credential_id,
            host_id,
        });
    }
    let provider = persisted.credential.provider;
    if !matches!(
        provider,
        CredentialProviderKind::OpenSshAgent | CredentialProviderKind::Pageant
    ) {
        return Err(DesktopError::UnsupportedProvider(provider));
    }
    let external_key = persisted
        .credential
        .external_key
        .ok_or(DesktopError::MissingExternalKey(credential_id))?;
    Ok((host, history, provider, external_key))
}

async fn connect_agent_sftp(
    state: &DesktopState,
    host_id: HostId,
    credential_id: CredentialId,
) -> Result<NativeSftpSession, DesktopError> {
    let (host, history, provider, external_key) = {
        let storage = database(state)?;
        resolve_agent_session(&storage, host_id, credential_id)?
    };
    let username = host
        .target
        .username()
        .ok_or(DesktopError::UsernameRequired)?
        .to_owned();
    let request = NativeAgentSftpRequest::new(host.target, username, external_key)?;
    let mut agent = connect_agent(provider).await?;
    Ok(NativeSshEngine::default()
        .connect_agent_sftp(request, &mut agent, &history, &HostKeyPolicy::strict())
        .await?)
}

#[tauri::command]
async fn list_sftp_directory(
    state: tauri::State<'_, DesktopState>,
    host_id: HostId,
    credential_id: CredentialId,
    remote_path: String,
    max_entries: usize,
) -> Result<Vec<SftpEntry>, DesktopError> {
    let session = connect_agent_sftp(&state, host_id, credential_id).await?;
    let entries = session.list_directory(&remote_path, max_entries).await?;
    session.close().await?;
    Ok(entries)
}

#[tauri::command]
async fn read_sftp_file(
    state: tauri::State<'_, DesktopState>,
    host_id: HostId,
    credential_id: CredentialId,
    remote_path: String,
    max_bytes: usize,
) -> Result<Vec<u8>, DesktopError> {
    let session = connect_agent_sftp(&state, host_id, credential_id).await?;
    let contents = session.download(&remote_path, max_bytes).await?;
    session.close().await?;
    Ok(contents)
}

#[tauri::command]
async fn upload_sftp_file(
    state: tauri::State<'_, DesktopState>,
    host_id: HostId,
    credential_id: CredentialId,
    remote_path: String,
    contents: Vec<u8>,
) -> Result<SftpUploadResult, DesktopError> {
    if contents.len() > 10 * 1024 * 1024 {
        return Err(DesktopError::SftpUploadTooLarge);
    }
    let session = connect_agent_sftp(&state, host_id, credential_id).await?;
    let result = session
        .upload_new(&remote_path, &contents, 10 * 1024 * 1024)
        .await?;
    session.close().await?;
    Ok(result)
}

#[tauri::command]
async fn list_local_forwards(
    state: tauri::State<'_, DesktopState>,
) -> Result<Vec<LocalForwardSummary>, DesktopError> {
    let forwards = state.local_forwards.lock().await;
    let mut summaries = forwards
        .iter()
        .map(|(id, control)| {
            summarize_local_forward(
                id,
                control.host_id,
                control.credential_id,
                control.session.snapshot(),
            )
        })
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(summaries)
}

#[tauri::command]
async fn start_local_forward(
    state: tauri::State<'_, DesktopState>,
    host_id: HostId,
    credential_id: CredentialId,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
) -> Result<LocalForwardSummary, DesktopError> {
    let (host, history, provider, external_key) = {
        let storage = database(&state)?;
        resolve_agent_session(&storage, host_id, credential_id)?
    };
    let username = host
        .target
        .username()
        .ok_or(DesktopError::UsernameRequired)?
        .to_owned();
    let spec = LocalForwardSpec::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port),
        remote_host,
        remote_port,
    )?;
    let request = NativeAgentLocalForwardRequest::new(host.target, username, external_key, spec)?;
    let mut agent = connect_agent(provider).await?;
    let session = NativeSshEngine::default()
        .start_agent_local_forward(request, &mut agent, &history, &HostKeyPolicy::strict())
        .await?;
    let id = Uuid::new_v4().to_string();
    let summary = summarize_local_forward(&id, host_id, credential_id, session.snapshot());
    state.local_forwards.lock().await.insert(
        id,
        LocalForwardControl {
            host_id,
            credential_id,
            session,
        },
    );
    Ok(summary)
}

#[tauri::command]
async fn stop_local_forward(
    state: tauri::State<'_, DesktopState>,
    forward_id: String,
) -> Result<LocalForwardSummary, DesktopError> {
    let control = state
        .local_forwards
        .lock()
        .await
        .remove(&forward_id)
        .ok_or_else(|| DesktopError::LocalForwardNotFound(forward_id.clone()))?;
    let snapshot = control.session.shutdown().await?;
    Ok(summarize_local_forward(
        &forward_id,
        control.host_id,
        control.credential_id,
        snapshot,
    ))
}

#[tauri::command]
async fn start_agent_session(
    state: tauri::State<'_, DesktopState>,
    host_id: HostId,
    credential_id: CredentialId,
    columns: u32,
    rows: u32,
    terminal_type: String,
    on_event: Channel<TerminalEvent>,
) -> Result<String, DesktopError> {
    let (host, history, provider, external_key) = {
        let storage = database(&state)?;
        resolve_agent_session(&storage, host_id, credential_id)?
    };
    let username = host
        .target
        .username()
        .ok_or(DesktopError::UsernameRequired)?
        .to_owned();
    let size = TerminalSize::new(columns, rows)?;
    let request = NativeAgentShellRequest::new(host.target, username, external_key, size)?
        .with_terminal_type(terminal_type)?;
    let mut agent = connect_agent(provider).await?;
    let (input_writer, input_reader) = tokio::io::duplex(64 * 1024);
    let (size_sender, size_receiver) = watch::channel(size);
    let session_id = Uuid::new_v4().to_string();
    state.sessions.lock().await.insert(
        session_id.clone(),
        SessionControl {
            input: Arc::new(AsyncMutex::new(input_writer)),
            size: size_sender,
        },
    );
    let sessions = Arc::clone(&state.sessions);
    let task_session_id = session_id.clone();
    let channel = Arc::new(on_event);
    let stdout = ChannelWriter {
        channel: Arc::clone(&channel),
        stream: TerminalStream::Stdout,
    };
    let stderr = ChannelWriter {
        channel: Arc::clone(&channel),
        stream: TerminalStream::Stderr,
    };
    tauri::async_runtime::spawn(async move {
        let result = NativeSshEngine::default()
            .run_agent_shell(
                request,
                &mut agent,
                &history,
                &HostKeyPolicy::strict(),
                NativeShellIo::new(input_reader, stdout, stderr, size_receiver),
            )
            .await;
        match result {
            Ok(output) => {
                let _ = channel.send(TerminalEvent::Exit {
                    status: output.exit_status(),
                });
            }
            Err(error) => {
                let _ = channel.send(TerminalEvent::Error {
                    message: error.to_string(),
                });
            }
        }
        sessions.lock().await.remove(&task_session_id);
    });
    Ok(session_id)
}

#[tauri::command]
async fn write_session(
    state: tauri::State<'_, DesktopState>,
    session_id: String,
    data: Vec<u8>,
) -> Result<(), DesktopError> {
    if data.len() > 65_536 {
        return Err(DesktopError::InputTooLarge);
    }
    let control = state
        .sessions
        .lock()
        .await
        .get(&session_id)
        .cloned()
        .ok_or_else(|| DesktopError::SessionNotFound(session_id.clone()))?;
    control.input.lock().await.write_all(&data).await?;
    Ok(())
}

#[tauri::command]
async fn resize_session(
    state: tauri::State<'_, DesktopState>,
    session_id: String,
    columns: u32,
    rows: u32,
) -> Result<(), DesktopError> {
    let size = TerminalSize::new(columns, rows)?;
    let control = state
        .sessions
        .lock()
        .await
        .get(&session_id)
        .cloned()
        .ok_or_else(|| DesktopError::SessionNotFound(session_id))?;
    control
        .size
        .send(size)
        .map_err(|_| DesktopError::StateUnavailable)
}

#[tauri::command]
async fn close_session(
    state: tauri::State<'_, DesktopState>,
    session_id: String,
) -> Result<(), DesktopError> {
    let control = state
        .sessions
        .lock()
        .await
        .remove(&session_id)
        .ok_or_else(|| DesktopError::SessionNotFound(session_id))?;
    control.input.lock().await.shutdown().await?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let paths = PlatformPaths::discover()?;
            paths.ensure_data_dir()?;
            let storage = SqliteStorage::open(paths.database)?;
            app.manage(DesktopState {
                database: Mutex::new(storage),
                sessions: Arc::new(AsyncMutex::new(HashMap::new())),
                local_forwards: Arc::new(AsyncMutex::new(HashMap::new())),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_hosts,
            add_host,
            list_credentials,
            list_agent_identities,
            import_agent_credential,
            probe_host_key,
            trust_host_key,
            start_agent_session,
            write_session,
            resize_session,
            close_session,
            list_sftp_directory,
            read_sftp_file,
            upload_sftp_file,
            list_local_forwards,
            start_local_forward,
            stop_local_forward,
        ])
        .run(tauri::generate_context!())
        .expect("YASC desktop runtime failed");
}

#[cfg(test)]
mod tests {
    use yasc_domain::{CredentialCapabilities, CredentialUsage, Custody, Synchronization};

    use super::*;

    #[test]
    fn summary_exposes_public_agent_metadata_without_secret_references() {
        let host_id = HostId::new();
        let credential = Credential::new_external_key(
            "Agent key",
            CredentialProviderKind::OpenSshAgent,
            CredentialCapabilities::new(
                Custody::ExternalProvider,
                Synchronization::LocalOnly,
                [CredentialUsage::DirectSsh],
            )
            .unwrap(),
            ExternalKeyReference::new("ssh-ed25519", vec![1, 2, 3], None).unwrap(),
        )
        .unwrap();
        let grant =
            CredentialGrant::new(credential.id, [host_id], [CredentialUsage::DirectSsh]).unwrap();
        let summary = summarize_credential(&PersistedCredential {
            credential,
            secret_refs: Vec::new(),
            grants: vec![grant],
        });

        assert!(
            summary.is_err(),
            "invalid public-key blobs must fail closed"
        );
    }

    #[test]
    fn session_resolution_enforces_host_scoped_grant_before_provider_use() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let allowed = Host::new("Allowed", "deploy@allowed.example".parse().unwrap()).unwrap();
        let denied = Host::new("Denied", "deploy@denied.example".parse().unwrap()).unwrap();
        storage.save_host(&allowed).unwrap();
        storage.save_host(&denied).unwrap();
        let credential = Credential::new_external_key(
            "Agent key",
            CredentialProviderKind::OpenSshAgent,
            CredentialCapabilities::new(
                Custody::ExternalProvider,
                Synchronization::LocalOnly,
                [CredentialUsage::DirectSsh],
            )
            .unwrap(),
            ExternalKeyReference::new("ssh-ed25519", vec![1, 2, 3], None).unwrap(),
        )
        .unwrap();
        let grant = CredentialGrant::new(credential.id, [allowed.id], [CredentialUsage::DirectSsh])
            .unwrap();
        storage.save_credential(&credential, &[], &[grant]).unwrap();

        assert!(matches!(
            resolve_agent_session(&storage, denied.id, credential.id),
            Err(DesktopError::CredentialUnauthorized { .. })
        ));
    }
}
