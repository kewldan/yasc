#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    env, fs,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose};
use clap::{Args, Parser, Subcommand, ValueEnum};
use crossterm::terminal;
use thiserror::Error;
use yasc_domain::{
    Credential, CredentialCapabilities, CredentialGrant, CredentialId, CredentialProviderKind,
    CredentialUsage, Custody, ExternalKeyReference, Host, HostId, HostKeyAlgorithm,
    HostKeyDecision, HostKeyError, HostKeyFingerprint, HostKeyMaterial, HostKeyObservation,
    HostKeyPolicy, HostKeySource, SshTarget, Synchronization,
};
use yasc_platform::{PlatformError, PlatformPaths};
use yasc_ssh::{
    ConnectionPlan, HostKeyPolicy as OpenSshHostKeyPolicy, NativeAgentCommandRequest,
    NativeAgentShellRequest, NativeCommandRequest, NativeShellIo, NativeShellRequest,
    NativeSshEngine, NativeSshError, OpenSshEngine, OpenSshError, OpenSshRequest, SshEngine,
    TerminalSize, connect_agent, external_key_fingerprint, list_agent_identities,
    validate_private_key,
};
use yasc_storage::{SqliteStorage, StorageError};
use yasc_vault::{EncryptedVault, SecretBytes, SecretKind, VaultBackend, VaultError};

#[derive(Debug, Parser)]
#[command(name = "yasc", version, about = "Yes Another SSH Client")]
struct Cli {
    /// Override the local SQLite database path.
    #[arg(long, global = true, value_name = "PATH")]
    database: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect a normalized direct connection plan without connecting.
    Inspect(InspectArgs),
    /// Open an interactive direct SSH session using the controlled OpenSSH adapter.
    Connect(ConnectArgs),
    /// Execute one command through the native SSH engine.
    Exec(NativeExecArgs),
    /// Open an interactive shell through the native SSH engine.
    Shell(NativeShellArgs),
    /// Manage the local host inventory.
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
    /// Inspect and manage persistent SSH host-key trust.
    HostKey {
        #[command(subcommand)]
        command: HostKeyCommand,
    },
    /// Initialize the encrypted local vault.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Import and inspect local-vault and external-agent SSH credentials.
    Credential {
        #[command(subcommand)]
        command: CredentialCommand,
    },
    /// Inspect identities available from an external SSH agent.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
}

#[derive(Debug, Args)]
struct NativeExecArgs {
    /// Inventory host identifier. The host target must include a username.
    host_id: HostId,
    /// Private key in an OpenSSH, PKCS#8, PEM, or supported PuTTY text format.
    #[arg(long, value_name = "PATH")]
    identity: Option<PathBuf>,
    /// Local-vault or external-agent credential identifier.
    #[arg(long, value_name = "ID")]
    credential: Option<CredentialId>,
    /// File containing the local vault password. Required only for local-vault credentials.
    #[arg(long, value_name = "PATH")]
    vault_password_file: Option<PathBuf>,
    /// File containing the private-key passphrase. Trailing CR/LF bytes are removed.
    #[arg(long, value_name = "PATH")]
    passphrase_file: Option<PathBuf>,
    /// Remote command string passed to the SSH exec request.
    command: String,
    /// End-to-end command timeout in seconds.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=86400))]
    timeout_seconds: u64,
    /// Combined stdout and stderr capture limit.
    #[arg(long, default_value_t = 1_048_576)]
    max_output_bytes: usize,
    /// Print machine-readable JSON with base64-encoded output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct NativeShellArgs {
    /// Inventory host identifier. The host target must include a username.
    host_id: HostId,
    /// Private key in an OpenSSH, PKCS#8, PEM, or supported PuTTY text format.
    #[arg(long, value_name = "PATH")]
    identity: Option<PathBuf>,
    /// Local-vault or external-agent credential identifier.
    #[arg(long, value_name = "ID")]
    credential: Option<CredentialId>,
    /// File containing the local vault password. Required only for local-vault credentials.
    #[arg(long, value_name = "PATH")]
    vault_password_file: Option<PathBuf>,
    /// File containing the private-key passphrase. Trailing CR/LF bytes are removed.
    #[arg(long, value_name = "PATH")]
    passphrase_file: Option<PathBuf>,
    /// PTY terminal type. Defaults to the local TERM value or xterm-256color.
    #[arg(long, value_name = "TERM")]
    terminal_type: Option<String>,
}

#[derive(Debug, Subcommand)]
enum VaultCommand {
    /// Create the local encrypted vault.
    Init(VaultInitArgs),
}

#[derive(Debug, Args)]
struct VaultInitArgs {
    /// File containing the vault password. Trailing CR/LF bytes are removed.
    #[arg(long, value_name = "PATH")]
    password_file: PathBuf,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum CredentialCommand {
    /// Validate and encrypt a private key for explicitly selected hosts.
    ImportKey(CredentialImportKeyArgs),
    /// Register a non-exportable key already available from an SSH agent.
    ImportAgent(CredentialImportAgentArgs),
    /// List credential metadata without unlocking the vault.
    List(OutputArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AgentProviderArg {
    #[value(name = "openssh")]
    OpenSsh,
    Pageant,
}

impl From<AgentProviderArg> for CredentialProviderKind {
    fn from(value: AgentProviderArg) -> Self {
        match value {
            AgentProviderArg::OpenSsh => Self::OpenSshAgent,
            AgentProviderArg::Pageant => Self::Pageant,
        }
    }
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// List public identities without requesting signatures.
    List(AgentListArgs),
}

#[derive(Debug, Args)]
struct AgentListArgs {
    /// External agent implementation.
    #[arg(long, value_enum, default_value_t = AgentProviderArg::OpenSsh)]
    provider: AgentProviderArg,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CredentialImportKeyArgs {
    /// Human-readable credential label.
    label: String,
    /// Host allowed to use this credential. May be repeated.
    #[arg(long = "host", required = true, value_name = "HOST_ID")]
    host_ids: Vec<HostId>,
    /// Private key in an OpenSSH, PKCS#8, PEM, or supported PuTTY text format.
    #[arg(long, value_name = "PATH")]
    key_file: PathBuf,
    /// File containing the private-key passphrase. It is encrypted separately.
    #[arg(long, value_name = "PATH")]
    key_passphrase_file: Option<PathBuf>,
    /// File containing the local vault password.
    #[arg(long, value_name = "PATH")]
    vault_password_file: PathBuf,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CredentialImportAgentArgs {
    /// Human-readable credential label.
    label: String,
    /// Public-key SHA-256 fingerprint returned by `yasc agent list`.
    fingerprint: String,
    /// Host allowed to use this credential. May be repeated.
    #[arg(long = "host", required = true, value_name = "HOST_ID")]
    host_ids: Vec<HostId>,
    /// External agent implementation.
    #[arg(long, value_enum, default_value_t = AgentProviderArg::OpenSsh)]
    provider: AgentProviderArg,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct InspectArgs {
    /// SSH destination in [user@]host[:port] form.
    target: SshTarget,
    /// Evaluate the target through the installed OpenSSH client (`ssh -G`).
    #[arg(long)]
    effective: bool,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    openssh: OpenSshArgs,
}

#[derive(Debug, Args)]
struct ConnectArgs {
    /// SSH destination in [user@]host[:port] form.
    target: SshTarget,
    #[command(flatten)]
    openssh: OpenSshArgs,
}

#[derive(Debug, Args)]
struct OpenSshArgs {
    /// Explicit OpenSSH configuration file. Defaults to no configuration file.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Explicit private-key path passed to OpenSSH with IdentitiesOnly enabled.
    #[arg(long, value_name = "PATH")]
    identity: Option<PathBuf>,
    /// Trust a previously unseen host key, while still rejecting changed keys.
    #[arg(long)]
    accept_new: bool,
    /// OpenSSH executable or absolute path.
    #[arg(long, default_value = "ssh", value_name = "PATH")]
    ssh_binary: PathBuf,
}

impl OpenSshArgs {
    fn request(&self, target: SshTarget) -> OpenSshRequest {
        let mut request = OpenSshRequest::new(target);
        request.config_file = self.config.clone();
        request.identity_file = self.identity.clone();
        request.host_key_policy = if self.accept_new {
            OpenSshHostKeyPolicy::AcceptNew
        } else {
            OpenSshHostKeyPolicy::Strict
        };
        request
    }
}

#[derive(Debug, Subcommand)]
enum HostCommand {
    /// Add a host to the local inventory.
    Add(HostAddArgs),
    /// List active hosts in the local inventory.
    List(OutputArgs),
    /// Show one host by identifier.
    Show(HostIdArgs),
    /// Remove a host by creating a local tombstone.
    Remove(HostIdArgs),
    /// Preview or apply a loss-aware import from an OpenSSH configuration.
    ImportOpenSsh(HostImportOpenSshArgs),
}

#[derive(Debug, Subcommand)]
enum HostKeyCommand {
    /// Perform native SSH key exchange and evaluate the exact presented server key.
    Probe(HostKeyProbeArgs),
    /// Evaluate a presented key without changing trust state.
    Check(HostKeyCheckArgs),
    /// Trust the first key for a host after explicit confirmation.
    Trust(HostKeyTrustArgs),
    /// Replace an expected active key and preserve it as superseded history.
    Rotate(HostKeyRotateArgs),
    /// Persist a key learned through UpdateHostKeys after active-key authentication.
    AcceptUpdate(HostKeyAcceptUpdateArgs),
    /// Revoke a key already present in host history.
    Revoke(HostKeyRevokeArgs),
    /// List key history or immutable trust events.
    List(HostKeyListArgs),
}

#[derive(Debug, Args)]
struct HostKeyProbeArgs {
    /// Inventory host identifier.
    host_id: HostId,
    /// Ask for confirmation when no trusted key exists.
    #[arg(long)]
    ask: bool,
    /// Explicitly persist a key when the probe returns a first-use confirmation decision.
    #[arg(long)]
    trust_first_use: bool,
    /// SSH handshake timeout in seconds.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=300))]
    timeout_seconds: u64,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PresentedHostKeyArgs {
    /// Inventory host identifier.
    host_id: HostId,
    /// OpenSSH key algorithm, for example ssh-ed25519.
    algorithm: HostKeyAlgorithm,
    /// Base64-encoded SSH public-key blob, without algorithm or comment.
    key_base64: String,
}

#[derive(Debug, Args)]
struct HostKeyCheckArgs {
    #[command(flatten)]
    key: PresentedHostKeyArgs,
    /// Ask for confirmation when no trusted key exists.
    #[arg(long)]
    ask: bool,
    /// Treat this key as an UpdateHostKeys observation.
    #[arg(long, requires = "authenticated_by")]
    update_host_keys: bool,
    /// Active fingerprint that authenticated this UpdateHostKeys observation.
    #[arg(long)]
    authenticated_by: Option<HostKeyFingerprint>,
    /// Certificate-authority fingerprint that signed the presented host certificate.
    #[arg(long)]
    certificate_authority: Option<HostKeyFingerprint>,
    /// Trust a certificate authority for this evaluation. May be repeated.
    #[arg(long)]
    trust_ca: Vec<HostKeyFingerprint>,
    /// Revoke a certificate authority for this evaluation. May be repeated.
    #[arg(long)]
    revoke_ca: Vec<HostKeyFingerprint>,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct HostKeyTrustArgs {
    #[command(flatten)]
    key: PresentedHostKeyArgs,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct HostKeyRotateArgs {
    #[command(flatten)]
    key: PresentedHostKeyArgs,
    /// Fingerprint that must still be active before replacement.
    #[arg(long)]
    replace: HostKeyFingerprint,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct HostKeyAcceptUpdateArgs {
    #[command(flatten)]
    key: PresentedHostKeyArgs,
    /// Active trusted fingerprint that authenticated this UpdateHostKeys observation.
    #[arg(long)]
    authenticated_by: HostKeyFingerprint,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct HostKeyRevokeArgs {
    /// Inventory host identifier.
    host_id: HostId,
    /// Fingerprint to revoke.
    fingerprint: HostKeyFingerprint,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct HostKeyListArgs {
    /// Inventory host identifier.
    host_id: HostId,
    /// Show immutable trust events instead of key records.
    #[arg(long)]
    events: bool,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct HostAddArgs {
    /// Human-readable inventory label.
    label: String,
    /// SSH destination in [user@]host[:port] form.
    target: SshTarget,
    /// Attach a searchable tag. May be repeated.
    #[arg(long)]
    tag: Vec<String>,
    /// Mark the host environment, for example development or production.
    #[arg(long)]
    environment: Option<String>,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct HostImportOpenSshArgs {
    /// OpenSSH configuration to inspect. Include directives are rejected in this initial slice.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    /// Persist importable entries atomically. Without this flag, the command is preview-only.
    #[arg(long)]
    apply: bool,
    /// Attach an additional searchable tag to every imported host. May be repeated.
    #[arg(long)]
    tag: Vec<String>,
    /// OpenSSH executable or absolute path used for exact effective configuration evaluation.
    #[arg(long, default_value = "ssh", value_name = "PATH")]
    ssh_binary: PathBuf,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OutputArgs {
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct HostIdArgs {
    /// Stable host identifier.
    id: HostId,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Inspect(args) => {
            let request = args.openssh.request(args.target.clone());
            let engine = OpenSshEngine::new(&args.openssh.ssh_binary);
            let effective_config = args
                .effective
                .then(|| engine.effective_config(&request))
                .transpose()?
                .map(|config| config.redacted_entries());
            let plan = if args.effective {
                request.plan()
            } else {
                ConnectionPlan::direct(args.target)
            };
            if args.json {
                if let Some(effective_config) = effective_config {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "plan": plan,
                            "effective_config": effective_config,
                        }))?
                    );
                } else {
                    println!("{}", serde_json::to_string_pretty(&plan)?);
                }
            } else {
                println!("Connection plan");
                println!("  mode: direct");
                println!(
                    "  engine: {}",
                    match plan.engine {
                        SshEngine::NativeRust => "native-rust (planned)",
                        SshEngine::OpenSshCompatibility => "openssh-compatibility",
                    }
                );
                println!("  target: {}", plan.target);
                println!("  host: {}", plan.target.host());
                println!("  port: {}", plan.target.port());
                println!(
                    "  username: {}",
                    plan.target.username().unwrap_or("<from configuration>")
                );
                println!("  credential: <not selected>");
                println!("  network: not contacted");
                if let Some(effective_config) = effective_config {
                    println!("Effective OpenSSH configuration");
                    for entry in effective_config {
                        println!("  {}: {}", entry.key, entry.value);
                    }
                }
            }
        }
        Command::Connect(args) => {
            let engine = OpenSshEngine::new(&args.openssh.ssh_binary);
            let request = args.openssh.request(args.target);
            let plan = request.plan();
            eprintln!("YASC direct session via OpenSSH compatibility engine");
            eprintln!("Target: {}", plan.target);
            eprintln!("Host-key policy: {:?}", request.host_key_policy);
            let status = engine.connect(&request)?;
            if !status.success() {
                return Err(CliError::SshExit(status.code()));
            }
        }
        Command::Exec(args) => run_native_exec(cli.database, args).await?,
        Command::Shell(args) => run_native_shell(cli.database, args).await?,
        Command::Host { command } => run_host_command(cli.database, command)?,
        Command::HostKey { command } => run_host_key_command(cli.database, command).await?,
        Command::Vault { command } => run_vault_command(cli.database, command)?,
        Command::Credential { command } => run_credential_command(cli.database, command).await?,
        Command::Agent { command } => run_agent_command(command).await?,
    }
    Ok(())
}

fn run_vault_command(database: Option<PathBuf>, command: VaultCommand) -> Result<(), CliError> {
    match command {
        VaultCommand::Init(args) => {
            let storage = open_storage(database)?;
            let password = read_secret_file(&args.password_file, true)?;
            let vault = EncryptedVault::create(storage, password)?;
            drop(vault);
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "initialized": true,
                    }))?
                );
            } else {
                println!("Encrypted local vault initialized");
            }
        }
    }
    Ok(())
}

async fn run_credential_command(
    database: Option<PathBuf>,
    command: CredentialCommand,
) -> Result<(), CliError> {
    match command {
        CredentialCommand::ImportKey(args) => import_key_credential(database, args)?,
        CredentialCommand::ImportAgent(args) => import_agent_credential(database, args).await?,
        CredentialCommand::List(args) => {
            let storage = open_storage(database)?;
            let credentials = storage.list_credentials()?;
            if args.json {
                let rows = credentials
                    .iter()
                    .map(credential_json)
                    .collect::<Result<Vec<_>, _>>()?;
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else if credentials.is_empty() {
                println!("No credentials");
            } else {
                for persisted in &credentials {
                    println!(
                        "{}  {}  {}  hosts:{}{}",
                        persisted.credential.id,
                        persisted.credential.label,
                        credential_provider_name(persisted.credential.provider),
                        persisted
                            .grants
                            .iter()
                            .flat_map(|grant| grant.host_ids.iter())
                            .collect::<BTreeSet<_>>()
                            .len(),
                        if persisted.secret(SecretKind::Passphrase).is_some() {
                            "  passphrase:encrypted"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
    }
    Ok(())
}

const fn credential_provider_name(provider: CredentialProviderKind) -> &'static str {
    match provider {
        CredentialProviderKind::LocalVault => "local-vault",
        CredentialProviderKind::NativeKeystore => "native-keystore",
        CredentialProviderKind::OpenSshAgent => "openssh-agent",
        CredentialProviderKind::Pageant => "pageant",
        CredentialProviderKind::Pkcs11 => "pkcs11",
        CredentialProviderKind::Fido => "fido",
        CredentialProviderKind::ExternalPasswordManager => "external-password-manager",
        CredentialProviderKind::ServerDelegation => "server-delegation",
    }
}

async fn run_agent_command(command: AgentCommand) -> Result<(), CliError> {
    match command {
        AgentCommand::List(args) => {
            let mut agent = connect_agent(args.provider.into()).await?;
            let identities = list_agent_identities(&mut agent).await?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&identities)?);
            } else if identities.is_empty() {
                println!("No agent identities");
            } else {
                for identity in identities {
                    println!(
                        "{}  {}{}",
                        identity.fingerprint,
                        identity.algorithm,
                        if identity.comment.is_empty() {
                            String::new()
                        } else {
                            format!("  {}", identity.comment)
                        }
                    );
                }
            }
        }
    }
    Ok(())
}

async fn import_agent_credential(
    database: Option<PathBuf>,
    args: CredentialImportAgentArgs,
) -> Result<(), CliError> {
    if args.label.trim().is_empty() {
        return Err(CliError::EmptyCredentialLabel);
    }
    let mut storage = open_storage(database)?;
    for host_id in &args.host_ids {
        if storage.find_host(*host_id)?.is_none() {
            return Err(CliError::HostNotFound(*host_id));
        }
    }
    let provider = CredentialProviderKind::from(args.provider);
    let mut agent = connect_agent(provider).await?;
    let identity = list_agent_identities(&mut agent)
        .await?
        .into_iter()
        .find(|identity| identity.fingerprint == args.fingerprint)
        .ok_or_else(|| CliError::AgentFingerprintNotFound(args.fingerprint.clone()))?;
    let capabilities = CredentialCapabilities::new(
        Custody::ExternalProvider,
        Synchronization::LocalOnly,
        [CredentialUsage::DirectSsh],
    )?;
    let credential = Credential::new_external_key(
        args.label.trim(),
        provider,
        capabilities,
        identity.external_reference()?,
    )?;
    let grant = CredentialGrant::new(credential.id, args.host_ids, [CredentialUsage::DirectSsh])?;
    storage.save_credential(&credential, &[], std::slice::from_ref(&grant))?;
    if args.json {
        let persisted = yasc_storage::PersistedCredential {
            credential,
            secret_refs: Vec::new(),
            grants: vec![grant],
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&credential_json(&persisted)?)?
        );
    } else {
        println!(
            "Agent credential registered: {} ({})",
            credential.label, credential.id
        );
    }
    Ok(())
}

fn import_key_credential(
    database: Option<PathBuf>,
    args: CredentialImportKeyArgs,
) -> Result<(), CliError> {
    if args.label.trim().is_empty() {
        return Err(CliError::EmptyCredentialLabel);
    }
    let private_key = read_secret_file(&args.key_file, false)?;
    let passphrase = args
        .key_passphrase_file
        .as_deref()
        .map(|path| read_secret_file(path, true))
        .transpose()?;
    validate_private_key(&private_key, passphrase.as_ref())?;

    let storage = open_storage(database)?;
    for host_id in &args.host_ids {
        if storage.find_host(*host_id)?.is_none() {
            return Err(CliError::HostNotFound(*host_id));
        }
    }
    let capabilities = CredentialCapabilities::new(
        Custody::Exportable,
        Synchronization::LocalOnly,
        [CredentialUsage::DirectSsh],
    )?;
    let credential = Credential::new(
        args.label.trim(),
        CredentialProviderKind::LocalVault,
        capabilities,
    );
    let grant = CredentialGrant::new(credential.id, args.host_ids, [CredentialUsage::DirectSsh])?;
    let password = read_secret_file(&args.vault_password_file, true)?;
    let mut vault = EncryptedVault::open(storage)?;
    vault.unlock(password)?;
    let key_ref = vault.store(credential.id, SecretKind::SshPrivateKey, private_key)?;
    let passphrase_ref = match passphrase {
        Some(passphrase) => match vault.store(credential.id, SecretKind::Passphrase, passphrase) {
            Ok(reference) => Some(reference),
            Err(error) => {
                let _ = vault.remove(key_ref);
                return Err(error.into());
            }
        },
        None => None,
    };
    let mut secret_refs = vec![key_ref];
    if let Some(reference) = passphrase_ref {
        secret_refs.push(reference);
    }
    if let Err(error) =
        vault
            .store_mut()
            .save_credential(&credential, &secret_refs, std::slice::from_ref(&grant))
    {
        for reference in secret_refs.into_iter().rev() {
            let _ = vault.remove(reference);
        }
        return Err(error.into());
    }
    if args.json {
        let persisted = yasc_storage::PersistedCredential {
            credential,
            secret_refs,
            grants: vec![grant],
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&credential_json(&persisted)?)?
        );
    } else {
        println!(
            "Credential imported: {} ({})",
            credential.label, credential.id
        );
    }
    Ok(())
}

fn credential_json(
    persisted: &yasc_storage::PersistedCredential,
) -> Result<serde_json::Value, CliError> {
    let host_ids = persisted
        .grants
        .iter()
        .flat_map(|grant| grant.host_ids.iter())
        .collect::<BTreeSet<_>>();
    let external_key = persisted
        .credential
        .external_key
        .as_ref()
        .map(|reference| {
            Ok::<_, CliError>(serde_json::json!({
                "algorithm": reference.algorithm,
                "fingerprint": external_key_fingerprint(reference)?,
                "comment": reference.comment,
            }))
        })
        .transpose()?;
    Ok(serde_json::json!({
        "id": persisted.credential.id,
        "label": persisted.credential.label,
        "provider": persisted.credential.provider,
        "custody": persisted.credential.capabilities.custody,
        "synchronization": persisted.credential.capabilities.synchronization,
        "allowed_usages": persisted.credential.capabilities.allowed_usages,
        "host_ids": host_ids,
        "has_private_key": persisted.secret(SecretKind::SshPrivateKey).is_some(),
        "has_passphrase": persisted.secret(SecretKind::Passphrase).is_some(),
        "external_key": external_key,
    }))
}

async fn run_native_exec(database: Option<PathBuf>, args: NativeExecArgs) -> Result<(), CliError> {
    let storage = open_storage(database)?;
    let host = storage
        .find_host(args.host_id)?
        .ok_or(CliError::HostNotFound(args.host_id))?;
    let username = host
        .target
        .username()
        .ok_or(CliError::NativeUsernameRequired)?
        .to_owned();
    let history = storage.load_host_key_history(args.host_id)?;
    let authentication = resolve_native_authentication(
        storage,
        args.host_id,
        args.identity.as_deref(),
        args.credential,
        args.vault_password_file.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let engine = NativeSshEngine::default();
    let output = match authentication {
        ResolvedNativeAuthentication::PrivateKey {
            private_key,
            passphrase,
        } => {
            let mut request = NativeCommandRequest::new(
                host.target,
                username,
                private_key,
                args.command.into_bytes(),
            )?
            .with_timeout(Duration::from_secs(args.timeout_seconds))?
            .with_max_output_bytes(args.max_output_bytes)?;
            if let Some(passphrase) = passphrase {
                request = request.with_passphrase(passphrase);
            }
            engine
                .execute_command(request, &history, &HostKeyPolicy::strict())
                .await?
        }
        ResolvedNativeAuthentication::Agent {
            provider,
            external_key,
        } => {
            let request = NativeAgentCommandRequest::new(
                host.target,
                username,
                external_key,
                args.command.into_bytes(),
            )?
            .with_timeout(Duration::from_secs(args.timeout_seconds))?
            .with_max_output_bytes(args.max_output_bytes)?;
            let mut agent = connect_agent(provider).await?;
            engine
                .execute_agent_command(request, &mut agent, &history, &HostKeyPolicy::strict())
                .await?
        }
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "exit_status": output.exit_status(),
                "stdout_base64": general_purpose::STANDARD.encode(output.stdout()),
                "stderr_base64": general_purpose::STANDARD.encode(output.stderr()),
                "host_key_decision": output.host_key_decision(),
            }))?
        );
    } else {
        io::stdout().write_all(output.stdout())?;
        io::stdout().flush()?;
        io::stderr().write_all(output.stderr())?;
        io::stderr().flush()?;
    }
    if output.exit_status() != 0 {
        return Err(CliError::RemoteCommandExit(output.exit_status()));
    }
    Ok(())
}

async fn run_native_shell(
    database: Option<PathBuf>,
    args: NativeShellArgs,
) -> Result<(), CliError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(CliError::InteractiveTerminalRequired);
    }
    let storage = open_storage(database)?;
    let host = storage
        .find_host(args.host_id)?
        .ok_or(CliError::HostNotFound(args.host_id))?;
    let username = host
        .target
        .username()
        .ok_or(CliError::NativeUsernameRequired)?
        .to_owned();
    let history = storage.load_host_key_history(args.host_id)?;
    let authentication = resolve_native_authentication(
        storage,
        args.host_id,
        args.identity.as_deref(),
        args.credential,
        args.vault_password_file.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let (columns, rows) = terminal::size()?;
    let initial_size = TerminalSize::new(u32::from(columns), u32::from(rows))?;
    let terminal_type = args
        .terminal_type
        .or_else(|| env::var("TERM").ok())
        .unwrap_or_else(|| "xterm-256color".to_owned());

    let raw_mode = RawModeGuard::enable()?;
    let (size_sender, size_receiver) = tokio::sync::watch::channel(initial_size);
    let resize_task = tokio::spawn(monitor_terminal_size(size_sender, initial_size));
    let engine = NativeSshEngine::default();
    let result = match authentication {
        ResolvedNativeAuthentication::PrivateKey {
            private_key,
            passphrase,
        } => {
            let mut request =
                NativeShellRequest::new(host.target, username, private_key, initial_size)?
                    .with_terminal_type(terminal_type)?;
            if let Some(passphrase) = passphrase {
                request = request.with_passphrase(passphrase);
            }
            engine
                .run_shell(
                    request,
                    &history,
                    &HostKeyPolicy::strict(),
                    NativeShellIo::new(
                        tokio::io::stdin(),
                        tokio::io::stdout(),
                        tokio::io::stderr(),
                        size_receiver,
                    ),
                )
                .await
        }
        ResolvedNativeAuthentication::Agent {
            provider,
            external_key,
        } => {
            let request =
                NativeAgentShellRequest::new(host.target, username, external_key, initial_size)?
                    .with_terminal_type(terminal_type)?;
            let mut agent = connect_agent(provider).await?;
            engine
                .run_agent_shell(
                    request,
                    &mut agent,
                    &history,
                    &HostKeyPolicy::strict(),
                    NativeShellIo::new(
                        tokio::io::stdin(),
                        tokio::io::stdout(),
                        tokio::io::stderr(),
                        size_receiver,
                    ),
                )
                .await
        }
    };
    resize_task.abort();
    drop(raw_mode);
    let output = result?;
    if output.exit_status() != 0 {
        return Err(CliError::RemoteCommandExit(output.exit_status()));
    }
    Ok(())
}

enum ResolvedNativeAuthentication {
    PrivateKey {
        private_key: SecretBytes,
        passphrase: Option<SecretBytes>,
    },
    Agent {
        provider: CredentialProviderKind,
        external_key: ExternalKeyReference,
    },
}

fn resolve_native_authentication(
    storage: SqliteStorage,
    host_id: HostId,
    identity: Option<&Path>,
    credential: Option<CredentialId>,
    vault_password_file: Option<&Path>,
    passphrase_file: Option<&Path>,
) -> Result<ResolvedNativeAuthentication, CliError> {
    match (identity, credential) {
        (Some(identity), None) => {
            if vault_password_file.is_some() {
                return Err(CliError::InvalidCredentialSelection);
            }
            Ok(ResolvedNativeAuthentication::PrivateKey {
                private_key: read_secret_file(identity, false)?,
                passphrase: passphrase_file
                    .map(|path| read_secret_file(path, true))
                    .transpose()?,
            })
        }
        (None, Some(credential_id)) => {
            if passphrase_file.is_some() {
                return Err(CliError::InvalidCredentialSelection);
            }
            let persisted = storage
                .find_credential(credential_id)?
                .ok_or(CliError::CredentialNotFound(credential_id))?;
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
                return Err(CliError::CredentialUnauthorized {
                    credential_id,
                    host_id,
                });
            }
            match persisted.credential.provider {
                CredentialProviderKind::LocalVault => {
                    let password_path =
                        vault_password_file.ok_or(CliError::VaultPasswordRequired)?;
                    let key_ref = persisted
                        .secret(SecretKind::SshPrivateKey)
                        .ok_or(CliError::CredentialPrivateKeyMissing(credential_id))?;
                    let passphrase_ref = persisted.secret(SecretKind::Passphrase);
                    let password = read_secret_file(password_path, true)?;
                    let mut vault = EncryptedVault::open(storage)?;
                    vault.unlock(password)?;
                    let private_key = vault.read(key_ref)?;
                    let passphrase = passphrase_ref
                        .map(|reference| vault.read(reference))
                        .transpose()?;
                    Ok(ResolvedNativeAuthentication::PrivateKey {
                        private_key,
                        passphrase,
                    })
                }
                provider @ (CredentialProviderKind::OpenSshAgent
                | CredentialProviderKind::Pageant) => {
                    if vault_password_file.is_some() {
                        return Err(CliError::InvalidCredentialSelection);
                    }
                    let external_key = persisted
                        .credential
                        .external_key
                        .ok_or(CliError::CredentialExternalKeyMissing(credential_id))?;
                    Ok(ResolvedNativeAuthentication::Agent {
                        provider,
                        external_key,
                    })
                }
                provider => Err(CliError::UnsupportedCredentialProvider(provider)),
            }
        }
        _ => Err(CliError::InvalidCredentialSelection),
    }
}

async fn monitor_terminal_size(
    sender: tokio::sync::watch::Sender<TerminalSize>,
    mut last_size: TerminalSize,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if sender.is_closed() {
            return;
        }
        let Ok((columns, rows)) = terminal::size() else {
            continue;
        };
        let Ok(next_size) = TerminalSize::new(u32::from(columns), u32::from(rows)) else {
            continue;
        };
        if next_size != last_size {
            if sender.send(next_size).is_err() {
                return;
            }
            last_size = next_size;
        }
    }
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn read_secret_file(path: &Path, trim_line_endings: bool) -> Result<SecretBytes, CliError> {
    let mut file = fs::File::open(path).map_err(|source| CliError::ReadSecret {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = file
            .metadata()
            .map_err(|source| CliError::ReadSecret {
                path: path.to_path_buf(),
                source,
            })?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(CliError::InsecureSecretPermissions(path.to_path_buf()));
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| CliError::ReadSecret {
            path: path.to_path_buf(),
            source,
        })?;
    if trim_line_endings {
        while matches!(bytes.last(), Some(b'\r' | b'\n')) {
            bytes.pop();
        }
    }
    Ok(SecretBytes::new(bytes))
}

async fn run_host_key_command(
    database: Option<PathBuf>,
    command: HostKeyCommand,
) -> Result<(), CliError> {
    let mut storage = open_storage(database)?;
    let host_id = match &command {
        HostKeyCommand::Probe(args) => args.host_id,
        HostKeyCommand::Check(args) => args.key.host_id,
        HostKeyCommand::Trust(args) => args.key.host_id,
        HostKeyCommand::Rotate(args) => args.key.host_id,
        HostKeyCommand::AcceptUpdate(args) => args.key.host_id,
        HostKeyCommand::Revoke(args) => args.host_id,
        HostKeyCommand::List(args) => args.host_id,
    };
    let host = storage
        .find_host(host_id)?
        .ok_or(CliError::HostNotFound(host_id))?;

    match command {
        HostKeyCommand::Probe(args) => {
            let mut history = storage.load_host_key_history(args.host_id)?;
            let policy = if args.ask || args.trust_first_use {
                HostKeyPolicy::ask_on_first_use()
            } else {
                HostKeyPolicy::strict()
            };
            let engine = NativeSshEngine::new(Duration::from_secs(args.timeout_seconds));
            let probe = engine
                .probe_host_key(&host.target, &history, &policy)
                .await?;
            if probe.decision == HostKeyDecision::ConfirmFirstUse && args.trust_first_use {
                let event = history.trust_first_use(probe.observation, unix_now()?)?;
                storage.save_host_key_change(&history, &event)?;
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "decision": "trusted_first_use",
                            "event": event,
                        }))?
                    );
                } else {
                    println!("Trusted first-use host key: {}", event.fingerprint);
                }
            } else {
                print_native_probe(&probe, args.json)?;
                if !probe.decision.is_accepted() {
                    return Err(CliError::HostKeyRejected(probe.decision));
                }
            }
        }
        HostKeyCommand::Check(args) => {
            let history = storage.load_host_key_history(args.key.host_id)?;
            let mut observation = presented_host_key(args.key)?;
            observation.source = if args.update_host_keys {
                HostKeySource::UpdateHostKeys
            } else {
                HostKeySource::Presented
            };
            observation.authenticated_by = args.authenticated_by;
            observation.certificate_authority = args.certificate_authority;
            let mut policy = if args.ask {
                HostKeyPolicy::ask_on_first_use()
            } else {
                HostKeyPolicy::strict()
            };
            policy.allow_update_host_keys = args.update_host_keys;
            policy.trusted_certificate_authorities = args.trust_ca.into_iter().collect();
            policy.revoked_certificate_authorities = args.revoke_ca.into_iter().collect();
            let decision = history.evaluate(&observation, &policy);
            print_host_key_decision(&decision, args.json)?;
            if !decision.is_accepted() {
                return Err(CliError::HostKeyRejected(decision));
            }
        }
        HostKeyCommand::Trust(args) => {
            let mut history = storage.load_host_key_history(args.key.host_id)?;
            let mut observation = presented_host_key(args.key)?;
            observation.source = HostKeySource::Manual;
            let event = history.trust_first_use(observation, unix_now()?)?;
            storage.save_host_key_change(&history, &event)?;
            print_json_or_debug(&event, args.json)?;
        }
        HostKeyCommand::Rotate(args) => {
            let mut history = storage.load_host_key_history(args.key.host_id)?;
            let mut observation = presented_host_key(args.key)?;
            observation.source = HostKeySource::Manual;
            let event = history.trust_manual_change(observation, &args.replace, unix_now()?)?;
            storage.save_host_key_change(&history, &event)?;
            print_json_or_debug(&event, args.json)?;
        }
        HostKeyCommand::AcceptUpdate(args) => {
            let mut history = storage.load_host_key_history(args.key.host_id)?;
            let mut observation = presented_host_key(args.key)?;
            observation.source = HostKeySource::UpdateHostKeys;
            observation.authenticated_by = Some(args.authenticated_by);
            let mut policy = HostKeyPolicy::strict();
            policy.allow_update_host_keys = true;
            let event = history.trust_authenticated_update(observation, &policy, unix_now()?)?;
            storage.save_host_key_change(&history, &event)?;
            print_json_or_debug(&event, args.json)?;
        }
        HostKeyCommand::Revoke(args) => {
            let mut history = storage.load_host_key_history(args.host_id)?;
            let event = history.revoke(&args.fingerprint, unix_now()?)?;
            storage.save_host_key_change(&history, &event)?;
            print_json_or_debug(&event, args.json)?;
        }
        HostKeyCommand::List(args) => {
            if args.events {
                let events = storage.list_host_key_events(args.host_id)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&events)?);
                } else if events.is_empty() {
                    println!("No host-key trust events recorded.");
                } else {
                    for event in events {
                        println!(
                            "{}  {:?}  {}  {}",
                            event.occurred_at_unix, event.kind, event.fingerprint, event.id
                        );
                    }
                }
            } else {
                let history = storage.load_host_key_history(args.host_id)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(history.records())?);
                } else if history.records().is_empty() {
                    println!("No host keys recorded.");
                } else {
                    for record in history.records() {
                        println!(
                            "{:?}  {}  {}  {}",
                            record.state,
                            record.material.algorithm,
                            record.material.fingerprint,
                            record.id
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn print_native_probe(probe: &yasc_ssh::NativeHostKeyProbe, json: bool) -> Result<(), CliError> {
    if json {
        println!("{}", serde_json::to_string_pretty(probe)?);
    } else {
        println!("Native SSH host-key probe");
        println!("  algorithm: {}", probe.observation.material.algorithm);
        println!("  fingerprint: {}", probe.observation.material.fingerprint);
        println!("  decision: {:?}", probe.decision);
        println!("  authentication: not attempted");
    }
    Ok(())
}

fn presented_host_key(args: PresentedHostKeyArgs) -> Result<HostKeyObservation, CliError> {
    let material = HostKeyMaterial::from_openssh_base64(args.algorithm, &args.key_base64)?;
    Ok(HostKeyObservation::presented(material))
}

fn print_host_key_decision(decision: &HostKeyDecision, json: bool) -> Result<(), CliError> {
    if json {
        println!("{}", serde_json::to_string_pretty(decision)?);
    } else {
        println!("Host-key decision: {decision:?}");
    }
    Ok(())
}

fn print_json_or_debug<T>(value: &T, json: bool) -> Result<(), CliError>
where
    T: serde::Serialize + std::fmt::Debug,
{
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{value:?}");
    }
    Ok(())
}

fn unix_now() -> Result<i64, CliError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::ClockBeforeEpoch)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| CliError::ClockOutOfRange)
}

fn run_host_command(database: Option<PathBuf>, command: HostCommand) -> Result<(), CliError> {
    let mut storage = open_storage(database)?;
    match command {
        HostCommand::Add(args) => {
            let mut host = Host::new(args.label, args.target)?;
            host.tags = validate_tags(args.tag)?;
            host.environment = args.environment;
            storage.save_host(&host)?;
            print_host(&host, args.json)?;
        }
        HostCommand::List(args) => {
            let hosts = storage.list_hosts()?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&hosts)?);
            } else if hosts.is_empty() {
                println!("No hosts in the local inventory.");
            } else {
                for host in hosts {
                    println!("{}  {}  {}", host.id, host.label, host.target);
                }
            }
        }
        HostCommand::Show(args) => {
            let host = storage
                .find_host(args.id)?
                .ok_or(CliError::HostNotFound(args.id))?;
            print_host(&host, args.json)?;
        }
        HostCommand::Remove(args) => {
            if !storage.remove_host(args.id)? {
                return Err(CliError::HostNotFound(args.id));
            }
            if args.json {
                println!("{{\"removed\":\"{}\"}}", args.id);
            } else {
                println!("Removed host {} from the active inventory.", args.id);
            }
        }
        HostCommand::ImportOpenSsh(args) => {
            let preview = OpenSshEngine::new(args.ssh_binary).inventory_preview(&args.config)?;
            let existing = storage.list_hosts()?;
            let mut tags = validate_tags(args.tag)?;
            tags.insert("openssh-import".to_owned());
            let mut ready = Vec::new();
            let mut already_present_aliases = Vec::new();
            for candidate in &preview.candidates {
                if !candidate.blockers.is_empty() {
                    continue;
                }
                if existing.iter().any(|host| {
                    host.label.eq_ignore_ascii_case(&candidate.alias)
                        || host.target == candidate.target
                }) {
                    already_present_aliases.push(candidate.alias.clone());
                    continue;
                }
                let mut host = Host::new(candidate.alias.clone(), candidate.target.clone())?;
                host.tags = tags.clone();
                ready.push(host);
            }
            if args.apply {
                storage.save_hosts_atomically(&ready)?;
            }
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "applied": args.apply,
                        "preview": preview,
                        "ready": ready,
                        "already_present_aliases": already_present_aliases,
                    }))?
                );
            } else {
                for candidate in &preview.candidates {
                    if candidate.blockers.is_empty() {
                        let state = if already_present_aliases.contains(&candidate.alias) {
                            "already present"
                        } else if args.apply {
                            "imported"
                        } else {
                            "ready"
                        };
                        println!("{}  {}  {state}", candidate.alias, candidate.target);
                    } else {
                        println!(
                            "{}  {}  blocked: {:?}",
                            candidate.alias, candidate.target, candidate.blockers
                        );
                    }
                }
                for skipped in &preview.skipped_patterns {
                    println!("{}  skipped: {:?}", skipped.pattern, skipped.reason);
                }
                if !args.apply {
                    println!(
                        "Preview only: {} host(s) ready; re-run with --apply to persist them.",
                        ready.len()
                    );
                }
            }
        }
    }
    Ok(())
}

fn open_storage(database: Option<PathBuf>) -> Result<SqliteStorage, CliError> {
    let path = match database {
        Some(path) => path,
        None => {
            let paths = PlatformPaths::discover()?;
            paths.ensure_data_dir()?;
            paths.database
        }
    };
    SqliteStorage::open(path).map_err(CliError::from)
}

fn validate_tags(tags: Vec<String>) -> Result<BTreeSet<String>, CliError> {
    let mut validated = BTreeSet::new();
    for tag in tags {
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(CliError::EmptyTag);
        }
        validated.insert(tag.to_owned());
    }
    Ok(validated)
}

fn print_host(host: &Host, json: bool) -> Result<(), CliError> {
    if json {
        println!("{}", serde_json::to_string_pretty(host)?);
    } else {
        println!("Host {}", host.id);
        println!("  label: {}", host.label);
        println!("  target: {}", host.target);
        println!(
            "  environment: {}",
            host.environment.as_deref().unwrap_or("<not set>")
        );
        println!(
            "  tags: {}",
            if host.tags.is_empty() {
                "<none>".to_owned()
            } else {
                host.tags.iter().cloned().collect::<Vec<_>>().join(", ")
            }
        );
    }
    Ok(())
}

#[derive(Debug, Error)]
enum CliError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error(transparent)]
    OpenSsh(#[from] OpenSshError),
    #[error(transparent)]
    NativeSsh(#[from] NativeSshError),
    #[error(transparent)]
    InvalidHost(#[from] yasc_domain::HostError),
    #[error(transparent)]
    HostKey(#[from] HostKeyError),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    CredentialCapability(#[from] yasc_domain::CredentialCapabilityError),
    #[error(transparent)]
    CredentialGrant(#[from] yasc_domain::CredentialGrantError),
    #[error("host {0} was not found")]
    HostNotFound(HostId),
    #[error("host tags cannot be empty")]
    EmptyTag,
    #[error("OpenSSH session exited with status {0:?}")]
    SshExit(Option<i32>),
    #[error("host-key verification rejected the key: {0:?}")]
    HostKeyRejected(HostKeyDecision),
    #[error("system clock is before the Unix epoch")]
    ClockBeforeEpoch,
    #[error("system clock is outside the supported range")]
    ClockOutOfRange,
    #[error("native SSH requires a username in the inventory target")]
    NativeUsernameRequired,
    #[error("native interactive shell requires terminal stdin and stdout")]
    InteractiveTerminalRequired,
    #[error("credential label cannot be empty")]
    EmptyCredentialLabel,
    #[error(
        "choose exactly one of --identity or --credential; password options must match that choice"
    )]
    InvalidCredentialSelection,
    #[error("credential {0} was not found")]
    CredentialNotFound(CredentialId),
    #[error("credential {credential_id} does not authorize direct SSH to host {host_id}")]
    CredentialUnauthorized {
        credential_id: CredentialId,
        host_id: HostId,
    },
    #[error("credential {0} has no encrypted SSH private key")]
    CredentialPrivateKeyMissing(CredentialId),
    #[error("credential {0} has no external public-key reference")]
    CredentialExternalKeyMissing(CredentialId),
    #[error("no agent identity has fingerprint {0}")]
    AgentFingerprintNotFound(String),
    #[error("credential provider {0:?} is not supported by native SSH authentication")]
    UnsupportedCredentialProvider(CredentialProviderKind),
    #[error("--vault-password-file is required for a local-vault credential")]
    VaultPasswordRequired,
    #[error("failed to read secret file {path}: {source}")]
    ReadSecret {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("secret file permissions must deny group and other access: {0}")]
    #[cfg(unix)]
    InsecureSecretPermissions(PathBuf),
    #[error("remote command exited with status {0}")]
    RemoteCommandExit(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_file_trims_only_trailing_line_endings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("passphrase");
        fs::write(&path, b"  keep spaces  \r\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let secret = read_secret_file(&path, true).unwrap();

        assert_eq!(secret.expose_secret(), b"  keep spaces  ");
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_rejects_group_or_other_access() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity");
        fs::write(&path, b"not a real key").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        assert!(matches!(
            read_secret_file(&path, false),
            Err(CliError::InsecureSecretPermissions(found)) if found == path
        ));
    }
}
