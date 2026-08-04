#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose};
use clap::{Args, Parser, Subcommand};
use thiserror::Error;
use yasc_domain::{
    Host, HostId, HostKeyAlgorithm, HostKeyDecision, HostKeyError, HostKeyFingerprint,
    HostKeyMaterial, HostKeyObservation, HostKeyPolicy, HostKeySource, SshTarget,
};
use yasc_platform::{PlatformError, PlatformPaths};
use yasc_ssh::{
    ConnectionPlan, HostKeyPolicy as OpenSshHostKeyPolicy, NativeCommandRequest, NativeSshEngine,
    NativeSshError, OpenSshEngine, OpenSshError, OpenSshRequest, SshEngine,
};
use yasc_storage::{SqliteStorage, StorageError};
use yasc_vault::SecretBytes;

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
}

#[derive(Debug, Args)]
struct NativeExecArgs {
    /// Inventory host identifier. The host target must include a username.
    host_id: HostId,
    /// Private key in an OpenSSH, PKCS#8, PEM, or supported PuTTY text format.
    #[arg(long, value_name = "PATH")]
    identity: PathBuf,
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
        Command::Host { command } => run_host_command(cli.database, command)?,
        Command::HostKey { command } => run_host_key_command(cli.database, command).await?,
    }
    Ok(())
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
    let private_key = read_secret_file(&args.identity, false)?;
    let mut request = NativeCommandRequest::new(
        host.target,
        username,
        private_key,
        args.command.into_bytes(),
    )?
    .with_timeout(Duration::from_secs(args.timeout_seconds))?
    .with_max_output_bytes(args.max_output_bytes)?;
    if let Some(path) = args.passphrase_file {
        request = request.with_passphrase(read_secret_file(&path, true)?);
    }
    let history = storage.load_host_key_history(args.host_id)?;
    let engine = NativeSshEngine::default();
    let output = engine
        .execute_command(request, &history, &HostKeyPolicy::strict())
        .await?;
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
