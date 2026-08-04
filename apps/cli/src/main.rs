#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Args, Parser, Subcommand};
use thiserror::Error;
use yasc_domain::{
    Host, HostId, HostKeyAlgorithm, HostKeyDecision, HostKeyError, HostKeyFingerprint,
    HostKeyMaterial, HostKeyObservation, HostKeyPolicy, HostKeySource, SshTarget,
};
use yasc_platform::{PlatformError, PlatformPaths};
use yasc_ssh::{
    ConnectionPlan, HostKeyPolicy as OpenSshHostKeyPolicy, OpenSshEngine, OpenSshError,
    OpenSshRequest, SshEngine,
};
use yasc_storage::{SqliteStorage, StorageError};

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

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
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
        Command::Host { command } => run_host_command(cli.database, command)?,
        Command::HostKey { command } => run_host_key_command(cli.database, command)?,
    }
    Ok(())
}

fn run_host_key_command(
    database: Option<PathBuf>,
    command: HostKeyCommand,
) -> Result<(), CliError> {
    let mut storage = open_storage(database)?;
    let host_id = match &command {
        HostKeyCommand::Check(args) => args.key.host_id,
        HostKeyCommand::Trust(args) => args.key.host_id,
        HostKeyCommand::Rotate(args) => args.key.host_id,
        HostKeyCommand::AcceptUpdate(args) => args.key.host_id,
        HostKeyCommand::Revoke(args) => args.host_id,
        HostKeyCommand::List(args) => args.host_id,
    };
    storage
        .find_host(host_id)?
        .ok_or(CliError::HostNotFound(host_id))?;

    match command {
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
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error(transparent)]
    OpenSsh(#[from] OpenSshError),
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
}
