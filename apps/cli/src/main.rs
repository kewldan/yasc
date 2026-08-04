#![forbid(unsafe_code)]

use std::{collections::BTreeSet, path::PathBuf, process::ExitCode};

use clap::{Args, Parser, Subcommand};
use thiserror::Error;
use yasc_domain::{Host, HostId, SshTarget};
use yasc_platform::{PlatformError, PlatformPaths};
use yasc_ssh::ConnectionPlan;
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
    /// Manage the local host inventory.
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
}

#[derive(Debug, Args)]
struct InspectArgs {
    /// SSH destination in [user@]host[:port] form.
    target: SshTarget,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
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
            let plan = ConnectionPlan::direct(args.target);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                println!("Connection plan");
                println!("  mode: direct");
                println!("  engine: native-rust");
                println!("  target: {}", plan.target);
                println!("  host: {}", plan.target.host());
                println!("  port: {}", plan.target.port());
                println!(
                    "  username: {}",
                    plan.target.username().unwrap_or("<from configuration>")
                );
                println!("  credential: <not selected>");
                println!("  network: not contacted");
            }
        }
        Command::Host { command } => run_host_command(cli.database, command)?,
    }
    Ok(())
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
    InvalidHost(#[from] yasc_domain::HostError),
    #[error("host {0} was not found")]
    HostNotFound(HostId),
    #[error("host tags cannot be empty")]
    EmptyTag,
}
