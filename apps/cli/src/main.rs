#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use yasc_domain::SshTarget;
use yasc_ssh::ConnectionPlan;

#[derive(Debug, Parser)]
#[command(name = "yasc", version, about = "Yes Another SSH Client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect a normalized direct connection plan without connecting.
    Inspect(InspectArgs),
}

#[derive(Debug, Args)]
struct InspectArgs {
    /// SSH destination in [user@]host[:port] form.
    target: SshTarget,
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

fn run(cli: Cli) -> Result<(), serde_json::Error> {
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
    }
    Ok(())
}
