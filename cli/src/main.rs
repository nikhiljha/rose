#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use clap::{Parser, Subcommand};

/// `RoSE` — Remote Shell Environment.
#[derive(Parser)]
#[command(name = "rose", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Connect to a remote host.
    Connect {
        /// The host to connect to (e.g., myserver.example.com or user@host).
        host: String,

        /// Use SSH bootstrap mode instead of native mode.
        #[arg(long)]
        ssh: bool,
    },
    /// Run the `RoSE` server daemon.
    Server,
    /// Generate X.509 client certificates for authentication.
    Keygen,
}

/// COVERAGE: main is the thin entry point; logic is tested via the library crate.
#[cfg_attr(coverage_nightly, coverage(off))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect { host, ssh } => {
            let mode = if ssh { "ssh-bootstrap" } else { "native" };
            tracing::info!(%host, %mode, "connecting");
            anyhow::bail!("connect not yet implemented");
        }
        Commands::Server => {
            tracing::info!("starting server");
            anyhow::bail!("server not yet implemented");
        }
        Commands::Keygen => {
            tracing::info!("generating certificates");
            anyhow::bail!("keygen not yet implemented");
        }
    }
}
