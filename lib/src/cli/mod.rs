//! CLI entry point for the `rose` binary.
//!
//! This module contains all command-line parsing, server/client loop logic,
//! and SSH bootstrap mode. The actual binary is a thin wrapper that calls
//! [`run`].

mod client;
mod input;
mod keygen;
mod server;
mod ssh_bootstrap;
mod util;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// `RoSE` — Remote Shell Environment.
#[derive(Parser)]
#[command(name = "rose", version, about)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Connect to a remote host.
    Connect {
        /// The host to connect to (hostname or IP).
        host: String,

        /// Port to connect to.
        #[arg(long, default_value = "4433")]
        port: u16,

        /// Path to the server's certificate (DER format).
        #[arg(long)]
        cert: Option<PathBuf>,

        /// Use SSH bootstrap mode instead of native mode.
        #[arg(long)]
        ssh: bool,

        /// Path to the `rose` binary on the remote server (for `--ssh` mode).
        #[arg(long, default_value = "rose")]
        server_binary: String,

        /// Skip direct UDP and force STUN hole-punching (for testing).
        #[arg(long)]
        force_stun: bool,

        /// SSH port to connect to (for `--ssh` mode). Defaults to SSH's own default (22).
        #[arg(long)]
        ssh_port: Option<u16>,

        /// Extra options to pass to the SSH command (for `--ssh` mode).
        /// Can be specified multiple times, e.g. `--ssh-option StrictHostKeyChecking=no`.
        #[arg(long)]
        ssh_option: Vec<String>,

        /// Path to a client certificate for mutual TLS (PEM format).
        /// Used for reattaching to a bootstrapped session after detach.
        #[arg(long)]
        client_cert: Option<PathBuf>,
    },
    /// Run the `RoSE` server daemon.
    Server {
        /// Address to listen on.
        #[arg(long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,

        /// Bootstrap mode: read client cert from stdin, bind random port,
        /// print `ROSE_BOOTSTRAP` line to stdout.
        #[arg(long)]
        bootstrap: bool,

        /// Hostnames to include in the server certificate's Subject Alternative Names.
        /// Defaults to "localhost". Add your server's hostname or IP for proper
        /// TLS hostname verification in native mode.
        #[arg(long)]
        hostname: Vec<String>,
    },
    /// Generate X.509 client certificates for authentication.
    Keygen,
}

/// Parses CLI arguments and runs the appropriate subcommand.
///
/// This is the main entry point for the `rose` binary. Call this from
/// a `#[tokio::main]` function.
///
/// # Errors
///
/// Returns an error if the subcommand fails.
///
/// COVERAGE: CLI entry point; logic tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect {
            host,
            port,
            cert,
            ssh,
            server_binary,
            force_stun,
            ssh_port,
            ssh_option,
            client_cert,
        } => {
            if ssh {
                ssh_bootstrap::run_ssh_bootstrap(
                    &host,
                    &server_binary,
                    force_stun,
                    ssh_port,
                    &ssh_option,
                )
                .await
            } else {
                client::run_client(&host, port, cert, client_cert).await
            }
        }
        Commands::Server {
            listen,
            bootstrap,
            hostname,
        } => server::run_server(listen, bootstrap, hostname).await,
        Commands::Keygen => keygen::run_keygen(),
    }
}
