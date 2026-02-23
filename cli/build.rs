use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

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
        #[arg(long)]
        ssh_option: Vec<String>,

        /// Path to a client certificate for mutual TLS (DER format).
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
    },
    /// Generate X.509 client certificates for authentication.
    Keygen,
}

fn main() -> std::io::Result<()> {
    let Some(out_dir) = std::env::var_os("OUT_DIR") else {
        return Ok(());
    };
    let out_dir = std::path::PathBuf::from(out_dir);

    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd.clone());
    let mut buffer = Vec::new();
    man.render(&mut buffer)?;
    std::fs::write(out_dir.join("rose.1"), buffer)?;

    // Generate subcommand man pages
    for sub in cmd.get_subcommands() {
        let man = clap_mangen::Man::new(sub.clone());
        let mut buffer = Vec::new();
        man.render(&mut buffer)?;
        let name = format!("rose-{}.1", sub.get_name());
        std::fs::write(out_dir.join(name), buffer)?;
    }

    Ok(())
}
