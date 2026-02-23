//! CLI entry point for the `rose` binary.
//!
//! This module contains all command-line parsing, server/client loop logic,
//! and SSH bootstrap mode. The actual binary is a thin wrapper that calls
//! [`run`].

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use crossterm::event::{Event, KeyCode, KeyModifiers};
use crossterm::terminal;

use crate::config::{self, CertKeyPair, RosePaths};
use crate::protocol::{self, ClientSession, ControlMessage, ServerSession};
use crate::pty::PtySession;
use crate::scrollback::{self, ScrollbackLine, ScrollbackReceiver, ScrollbackSender};
use crate::session::{DetachedSession, SessionStore};
use crate::ssp::{
    DATAGRAM_KEYSTROKE, DATAGRAM_SSP_ACK, ScreenState, SspFrame, SspReceiver, SspSender,
    render_diff_ansi, render_full_redraw,
};
use crate::terminal::RoseTerminal;
use crate::transport::{QuicClient, QuicServer};

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

        /// Bootstrap mode: print connection info to stdout, exit when stdin closes.
        #[arg(long)]
        bootstrap: bool,

        /// Ephemeral mode: exit when all sessions disconnect (used with `--bootstrap`).
        #[arg(long)]
        ephemeral: bool,
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
                run_ssh_bootstrap(&host, &server_binary, force_stun, ssh_port, &ssh_option).await
            } else {
                run_client(&host, port, cert, client_cert).await
            }
        }
        Commands::Server {
            listen,
            bootstrap,
            ephemeral,
        } => run_server(listen, bootstrap, ephemeral).await,
        Commands::Keygen => run_keygen(),
    }
}

/// Sends an SSP frame as a QUIC datagram, falling back to a uni stream for
/// oversized frames. Returns `false` if the datagram send failed (connection
/// likely dead).
///
/// COVERAGE: CLI helper tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
fn send_ssp_frame(frame: &SspFrame, conn: &quinn::Connection) -> bool {
    let data = frame.encode();
    let max_dgram = conn.max_datagram_size().unwrap_or(1200);
    if data.len() <= max_dgram {
        conn.send_datagram(Bytes::from(data)).is_ok()
    } else {
        // Oversized frame: send via reliable uni stream
        let stream_data = frame.encode_for_stream();
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Ok(mut stream) = conn.open_uni().await {
                let _ = stream
                    .write_all(&[scrollback::stream_type::SSP_FRAME])
                    .await;
                let _ = stream.write_all(&stream_data).await;
                let _ = stream.finish();
            }
        });
        true
    }
}

/// COVERAGE: CLI server loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_server(listen: SocketAddr, bootstrap: bool, ephemeral: bool) -> anyhow::Result<()> {
    let server = if bootstrap {
        // Bootstrap mode: read the client's public cert from stdin (sent by the client
        // over the authenticated SSH channel), then bind with mutual TLS requiring it.
        // The client's private key never leaves the client.
        use std::io::BufRead;

        let mut client_cert_hex = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut client_cert_hex)
            .map_err(|e| anyhow::anyhow!("failed to read client cert from stdin: {e}"))?;
        let client_cert_der = hex_decode(client_cert_hex.trim())?;

        // Use persistent server cert (same as native mode).
        let paths = RosePaths::resolve();
        std::fs::create_dir_all(&paths.config_dir)?;
        let cert_path = paths.config_dir.join("server.crt");
        let key_path = paths.config_dir.join("server.key");
        let server_cert = if cert_path.exists() && key_path.exists() {
            let cert_der_bytes = std::fs::read(&cert_path)?;
            let key_der = std::fs::read(&key_path)?;
            CertKeyPair {
                cert_pem: String::new(),
                key_pem: String::new(),
                cert_der: rustls::pki_types::CertificateDer::from(cert_der_bytes),
                key_der,
            }
        } else {
            let cert = config::generate_self_signed_cert(&["localhost".to_string()])?;
            std::fs::write(&cert_path, cert.cert_der.as_ref())?;
            std::fs::write(&key_path, &cert.key_der)?;
            cert
        };

        // Write the client cert to a temp dir for mutual TLS authorization
        let auth_dir = std::env::temp_dir().join(format!("rose-bootstrap-{}", std::process::id()));
        std::fs::create_dir_all(&auth_dir)?;
        std::fs::write(auth_dir.join("bootstrap-client.crt"), &client_cert_der)?;

        // Try random ports in the mosh range (60000-61000) with mutual TLS
        let mut bound = None;
        for _ in 0..100 {
            let port = 60000 + (rand_u16() % 1000);
            let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
            match QuicServer::bind_mutual_tls(addr, server_cert.clone(), &auth_dir) {
                Ok(s) => {
                    bound = Some(s);
                    break;
                }
                Err(_) => continue,
            }
        }
        // Clean up temp dir (server already loaded the certs)
        let _ = std::fs::remove_dir_all(&auth_dir);

        let server =
            bound.ok_or_else(|| anyhow::anyhow!("failed to bind to any port in 60000-61000"))?;

        let addr = server.local_addr()?;
        // Print server cert only — client already has its own keypair
        let server_cert_hex = hex_encode(server.server_cert_der().as_ref());
        println!(
            "ROSE_BOOTSTRAP {port} {server_cert_hex}",
            port = addr.port()
        );

        server
    } else {
        // Native mode: reuse existing server cert if available, otherwise
        // generate one. Generating a new cert on every startup would
        // invalidate clients' TOFU cache.
        let paths = RosePaths::resolve();
        std::fs::create_dir_all(&paths.config_dir)?;
        let cert_path = paths.config_dir.join("server.crt");
        let key_path = paths.config_dir.join("server.key");

        let cert = if cert_path.exists() && key_path.exists() {
            let cert_der_bytes = std::fs::read(&cert_path)?;
            let key_der = std::fs::read(&key_path)?;
            eprintln!("Loaded existing certificate from {}", cert_path.display());
            CertKeyPair {
                cert_pem: String::new(),
                key_pem: String::new(),
                cert_der: rustls::pki_types::CertificateDer::from(cert_der_bytes),
                key_der,
            }
        } else {
            let cert = config::generate_self_signed_cert(&["localhost".to_string()])?;
            std::fs::write(&cert_path, cert.cert_der.as_ref())?;
            std::fs::write(&key_path, &cert.key_der)?;
            eprintln!("Generated new certificate at {}", cert_path.display());
            cert
        };

        QuicServer::bind_with_cert(listen, cert)?
    };

    let addr = server.local_addr()?;

    if !bootstrap {
        eprintln!("RoSE server listening on {addr}");
    }

    let store = SessionStore::new();

    if ephemeral {
        // Ephemeral mode: accept one session and exit when the shell exits.
        // The SSH connection that spawned us is killed by the client after
        // the bootstrap handshake — we don't depend on it staying alive.

        // In bootstrap mode, watch stdin for STUN hole-punch requests.
        if bootstrap {
            let punch_server = server.clone_for_punch();
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let stdin = tokio::io::stdin();
                let mut reader = tokio::io::BufReader::new(stdin);
                let mut line = String::new();
                match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line))
                    .await
                {
                    Ok(Ok(n)) if n > 0 => {
                        if let Ok(client_addr) = parse_stun_line(line.trim()) {
                            tracing::info!(%client_addr, "STUN hole-punch requested");
                            punch_server.punch_hole(client_addr);
                        }
                    }
                    _ => {}
                }
            });
        }

        let Some(conn) = server.accept().await? else {
            return Ok(());
        };
        let peer = conn.remote_address();
        tracing::info!(%peer, "bootstrap connection");

        let session_result = handle_server_session(conn, store).await;
        if let Err(e) = session_result {
            tracing::error!(%peer, "session error: {e}");
        }
    } else {
        loop {
            let Some(conn) = server.accept().await? else {
                break;
            };
            let peer = conn.remote_address();
            tracing::info!(%peer, "new connection");

            let store = store.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_server_session(conn, store).await {
                    tracing::error!(%peer, "session error: {e}");
                }
            });
        }
    }

    Ok(())
}

/// Loads the persistent client certificate from `~/.config/rose/`, or
/// generates one if it doesn't exist yet. The same cert is used for all
/// connection modes (native, bootstrap, reattach).
///
/// Cert and key are stored as DER files alongside the PEM files that
/// `rose keygen` generates.
///
/// COVERAGE: CLI helper tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
fn load_or_generate_client_cert() -> anyhow::Result<CertKeyPair> {
    let paths = RosePaths::resolve();
    std::fs::create_dir_all(&paths.config_dir)?;
    let cert_der_path = paths.config_dir.join("client.crt.der");
    let key_der_path = paths.config_dir.join("client.key.der");

    if cert_der_path.exists() && key_der_path.exists() {
        let cert_der_bytes = std::fs::read(&cert_der_path)?;
        let key_der = std::fs::read(&key_der_path)?;
        Ok(CertKeyPair {
            cert_pem: String::new(),
            key_pem: String::new(),
            cert_der: rustls::pki_types::CertificateDer::from(cert_der_bytes),
            key_der,
        })
    } else {
        let cert = config::generate_self_signed_cert(&["localhost".to_string()])?;
        // Save DER for fast loading
        std::fs::write(&cert_der_path, cert.cert_der.as_ref())?;
        std::fs::write(&key_der_path, &cert.key_der)?;
        // Also save PEM for human readability / interop
        std::fs::write(paths.config_dir.join("client.crt"), &cert.cert_pem)?;
        std::fs::write(paths.config_dir.join("client.key"), &cert.key_pem)?;
        eprintln!(
            "Generated client certificate at {}",
            cert_der_path.display()
        );
        Ok(cert)
    }
}

/// Generates a pseudo-random u16 for port selection.
///
/// COVERAGE: Thin wrapper for bootstrap port randomization.
#[cfg_attr(coverage_nightly, coverage(off))]
fn rand_u16() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch");
    (now.subsec_nanos() % 65536) as u16
}

/// Hex-encodes a byte slice.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses a `ROSE_BOOTSTRAP` line from the server's stdout.
///
/// Expected format: `ROSE_BOOTSTRAP <port> <server_cert_hex>`
///
/// # Errors
///
/// Returns an error if the line is malformed.
fn parse_bootstrap_line(line: &str) -> anyhow::Result<(u16, Vec<u8>)> {
    let line = line.trim();
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() != 3 || parts[0] != "ROSE_BOOTSTRAP" {
        anyhow::bail!("invalid bootstrap line: expected ROSE_BOOTSTRAP <port> <server_cert_hex>");
    }
    let port: u16 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid port in bootstrap line: {}", parts[1]))?;
    let server_cert_der = hex_decode(parts[2])?;
    Ok((port, server_cert_der))
}

/// Parses a `ROSE_STUN` line from the client's SSH stdin.
///
/// Expected format: `ROSE_STUN <ip> <port>`
///
/// # Errors
///
/// Returns an error if the line is malformed.
fn parse_stun_line(line: &str) -> anyhow::Result<SocketAddr> {
    let line = line.trim();
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() != 3 || parts[0] != "ROSE_STUN" {
        anyhow::bail!("invalid STUN line: expected ROSE_STUN <ip> <port>");
    }
    let ip: std::net::IpAddr = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IP in STUN line: {}", parts[1]))?;
    let port: u16 = parts[2]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid port in STUN line: {}", parts[2]))?;
    Ok(SocketAddr::new(ip, port))
}

/// Hex-decodes a string to bytes.
fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex string has odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| anyhow::anyhow!("invalid hex at position {i}"))
        })
        .collect()
}

/// COVERAGE: Session handler is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn handle_server_session(conn: quinn::Connection, store: SessionStore) -> anyhow::Result<()> {
    let (mut session, handshake) = ServerSession::accept_any(conn).await?;

    // Generate session ID and resolve PTY/terminal/sender
    let (session_id, pty, terminal, ssp_sender, rows, cols) = match handshake {
        ControlMessage::Hello {
            version: _,
            rows,
            cols,
            env_vars,
        } => {
            let session_id: [u8; 16] = rand_session_id();
            tracing::info!(rows, cols, "new session");

            let pty = PtySession::open_with_env(rows, cols, &env_vars)?;
            let terminal = Arc::new(Mutex::new(RoseTerminal::new(rows, cols)));
            let ssp_sender = Arc::new(Mutex::new(SspSender::new()));

            // Send SessionInfo to client
            session
                .send_control(&ControlMessage::SessionInfo {
                    version: protocol::PROTOCOL_VERSION,
                    session_id,
                })
                .await?;

            (session_id, pty, terminal, ssp_sender, rows, cols)
        }
        ControlMessage::Reconnect {
            version: _,
            rows,
            cols,
            session_id,
            env_vars: _,
        } => {
            tracing::info!(rows, cols, "reconnecting session");

            let detached = store
                .remove(&session_id)
                .ok_or_else(|| anyhow::anyhow!("session not found for reconnect"))?;

            // Resize if client's terminal changed
            if detached.rows != rows || detached.cols != cols {
                let _ = detached.pty.resize(rows, cols);
                detached
                    .terminal
                    .lock()
                    .expect("terminal lock poisoned")
                    .resize(rows, cols);
            }

            // Send SessionInfo to confirm reconnection
            session
                .send_control(&ControlMessage::SessionInfo {
                    version: protocol::PROTOCOL_VERSION,
                    session_id,
                })
                .await?;

            // Reset SSP sender so client gets a full init diff
            {
                let mut sender = detached.ssp_sender.lock().expect("sender lock poisoned");
                *sender = SspSender::new();
            }

            (
                session_id,
                detached.pty,
                detached.terminal,
                detached.ssp_sender,
                rows,
                cols,
            )
        }
        _ => anyhow::bail!("unexpected handshake message"),
    };

    let mut pty_output = pty.subscribe_output();
    let pty_closed = pty.closed();
    let pty_writer = pty.clone_writer();

    // Task: PTY output → terminal → SSP diff → client datagram
    //
    // Sends eagerly: when PTY output arrives, we snapshot and send immediately
    // (subject to a minimum frame interval to avoid flooding during bursts).
    // A background interval ensures retransmission of unacked frames even
    // when no new PTY output arrives.
    let session_conn = session.connection().clone();
    let terminal_out = Arc::clone(&terminal);
    let sender_out = Arc::clone(&ssp_sender);
    let output_task = tokio::spawn(async move {
        let mut dirty = false;
        let mut last_send = tokio::time::Instant::now();
        let min_frame_interval = Duration::from_millis(5);
        let mut retransmit = tokio::time::interval(Duration::from_millis(20));
        // Pin the notified future outside the loop so it persists across
        // iterations. notify_waiters() doesn't store a permit, so a fresh
        // notified() inside select! would miss notifications that fire
        // during the snapshot/send work below.
        let pty_closed_notified = pty_closed.notified();
        tokio::pin!(pty_closed_notified);
        loop {
            tokio::select! {
                result = pty_output.recv() => {
                    match result {
                        Ok(data) => {
                            terminal_out.lock().expect("terminal lock poisoned").advance(&data);
                            dirty = true;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(n, "output subscriber lagged");
                            dirty = true;
                        }
                    }
                }
                _ = retransmit.tick() => {}
                () = &mut pty_closed_notified => break,
            }

            // Send eagerly: snapshot and push state as soon as PTY output
            // arrives, rate-limited to avoid flooding during bursts.
            // Advance and snapshot share one terminal lock; push_state and
            // generate_frame share one sender lock (2 locks instead of 4).
            if dirty && last_send.elapsed() >= min_frame_interval {
                dirty = false;
                let state = terminal_out
                    .lock()
                    .expect("terminal lock poisoned")
                    .snapshot();
                last_send = tokio::time::Instant::now();

                let mut sender = sender_out.lock().expect("sender lock poisoned");
                sender.push_state(state);
                let frame = sender.generate_frame();
                drop(sender);
                if let Some(ref f) = frame
                    && !send_ssp_frame(f, &session_conn)
                {
                    break;
                }
            } else {
                // Retransmit unacked frames even without new PTY output
                let sender = sender_out.lock().expect("sender lock poisoned");
                let frame = sender.generate_frame();
                drop(sender);
                if let Some(ref f) = frame
                    && !send_ssp_frame(f, &session_conn)
                {
                    break;
                }
            }
        }
    });

    // Task: client datagrams → parse prefix → keystroke or ACK
    let input_conn = session.connection().clone();
    let sender_input = Arc::clone(&ssp_sender);
    let input_task = tokio::spawn(async move {
        while let Ok(data) = input_conn.read_datagram().await {
            if data.is_empty() {
                continue;
            }
            match data[0] {
                DATAGRAM_KEYSTROKE => {
                    let mut w = pty_writer.lock().expect("writer lock poisoned");
                    if std::io::Write::write_all(&mut *w, &data[1..]).is_err() {
                        break;
                    }
                    let _ = std::io::Write::flush(&mut *w);
                }
                DATAGRAM_SSP_ACK => {
                    if let Ok(frame) = SspFrame::decode(&data[1..]) {
                        sender_input
                            .lock()
                            .expect("sender lock poisoned")
                            .process_ack(frame.ack_num);
                    }
                }
                _ => {}
            }
        }
    });

    // Task: scrollback sync — periodically sends new scrollback lines via uni stream
    let scrollback_conn = session.connection().clone();
    let terminal_sb = Arc::clone(&terminal);
    let scrollback_task = tokio::spawn(async move {
        let mut sb_sender = ScrollbackSender::new();
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        let mut stream: Option<quinn::SendStream> = None;
        loop {
            interval.tick().await;
            let new_lines = {
                let term = terminal_sb.lock().expect("terminal lock poisoned");
                sb_sender.collect_new_lines(&term)
            };
            if new_lines.is_empty() {
                continue;
            }
            // Open a scrollback stream if we haven't yet
            let s = match &mut stream {
                Some(s) => s,
                None => match scrollback_conn.open_uni().await {
                    Ok(mut s) => {
                        if s.write_all(&[scrollback::stream_type::SCROLLBACK])
                            .await
                            .is_err()
                        {
                            break;
                        }
                        stream = Some(s);
                        stream.as_mut().expect("just assigned")
                    }
                    Err(_) => break,
                },
            };
            // Write each line to the stream
            for line in &new_lines {
                let encoded = line.encode();
                if s.write_all(&encoded).await.is_err() {
                    return;
                }
            }
        }
    });

    // Clone connection for clean close on shell exit
    let close_conn = session.connection().clone();

    // Task: control messages (resize, goodbye) — returns PTY for detaching
    let terminal_ctrl = Arc::clone(&terminal);
    let control_task = tokio::spawn(async move {
        loop {
            match session.recv_control().await {
                Ok(Some(ControlMessage::Resize { rows, cols })) => {
                    tracing::info!(rows, cols, "resize");
                    let _ = pty.resize(rows, cols);
                    terminal_ctrl
                        .lock()
                        .expect("terminal lock poisoned")
                        .resize(rows, cols);
                }
                Ok(Some(ControlMessage::Goodbye) | None) => break,
                Ok(Some(msg)) => {
                    tracing::warn!(?msg, "unexpected control message");
                }
                Err(e) => {
                    tracing::debug!("control stream ended: {e}");
                    break;
                }
            }
        }
        pty
    });

    // Wait for any task to finish (connection lost or session ended).
    // Every exit path except shell exit detaches the session so the client
    // can reconnect later — even if the network just dropped without a
    // Goodbye. The control_task holds the PTY, so we keep its handle
    // alive via `&mut` and await it afterwards to extract the PTY.
    // When control_task itself wins the race, we extract the PTY directly
    // since a JoinHandle cannot be polled after completion.
    let mut control_task = control_task;
    let shell_exited;
    let pty_from_control;
    tokio::select! {
        _ = output_task => {
            shell_exited = true;
            pty_from_control = None;
        },
        _ = input_task => {
            shell_exited = false;
            pty_from_control = None;
        },
        _ = scrollback_task => {
            shell_exited = false;
            pty_from_control = None;
        },
        result = &mut control_task => {
            shell_exited = false;
            pty_from_control = result.ok();
        },
    };

    if shell_exited {
        close_conn.close(0u32.into(), b"shell exited");
    } else {
        // Get PTY for detaching: either already extracted from control_task
        // (if it won the select race), or await it now (it will finish
        // quickly since the connection is dead).
        let pty = match pty_from_control {
            Some(pty) => Some(pty),
            None => tokio::time::timeout(Duration::from_secs(2), control_task)
                .await
                .ok()
                .and_then(Result::ok),
        };
        if let Some(pty) = pty {
            let _ = store.insert(
                session_id,
                DetachedSession {
                    pty,
                    terminal,
                    ssp_sender,
                    rows,
                    cols,
                },
            );
            tracing::info!("session detached, awaiting reconnection");
        }
    }

    Ok(())
}

/// Generates a random 16-byte session ID using system entropy.
///
/// COVERAGE: Thin wrapper around getrandom, tested via integration tests.
#[cfg_attr(coverage_nightly, coverage(off))]
fn rand_session_id() -> [u8; 16] {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Mix process ID, thread ID, and high-precision time for uniqueness.
    // This is not cryptographic but sufficient for session IDs.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch");
    let nanos = now.as_nanos();
    let pid = u128::from(std::process::id());
    let tid = std::thread::current().id();
    let seed = nanos ^ (pid << 32) ^ (format!("{tid:?}").len() as u128);
    seed.to_ne_bytes()
}

/// Collects environment variables to forward from client to server.
///
/// Includes `TERM`, `COLORTERM`, `LANG`, and all `LC_*` locale variables.
/// Defaults `TERM` to `xterm-256color` if unset (matches wezterm-term capabilities).
///
/// COVERAGE: Only called from `client_session_loop` which is excluded from
/// instrumented coverage (tested via e2e tests).
#[cfg_attr(coverage_nightly, coverage(off))]
fn collect_env_vars() -> Vec<(String, String)> {
    let mut vars = Vec::new();

    // TERM — default to xterm-256color if not set
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    vars.push(("TERM".to_string(), term));

    for key in ["COLORTERM", "LANG"] {
        if let Ok(val) = std::env::var(key) {
            vars.push((key.to_string(), val));
        }
    }

    // All LC_* locale variables
    for (key, val) in std::env::vars() {
        if key.starts_with("LC_") {
            vars.push((key, val));
        }
    }

    vars
}

/// COVERAGE: CLI client loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_client(
    host: &str,
    port: u16,
    cert_path: Option<PathBuf>,
    client_cert_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    // Load server certificate
    let cert_path = cert_path.unwrap_or_else(|| {
        let paths = RosePaths::resolve();
        paths.known_hosts_dir.join(format!("{host}.crt"))
    });
    let cert_der = std::fs::read(&cert_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read server cert at {}: {e}\nHint: copy the server's cert file here, or use --cert to specify a path",
            cert_path.display()
        )
    })?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert_der);

    // Load client cert for mutual TLS if specified, or auto-load if
    // the persistent client cert exists (for reattaching to bootstrap sessions).
    let client_cert = if let Some(ref path) = client_cert_path {
        let cert_der_bytes = std::fs::read(path)?;
        let key_path = path.with_extension("key.der");
        let key_der = std::fs::read(&key_path).map_err(|e| {
            anyhow::anyhow!("failed to read client key at {}: {e}", key_path.display())
        })?;
        Some(CertKeyPair {
            cert_pem: String::new(),
            key_pem: String::new(),
            cert_der: rustls::pki_types::CertificateDer::from(cert_der_bytes),
            key_der,
        })
    } else {
        // Auto-detect: if persistent client cert exists, use it for mutual TLS
        let paths = RosePaths::resolve();
        let auto_cert = paths.config_dir.join("client.crt.der");
        let auto_key = paths.config_dir.join("client.key.der");
        if auto_cert.exists() && auto_key.exists() {
            let cert_der_bytes = std::fs::read(&auto_cert)?;
            let key_der = std::fs::read(&auto_key)?;
            Some(CertKeyPair {
                cert_pem: String::new(),
                key_pem: String::new(),
                cert_der: rustls::pki_types::CertificateDer::from(cert_der_bytes),
                key_der,
            })
        } else {
            None
        }
    };

    let addr: SocketAddr = format!("{host}:{port}").parse().unwrap_or_else(|_| {
        // If host isn't a direct IP, try resolving
        use std::net::ToSocketAddrs;
        format!("{host}:{port}")
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .unwrap_or_else(|| {
                eprintln!("Could not resolve {host}:{port}");
                std::process::exit(1);
            })
    });

    // Enter raw mode before the reconnection loop so it stays active across reconnections
    terminal::enable_raw_mode()?;
    let _raw_guard = RawModeGuard;

    client_session_loop(addr, &cert_der, client_cert.as_ref()).await
}

/// Marker that STUN was used for the initial connection.
///
/// When present in the reconnection loop, each reconnect attempt redoes
/// STUN discovery (the NAT mapping is lost when the network changes).
/// SSH is already killed at this point — STUN reconnection sends punch
/// packets from the server's existing endpoint, which already has the
/// firewall pinhole from the initial connection.
struct StunReconnectContext {}

/// Reconnection loop: connects/reconnects to the server with exponential backoff.
///
/// When `client_cert` is `Some`, mutual TLS is used (for SSH bootstrap mode).
///
/// COVERAGE: CLI client session loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn client_session_loop(
    addr: SocketAddr,
    cert_der: &rustls::pki_types::CertificateDer<'static>,
    client_cert: Option<&CertKeyPair>,
) -> anyhow::Result<()> {
    client_session_loop_inner(addr, cert_der, client_cert, None, None).await
}

/// Like [`client_session_loop`] but uses a pre-established connection for the
/// first iteration. Used when direct QUIC connect already succeeded.
///
/// COVERAGE: CLI client session loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn client_session_loop_with_conn(
    first_conn: quinn::Connection,
    addr: SocketAddr,
    cert_der: &rustls::pki_types::CertificateDer<'static>,
    client_cert: Option<&CertKeyPair>,
) -> anyhow::Result<()> {
    client_session_loop_inner(addr, cert_der, client_cert, Some(first_conn), None).await
}

/// Like [`client_session_loop`] but uses a pre-created [`QuicClient`] for the
/// first connection and enables STUN-based reconnection via `stun_ctx`.
///
/// COVERAGE: CLI client session loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn client_session_loop_with_client(
    first_client: QuicClient,
    addr: SocketAddr,
    cert_der: &rustls::pki_types::CertificateDer<'static>,
    client_cert: Option<&CertKeyPair>,
    stun_ctx: StunReconnectContext,
) -> anyhow::Result<()> {
    let conn = if let Some(cc) = client_cert {
        first_client
            .connect_with_cert(addr, "localhost", cert_der, cc)
            .await?
    } else {
        first_client.connect(addr, "localhost", cert_der).await?
    };
    client_session_loop_inner(addr, cert_der, client_cert, Some(conn), Some(stun_ctx)).await
}

/// Performs STUN discovery for reconnection, returning a [`QuicClient`]
/// with the STUN-mapped socket.
///
/// SSH is already dead at this point. The server's firewall pinhole from
/// the initial connection (or previous reconnect) should still allow
/// return traffic. We just need a fresh NAT mapping on the client side.
///
/// COVERAGE: Requires real STUN server; tested via e2e.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn stun_reconnect() -> anyhow::Result<QuicClient> {
    // STUN discovery is blocking I/O
    let (socket, public_addr) = tokio::task::spawn_blocking(|| {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let public_addr = crate::stun::stun_discover(&socket)?;
        Ok::<_, anyhow::Error>((socket, public_addr))
    })
    .await??;

    tracing::info!(%public_addr, "STUN rediscovered for reconnect");

    QuicClient::from_socket(socket).map_err(Into::into)
}

/// Core reconnection loop. If `first_conn` is provided, skips the connect
/// phase for the first iteration. If `stun_ctx` is provided, uses STUN
/// hole-punching for reconnection instead of direct connect.
///
/// COVERAGE: CLI client session loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn client_session_loop_inner(
    addr: SocketAddr,
    cert_der: &rustls::pki_types::CertificateDer<'static>,
    client_cert: Option<&CertKeyPair>,
    first_conn: Option<quinn::Connection>,
    stun_ctx: Option<StunReconnectContext>,
) -> anyhow::Result<()> {
    let mut session_id: Option<[u8; 16]> = None;
    let mut backoff = Duration::from_millis(100);
    let mut initial_conn = first_conn;
    /// Max retries before giving up on the initial connection.
    /// Once a session is established, retries are unlimited (reconnection).
    const MAX_INITIAL_RETRIES: u32 = 5;
    let mut initial_retries: u32 = 0;

    // Long-lived stdin reader: sends crossterm events through a channel
    // that survives across reconnection attempts, so the user can always
    // type Enter~. to quit — even during backoff or connection attempts.
    let (key_tx, key_rx) = tokio::sync::mpsc::unbounded_channel();
    let key_rx = Arc::new(tokio::sync::Mutex::new(key_rx));
    std::thread::spawn(move || {
        while let Ok(event) = crossterm::event::read() {
            if key_tx.send(event).is_err() {
                break;
            }
        }
    });

    loop {
        // On initial connection (no session yet), give up after MAX_INITIAL_RETRIES.
        // Once a session is established, retry indefinitely (reconnection).
        if session_id.is_none() && initial_conn.is_none() {
            initial_retries += 1;
            if initial_retries > MAX_INITIAL_RETRIES {
                let mut stdout = std::io::stdout();
                let _ = stdout.write_all(b"\r\n[RoSE: could not connect to server, giving up]\r\n");
                let _ = stdout.flush();
                anyhow::bail!("failed to connect after {MAX_INITIAL_RETRIES} attempts");
            }
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(
                format!(
                    "\r\n[RoSE: connection failed, retrying ({initial_retries}/{MAX_INITIAL_RETRIES})...]\r\n"
                )
                .as_bytes(),
            );
            let _ = stdout.flush();
        }

        // If we have a pre-established connection (first iteration after
        // bootstrap), use it directly. Otherwise, create a fresh endpoint
        // so the UDP socket survives network interface changes.
        let conn = if let Some(conn) = initial_conn.take() {
            backoff = Duration::from_millis(100);
            conn
        } else if stun_ctx.is_some() {
            // STUN was required — redo STUN for reconnection
            match stun_reconnect().await {
                Ok(client) => {
                    let conn_result = tokio::time::timeout(Duration::from_secs(5), async {
                        if let Some(cc) = client_cert {
                            client
                                .connect_with_cert(addr, "localhost", cert_der, cc)
                                .await
                        } else {
                            client.connect(addr, "localhost", cert_der).await
                        }
                    })
                    .await;
                    match conn_result {
                        Ok(Ok(c)) => {
                            backoff = Duration::from_millis(100);
                            c
                        }
                        Ok(Err(e)) => {
                            tracing::debug!(?backoff, "STUN reconnect failed: {e}");
                            if wait_or_disconnect(&key_rx, backoff).await {
                                let mut stdout = std::io::stdout();
                                let _ = stdout.write_all(b"\r\n[RoSE: disconnected]\r\n");
                                let _ = stdout.flush();
                                break Ok(());
                            }
                            backoff = (backoff * 2).min(Duration::from_secs(5));
                            continue;
                        }
                        Err(_) => {
                            tracing::debug!(?backoff, "STUN reconnect timed out");
                            if wait_or_disconnect(&key_rx, backoff).await {
                                let mut stdout = std::io::stdout();
                                let _ = stdout.write_all(b"\r\n[RoSE: disconnected]\r\n");
                                let _ = stdout.flush();
                                break Ok(());
                            }
                            backoff = (backoff * 2).min(Duration::from_secs(5));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(?backoff, "STUN rediscovery failed: {e}");
                    if wait_or_disconnect(&key_rx, backoff).await {
                        let mut stdout = std::io::stdout();
                        let _ = stdout.write_all(b"\r\n[RoSE: disconnected]\r\n");
                        let _ = stdout.flush();
                        break Ok(());
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
            }
        } else {
            let client = match QuicClient::new() {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(?backoff, "failed to create endpoint: {e}");
                    if wait_or_disconnect(&key_rx, backoff).await {
                        let mut stdout = std::io::stdout();
                        let _ = stdout.write_all(b"\r\n[RoSE: disconnected]\r\n");
                        let _ = stdout.flush();
                        break Ok(());
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
            };
            let conn_result = tokio::time::timeout(Duration::from_secs(5), async {
                if let Some(cc) = client_cert {
                    client
                        .connect_with_cert(addr, "localhost", cert_der, cc)
                        .await
                } else {
                    client.connect(addr, "localhost", cert_der).await
                }
            })
            .await;
            match conn_result {
                Ok(Ok(c)) => {
                    backoff = Duration::from_millis(100);
                    c
                }
                Ok(Err(e)) => {
                    tracing::debug!(?backoff, "connection failed: {e}");
                    if wait_or_disconnect(&key_rx, backoff).await {
                        let mut stdout = std::io::stdout();
                        let _ = stdout.write_all(b"\r\n[RoSE: disconnected]\r\n");
                        let _ = stdout.flush();
                        break Ok(());
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
                Err(_) => {
                    tracing::debug!(?backoff, "connection timed out");
                    if wait_or_disconnect(&key_rx, backoff).await {
                        let mut stdout = std::io::stdout();
                        let _ = stdout.write_all(b"\r\n[RoSE: disconnected]\r\n");
                        let _ = stdout.flush();
                        break Ok(());
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
            }
        };

        let (cols, rows) = terminal::size()?;
        let env = collect_env_vars();
        let mut session = if let Some(sid) = session_id {
            match ClientSession::reconnect(conn, rows, cols, sid, env).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(?backoff, "reconnect handshake failed: {e}");
                    if wait_or_disconnect(&key_rx, backoff).await {
                        let mut stdout = std::io::stdout();
                        let _ = stdout.write_all(b"\r\n[RoSE: disconnected]\r\n");
                        let _ = stdout.flush();
                        break Ok(());
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
            }
        } else {
            ClientSession::connect(conn, rows, cols, env).await?
        };

        // Read SessionInfo from server (with timeout to avoid hanging)
        match tokio::time::timeout(Duration::from_secs(5), session.recv_control()).await {
            Ok(Ok(Some(ControlMessage::SessionInfo {
                version: _,
                session_id: sid,
            }))) => {
                session_id = Some(sid);
            }
            Ok(Ok(Some(other))) => {
                anyhow::bail!("expected SessionInfo, got {other:?}");
            }
            Ok(Ok(None) | Err(_)) | Err(_) => {
                tracing::debug!(?backoff, "handshake timed out");
                if wait_or_disconnect(&key_rx, backoff).await {
                    let mut stdout = std::io::stdout();
                    let _ = stdout.write_all(b"\r\n[RoSE: disconnected]\r\n");
                    let _ = stdout.flush();
                    break Ok(());
                }
                backoff = (backoff * 2).min(Duration::from_secs(5));
                continue;
            }
        }

        if session_id.is_some() && backoff > Duration::from_millis(100) {
            tracing::info!("reconnected");
        } else {
            tracing::info!("connected");
        }

        // Clear screen + scrollback so SSP rendering starts clean
        {
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(b"\x1b[3J\x1b[2J\x1b[H");
            let _ = stdout.flush();
        }

        // Fresh SSP state each connection (server resets SspSender on reconnect)
        let receiver = Arc::new(Mutex::new(SspReceiver::new(rows)));
        // Tracks what's on the user's screen as a plain ScreenState.
        // We diff the incoming SSP state against this to generate minimal
        // ANSI output. Using ScreenState instead of a wezterm terminal
        // avoids an expensive snapshot + advance round-trip per frame.
        let client_screen = Arc::new(Mutex::new(ScreenState::empty(rows)));

        // Scrollback state shared between stream reader and SSP renderer
        let scrollback_rx = Arc::new(Mutex::new(ScrollbackReceiver::new()));
        let rendered_sb_count = Arc::new(Mutex::new(0usize));

        // Task: receive SSP frames via datagrams → apply diff → render
        let output_conn = session.connection().clone();
        let recv_dgram = Arc::clone(&receiver);
        let client_dgram = Arc::clone(&client_screen);
        let sb_rx_dgram = Arc::clone(&scrollback_rx);
        let sb_count_dgram = Arc::clone(&rendered_sb_count);
        let output_task = tokio::spawn(async move {
            let mut sb_check = tokio::time::interval(Duration::from_millis(200));
            loop {
                tokio::select! {
                    result = output_conn.read_datagram() => {
                        match result {
                            Ok(data) => {
                                // Drain all queued datagrams and keep only the
                                // newest frame (highest new_num). Each frame from
                                // the server diffs from the last ACK'd state, so
                                // a newer frame subsumes all older ones.
                                let mut best = SspFrame::decode(&data).ok();
                                while let Ok(Ok(more)) = tokio::time::timeout(
                                    Duration::ZERO,
                                    output_conn.read_datagram(),
                                ).await {
                                    if let Ok(frame) = SspFrame::decode(&more) {
                                        match &best {
                                            Some(b) if frame.new_num <= b.new_num => {}
                                            _ => best = Some(frame),
                                        }
                                    }
                                }
                                if let Some(ref frame) = best {
                                    process_ssp_frame(
                                        frame,
                                        &recv_dgram,
                                        &client_dgram,
                                        &output_conn,
                                        &sb_rx_dgram,
                                        &sb_count_dgram,
                                    );
                                }
                            }
                            Err(e) => return e,
                        }
                    }
                    _ = sb_check.tick() => {
                        // Render scrollback even when no SSP frames are arriving
                        // (e.g., idle terminal after a burst of output)
                        maybe_render_scrollback(
                            &recv_dgram,
                            &client_dgram,
                            &sb_rx_dgram,
                            &sb_count_dgram,
                        );
                    }
                }
            }
        });

        // Task: receive uni streams (oversized SSP frames and scrollback)
        let stream_conn = session.connection().clone();
        let recv_stream = Arc::clone(&receiver);
        let client_stream = Arc::clone(&client_screen);
        let sb_rx_stream = Arc::clone(&scrollback_rx);
        let sb_count_stream = Arc::clone(&rendered_sb_count);
        let stream_task = tokio::spawn(async move {
            while let Ok(mut uni) = stream_conn.accept_uni().await {
                // Read type prefix byte
                let mut type_buf = [0u8; 1];
                if uni.read_exact(&mut type_buf).await.is_err() {
                    continue;
                }
                match type_buf[0] {
                    scrollback::stream_type::SSP_FRAME => {
                        // Oversized SSP frame: read length-prefixed frame
                        let mut len_buf = [0u8; 4];
                        if uni.read_exact(&mut len_buf).await.is_err() {
                            continue;
                        }
                        let len = u32::from_be_bytes(len_buf) as usize;
                        match uni.read_to_end(len).await {
                            Ok(data) => {
                                if let Ok(frame) = SspFrame::decode(&data) {
                                    process_ssp_frame(
                                        &frame,
                                        &recv_stream,
                                        &client_stream,
                                        &stream_conn,
                                        &sb_rx_stream,
                                        &sb_count_stream,
                                    );
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    scrollback::stream_type::SCROLLBACK => {
                        // Spawn scrollback reader as a separate task so the
                        // stream accept loop remains free to handle SSP frames.
                        let sb_rx = Arc::clone(&scrollback_rx);
                        tokio::spawn(async move {
                            let mut buf = Vec::new();
                            loop {
                                let mut chunk = vec![0u8; 4096];
                                match uni.read(&mut chunk).await {
                                    Ok(Some(n)) => {
                                        buf.extend_from_slice(&chunk[..n]);
                                        while buf.len() >= 12 {
                                            match ScrollbackLine::decode(&buf) {
                                                Ok((line, consumed)) => {
                                                    sb_rx
                                                        .lock()
                                                        .expect("scrollback lock poisoned")
                                                        .add_line(line);
                                                    buf.drain(..consumed);
                                                }
                                                Err(_) => break,
                                            }
                                        }
                                    }
                                    _ => break,
                                }
                            }
                        });
                    }
                    _ => {
                        tracing::warn!(type_byte = type_buf[0], "unknown uni stream type");
                    }
                }
            }
        });

        // Task: stdin → prefix with 0x00 → send input datagrams
        // Includes SSH-style escape sequence detection: Enter ~ .
        // Reads from the long-lived stdin channel (not spawn_blocking)
        // so the reader thread survives across reconnections.
        let input_conn = session.connection().clone();
        let input_key_rx = Arc::clone(&key_rx);
        /// What the input task decided.
        #[derive(Clone, Copy)]
        enum InputResult {
            Disconnect,
            Detach,
            ConnectionLost,
        }

        let input_task = tokio::spawn(async move {
            let mut escape = EscapeState::Normal;

            /// Sends raw bytes as a keystroke datagram. Returns false if
            /// the connection is broken.
            fn send_keys(conn: &quinn::Connection, bytes: &[u8]) -> bool {
                let mut data = vec![DATAGRAM_KEYSTROKE];
                data.extend_from_slice(bytes);
                conn.send_datagram(Bytes::from(data)).is_ok()
            }

            loop {
                let event = input_key_rx.lock().await.recv().await;
                match event {
                    Some(Event::Key(key)) => {
                        let key_bytes = key_event_to_bytes(&key);
                        if key_bytes.is_empty() {
                            continue;
                        }

                        match escape {
                            EscapeState::Normal => {
                                if key.code == crossterm::event::KeyCode::Enter {
                                    escape = EscapeState::AfterEnter;
                                    if !send_keys(&input_conn, &key_bytes) {
                                        break;
                                    }
                                } else if !send_keys(&input_conn, &key_bytes) {
                                    break;
                                }
                            }
                            EscapeState::AfterEnter => {
                                if key.code == crossterm::event::KeyCode::Char('~') {
                                    // Buffer the tilde — don't send yet
                                    escape = EscapeState::AfterTilde;
                                } else if key.code == crossterm::event::KeyCode::Enter {
                                    // Another Enter — stay in AfterEnter
                                    if !send_keys(&input_conn, &key_bytes) {
                                        break;
                                    }
                                } else {
                                    // Not an escape — send key normally
                                    escape = EscapeState::Normal;
                                    if !send_keys(&input_conn, &key_bytes) {
                                        break;
                                    }
                                }
                            }
                            EscapeState::AfterTilde => {
                                match key.code {
                                    crossterm::event::KeyCode::Char('.') => {
                                        // Enter ~ . → user-initiated disconnect
                                        return InputResult::Disconnect;
                                    }
                                    crossterm::event::KeyCode::Char('d') => {
                                        // Enter ~ d → detach (keep session alive)
                                        return InputResult::Detach;
                                    }
                                    crossterm::event::KeyCode::Char('~') => {
                                        // Enter ~ ~ → send literal ~
                                        escape = EscapeState::Normal;
                                        if !send_keys(&input_conn, b"~") {
                                            break;
                                        }
                                    }
                                    crossterm::event::KeyCode::Char('?') => {
                                        // Enter ~ ? → show escape help
                                        let mut stdout = std::io::stdout();
                                        let _ = stdout.write_all(
                                            b"\r\nSupported escape sequences:\r\n\
                                              \x20 ~.  - disconnect\r\n\
                                              \x20 ~d  - detach (session stays alive)\r\n\
                                              \x20 ~~  - send literal ~\r\n\
                                              \x20 ~?  - this help\r\n",
                                        );
                                        let _ = stdout.flush();
                                        escape = EscapeState::Normal;
                                    }
                                    _ => {
                                        // Not a recognized escape — flush the
                                        // buffered tilde and send current key
                                        escape = EscapeState::Normal;
                                        if !send_keys(&input_conn, b"~") {
                                            break;
                                        }
                                        if !send_keys(&input_conn, &key_bytes) {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some(Event::Resize(_, _)) => {
                        // Resize handled separately below
                    }
                    None => break, // channel closed
                    _ => {}
                }
            }
            InputResult::ConnectionLost
        });

        // Clone connection for checking close reason after the main select
        let check_conn = session.connection().clone();

        // Task: resize events + server control messages (Goodbye)
        // Returns true if the server sent Goodbye (shell exited).
        let control_task = tokio::spawn(async move {
            let mut last_size = (cols, rows);
            let mut resize_interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                tokio::select! {
                    _ = resize_interval.tick() => {
                        if let Ok(new_size) = terminal::size()
                            && new_size != last_size
                        {
                            last_size = new_size;
                            let msg = ControlMessage::Resize {
                                rows: new_size.1,
                                cols: new_size.0,
                            };
                            if session.send_control(&msg).await.is_err() {
                                break;
                            }
                        }
                    }
                    msg = session.recv_control() => {
                        match msg {
                            Ok(Some(ControlMessage::Goodbye)) => return true,
                            Ok(None) | Err(_) => break,
                            Ok(Some(_)) => {}
                        }
                    }
                }
            }
            false
        });

        enum SessionExit {
            ShellExited,
            UserDisconnect,
            UserDetach,
            ConnectionLost,
        }

        let exit = tokio::select! {
            _ = output_task => SessionExit::ConnectionLost,
            _ = stream_task => SessionExit::ConnectionLost,
            result = input_task => {
                match result.ok().unwrap_or(InputResult::ConnectionLost) {
                    InputResult::Disconnect => SessionExit::UserDisconnect,
                    InputResult::Detach => SessionExit::UserDetach,
                    InputResult::ConnectionLost => SessionExit::ConnectionLost,
                }
            },
            result = control_task => {
                if result.unwrap_or(false) {
                    SessionExit::UserDisconnect
                } else {
                    SessionExit::ConnectionLost
                }
            },
        };

        // When the server closes the connection gracefully (shell exited),
        // any task may win the select race. Check the connection's close
        // reason regardless of which task finished first.
        let exit = match exit {
            SessionExit::ConnectionLost => match check_conn.close_reason() {
                Some(quinn::ConnectionError::ApplicationClosed(ref close))
                    if close.error_code == quinn::VarInt::from_u32(0) =>
                {
                    SessionExit::ShellExited
                }
                _ => SessionExit::ConnectionLost,
            },
            other => other,
        };

        match exit {
            SessionExit::ShellExited => {
                let mut stdout = std::io::stdout();
                let _ = stdout.write_all(b"\r\n[RoSE: shell exited]\r\n");
                let _ = stdout.flush();
                break Ok(());
            }
            SessionExit::UserDisconnect => {
                let mut stdout = std::io::stdout();
                let _ = stdout.write_all(b"\r\n[RoSE: disconnected]\r\n");
                let _ = stdout.flush();
                break Ok(());
            }
            SessionExit::UserDetach => {
                let mut stdout = std::io::stdout();
                let _ = stdout.write_all(
                    format!(
                        "\r\n[RoSE: detached]\r\n\
                         [RoSE: to reattach, run: rose connect {} --port {}]\r\n",
                        addr.ip(),
                        addr.port()
                    )
                    .as_bytes(),
                );
                let _ = stdout.flush();
                break Ok(());
            }
            SessionExit::ConnectionLost => {
                tracing::debug!("connection lost, reconnecting");
            }
        }
    }
}

/// SSH bootstrap mode: generates an ephemeral client cert, spawns
/// `ssh <host> rose server --bootstrap --ephemeral`, sends the client's
/// public cert over stdin, parses the `ROSE_BOOTSTRAP` line, then connects
/// QUIC directly to the host with mutual TLS.
///
/// If the direct QUIC connection fails (e.g., server's UDP port is
/// firewalled), falls back to STUN-based NAT hole-punching: discovers
/// the client's public address via STUN, tells the server over SSH stdin,
/// and the server sends packets to open its firewall for return traffic.
///
/// The client's private key never leaves this process.
///
/// COVERAGE: CLI bootstrap mode is tested via unit tests for parsing.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_ssh_bootstrap(
    host: &str,
    server_binary: &str,
    force_stun: bool,
    ssh_port: Option<u16>,
    ssh_options: &[String],
) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    // Load or generate persistent client cert from ~/.config/rose/.
    // The same cert is used for all connections (bootstrap, native, reattach).
    let client_cert = load_or_generate_client_cert()?;

    eprintln!("Starting SSH bootstrap to {host}...");

    let mut cmd = tokio::process::Command::new("ssh");
    if let Some(port) = ssh_port {
        cmd.arg("-p").arg(port.to_string());
    }
    for opt in ssh_options {
        cmd.arg("-o").arg(opt);
    }
    let mut ssh = cmd
        .arg(host)
        .arg("nohup")
        .arg(server_binary)
        .arg("server")
        .arg("--bootstrap")
        .arg("--ephemeral")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn ssh: {e}"))?;

    // Send client's public cert to the server over the SSH channel
    {
        let stdin = ssh
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("failed to capture ssh stdin"))?;
        let cert_hex = hex_encode(client_cert.cert_der.as_ref());
        stdin.write_all(cert_hex.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
    }

    let stdout = ssh
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture ssh stdout"))?;
    let mut reader = tokio::io::BufReader::new(stdout);
    let mut line = String::new();

    tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut line))
        .await
        .map_err(|_| anyhow::anyhow!("timeout waiting for ROSE_BOOTSTRAP line"))?
        .map_err(|e| anyhow::anyhow!("failed to read bootstrap line: {e}"))?;

    let (port, server_cert_der) = parse_bootstrap_line(&line)?;
    eprintln!("Bootstrap: server on port {port}");

    let server_cert_der = rustls::pki_types::CertificateDer::from(server_cert_der);

    // Resolve the actual hostname via `ssh -G` since the user may be using
    // an SSH config alias (Host) that isn't a real DNS name.
    let resolved_host = resolve_ssh_hostname(host).await?;
    let addr: SocketAddr = {
        use std::net::ToSocketAddrs;
        let addrs: Vec<SocketAddr> = format!("{resolved_host}:{port}")
            .to_socket_addrs()
            .map(Iterator::collect)
            .unwrap_or_default();
        // Prefer IPv4 — STUN fallback only discovers IPv4 mappings, and an
        // IPv4 socket can't connect to an IPv6 address.
        addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs.first())
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "could not resolve {resolved_host}:{port} (from ssh config for {host})"
                )
            })?
    };

    // Save server cert to known_hosts so direct reconnection (reattach) works.
    let paths = RosePaths::resolve();
    std::fs::create_dir_all(&paths.known_hosts_dir)?;
    std::fs::write(
        paths.known_hosts_dir.join(format!("{}.crt", addr.ip())),
        server_cert_der.as_ref(),
    )?;

    // Start STUN discovery in parallel with direct connect attempt.
    // If direct succeeds, we discard the STUN result. If direct fails,
    // we use it for hole-punching.
    let stun_handle = tokio::task::spawn_blocking(|| {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let public_addr = crate::stun::stun_discover(&socket)?;
        Ok::<_, anyhow::Error>((socket, public_addr))
    });

    // Try direct QUIC connection first (3s timeout), unless --force-stun.
    // We return both the connection AND the client — dropping the client
    // would close the endpoint and kill all connections on it.
    let direct_result = if force_stun {
        eprintln!("[RoSE: --force-stun: skipping direct attempt]");
        None
    } else {
        Some(
            tokio::time::timeout(Duration::from_secs(3), async {
                let client = QuicClient::new()?;
                let conn = client
                    .connect_with_cert(addr, "localhost", &server_cert_der, &client_cert)
                    .await?;
                Ok::<_, crate::transport::TransportError>((client, conn))
            })
            .await,
        )
    };

    let use_stun = match &direct_result {
        Some(Ok(Ok(_))) => false,
        Some(Ok(Err(e))) => {
            tracing::debug!("direct connection failed: {e}");
            true
        }
        Some(Err(_)) => {
            tracing::debug!("direct connection timed out");
            true
        }
        None => true, // --force-stun
    };

    // If STUN is needed, send ROSE_STUN to the server over SSH stdin.
    let stun_socket = if use_stun {
        eprintln!("[RoSE: direct UDP failed, trying STUN hole-punch...]");

        match stun_handle.await {
            Ok(Ok((stun_socket, public_addr))) => {
                eprintln!("[RoSE: STUN discovered {public_addr}]");

                let stun_msg = format!("ROSE_STUN {} {}\n", public_addr.ip(), public_addr.port());
                if let Some(stdin) = ssh.stdin.as_mut() {
                    let _ = stdin.write_all(stun_msg.as_bytes()).await;
                    let _ = stdin.flush().await;
                }

                // Wait for server to send punch packets
                tokio::time::sleep(Duration::from_millis(500)).await;

                eprintln!(
                    "[RoSE: connected via STUN — roaming may be limited, \
                     consider forwarding UDP 60000-61000]"
                );

                Some(stun_socket)
            }
            Ok(Err(e)) => {
                eprintln!("[RoSE: STUN discovery failed: {e}]");
                anyhow::bail!("direct UDP connection failed and STUN fallback unavailable: {e}");
            }
            Err(e) => {
                anyhow::bail!("STUN discovery task panicked: {e}");
            }
        }
    } else {
        None
    };

    // Kill SSH — nohup keeps the server alive.
    let _ = ssh.kill().await;

    // Enter raw mode and start the session loop
    terminal::enable_raw_mode()?;
    let _raw_guard = RawModeGuard;

    if let Some(stun_socket) = stun_socket {
        let client = QuicClient::from_socket(stun_socket)?;
        client_session_loop_with_client(
            client,
            addr,
            &server_cert_der,
            Some(&client_cert),
            StunReconnectContext {},
        )
        .await
    } else if let Some(Ok(Ok((_client, conn)))) = direct_result {
        // _client must stay alive — dropping it closes the endpoint.
        client_session_loop_with_conn(conn, addr, &server_cert_der, Some(&client_cert)).await
    } else {
        // Direct failed but STUN wasn't available — already bailed above
        unreachable!()
    }
}

/// Resolves an SSH host alias to the actual hostname using `ssh -G`.
///
/// SSH config aliases (e.g., `myserver` mapping to `10.0.0.5` via `HostName`)
/// aren't DNS-resolvable, so we ask SSH what it would actually connect to.
///
/// COVERAGE: Requires SSH to be installed.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn resolve_ssh_hostname(host: &str) -> anyhow::Result<String> {
    let output = tokio::process::Command::new("ssh")
        .arg("-G")
        .arg(host)
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run `ssh -G {host}`: {e}"))?;

    if !output.status.success() {
        anyhow::bail!(
            "`ssh -G {host}` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(hostname) = line.strip_prefix("hostname ") {
            return Ok(hostname.to_string());
        }
    }

    // If ssh -G doesn't have a hostname field, fall back to the original
    Ok(host.to_string())
}

/// Waits for `duration` but returns early if the user types Enter~.
///
/// Used during reconnection backoff so the user can quit even when
/// disconnected. Returns `true` if the user typed Enter~.
///
/// COVERAGE: CLI helper tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn wait_or_disconnect(
    key_rx: &Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Event>>>,
    duration: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + duration;
    let mut escape = EscapeState::Normal;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        tokio::select! {
            event = async { key_rx.lock().await.recv().await } => {
                if let Some(Event::Key(key)) = event {
                    match escape {
                        EscapeState::Normal => {
                            if key.code == KeyCode::Enter {
                                escape = EscapeState::AfterEnter;
                            }
                        }
                        EscapeState::AfterEnter => match key.code {
                            KeyCode::Char('~') => escape = EscapeState::AfterTilde,
                            KeyCode::Enter => {}
                            _ => escape = EscapeState::Normal,
                        },
                        EscapeState::AfterTilde => {
                            if key.code == KeyCode::Char('.') {
                                return true;
                            }
                            escape = EscapeState::Normal;
                        }
                    }
                }
            }
            () = tokio::time::sleep(remaining) => {
                return false;
            }
        }
    }
}

/// Performs a full terminal redraw (scrollback + visible) and resets the
/// client terminal to match.
///
/// COVERAGE: CLI helper tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
fn do_full_redraw(
    scrollback_rx: &Mutex<ScrollbackReceiver>,
    rendered_sb_count: &Mutex<usize>,
    new_state: &ScreenState,
    screen: &mut ScreenState,
) {
    let sb = scrollback_rx.lock().expect("scrollback lock poisoned");
    let mut count = rendered_sb_count
        .lock()
        .expect("rendered count lock poisoned");

    let ansi = render_full_redraw(sb.lines(), new_state);
    *count = sb.len();
    drop(sb);
    drop(count);

    let mut out = std::io::BufWriter::new(std::io::stdout());
    let _ = out.write_all(&ansi);
    let _ = out.flush();

    // Update stored screen state to match what's now on the user's terminal.
    *screen = new_state.clone();
}

/// Checks if scrollback changed and triggers a full redraw if needed.
///
/// Called periodically from the output task so scrollback is rendered
/// even when no SSP frames are arriving (e.g., idle terminal after
/// a burst of output).
///
/// COVERAGE: CLI helper tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
fn maybe_render_scrollback(
    receiver: &Arc<Mutex<SspReceiver>>,
    client_screen: &Arc<Mutex<ScreenState>>,
    scrollback_rx: &Arc<Mutex<ScrollbackReceiver>>,
    rendered_sb_count: &Arc<Mutex<usize>>,
) {
    let needs_redraw = {
        let sb = scrollback_rx.lock().expect("scrollback lock poisoned");
        let count = rendered_sb_count
            .lock()
            .expect("rendered count lock poisoned");
        sb.len() != *count
    };
    if !needs_redraw {
        return;
    }

    let recv = receiver.lock().expect("receiver lock poisoned");
    let state = recv.state().clone();
    drop(recv);

    let mut screen = client_screen.lock().expect("client screen lock poisoned");
    do_full_redraw(scrollback_rx, rendered_sb_count, &state, &mut screen);
}

/// Processes an SSP frame: applies diff, renders to stdout, sends ACK.
///
/// Shared by both the datagram and stream receive paths.
///
/// Uses incremental diff when only the visible screen changed, or a full
/// redraw (with scrollback) when scrollback lines arrived, the terminal
/// resized, or the client reconnected.
///
/// COVERAGE: CLI helper tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
fn process_ssp_frame(
    frame: &SspFrame,
    receiver: &Arc<Mutex<SspReceiver>>,
    client_screen: &Arc<Mutex<ScreenState>>,
    conn: &quinn::Connection,
    scrollback_rx: &Arc<Mutex<ScrollbackReceiver>>,
    rendered_sb_count: &Arc<Mutex<usize>>,
) {
    let mut recv = receiver.lock().expect("receiver lock poisoned");
    match recv.process_frame(frame) {
        Ok(Some(_)) => {
            let new_state = recv.state().clone();
            let mut screen = client_screen.lock().expect("client screen lock poisoned");

            // Determine if a full redraw is needed
            let needs_full_redraw = {
                let sb = scrollback_rx.lock().expect("scrollback lock poisoned");
                let count = rendered_sb_count
                    .lock()
                    .expect("rendered count lock poisoned");
                sb.len() != *count || new_state.rows.len() != screen.rows.len()
            };

            if needs_full_redraw {
                do_full_redraw(scrollback_rx, rendered_sb_count, &new_state, &mut screen);
            } else {
                let ansi = render_diff_ansi(&screen, &new_state);
                let mut out = std::io::BufWriter::new(std::io::stdout());
                let _ = out.write_all(&ansi);
                let _ = out.flush();
                // Update stored screen state to match what's on the user's terminal
                *screen = new_state;
            }

            // Send ACK back to server
            let ack = SspFrame::ack_only(recv.ack_num());
            let mut ack_data = vec![DATAGRAM_SSP_ACK];
            ack_data.extend_from_slice(&ack.encode());
            let _ = conn.send_datagram(Bytes::from(ack_data));
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("SSP frame error: {e}");
        }
    }
}

/// COVERAGE: Keygen is a simple CLI command tested manually.
#[cfg_attr(coverage_nightly, coverage(off))]
fn run_keygen() -> anyhow::Result<()> {
    let paths = RosePaths::resolve();
    std::fs::create_dir_all(&paths.config_dir)?;

    let cert = config::generate_self_signed_cert(&["localhost".to_string()])?;

    // Save PEM (human readable) and DER (fast loading)
    std::fs::write(paths.config_dir.join("client.crt"), &cert.cert_pem)?;
    std::fs::write(paths.config_dir.join("client.key"), &cert.key_pem)?;
    std::fs::write(
        paths.config_dir.join("client.crt.der"),
        cert.cert_der.as_ref(),
    )?;
    std::fs::write(paths.config_dir.join("client.key.der"), &cert.key_der)?;

    eprintln!(
        "Certificate: {}",
        paths.config_dir.join("client.crt").display()
    );
    eprintln!(
        "Private key: {}",
        paths.config_dir.join("client.key").display()
    );

    Ok(())
}

/// RAII guard to restore terminal mode on drop.
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

/// SSH-style escape sequence state machine.
///
/// Detects `Enter ~ .` to disconnect, `Enter ~ ~` to send literal `~`,
/// and `Enter ~ ?` for help.
enum EscapeState {
    /// No escape sequence in progress.
    Normal,
    /// Enter was just pressed — `~` would start an escape.
    AfterEnter,
    /// Enter + `~` were pressed — waiting for `.`, `~`, or `?`.
    AfterTilde,
}

/// Converts a crossterm key event to bytes to send to the PTY.
fn key_event_to_bytes(key: &crossterm::event::KeyEvent) -> Vec<u8> {
    // Ctrl+C
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && let KeyCode::Char(c) = key.code
    {
        // Ctrl+letter maps to ASCII 1-26
        let ctrl_byte = (c as u8).wrapping_sub(b'a').wrapping_add(1);
        return vec![ctrl_byte];
    }

    match key.code {
        KeyCode::Char(c) => {
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            s.as_bytes().to_vec()
        }
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Backspace => vec![127],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => b"\x1b[A".to_vec(),
        KeyCode::Down => b"\x1b[B".to_vec(),
        KeyCode::Right => b"\x1b[C".to_vec(),
        KeyCode::Left => b"\x1b[D".to_vec(),
        KeyCode::Home => b"\x1b[H".to_vec(),
        KeyCode::End => b"\x1b[F".to_vec(),
        KeyCode::PageUp => b"\x1b[5~".to_vec(),
        KeyCode::PageDown => b"\x1b[6~".to_vec(),
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::Insert => b"\x1b[2~".to_vec(),
        KeyCode::F(n) => f_key_escape(n),
        _ => vec![],
    }
}

/// Returns the escape sequence for a function key.
fn f_key_escape(n: u8) -> Vec<u8> {
    match n {
        1 => b"\x1bOP".to_vec(),
        2 => b"\x1bOQ".to_vec(),
        3 => b"\x1bOR".to_vec(),
        4 => b"\x1bOS".to_vec(),
        5 => b"\x1b[15~".to_vec(),
        6 => b"\x1b[17~".to_vec(),
        7 => b"\x1b[18~".to_vec(),
        8 => b"\x1b[19~".to_vec(),
        9 => b"\x1b[20~".to_vec(),
        10 => b"\x1b[21~".to_vec(),
        11 => b"\x1b[23~".to_vec(),
        12 => b"\x1b[24~".to_vec(),
        _ => vec![],
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_roundtrip() {
        let data = b"hello world";
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(b""), "");
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hex_decode_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_invalid_chars() {
        assert!(hex_decode("zzzz").is_err());
    }

    #[test]
    fn parse_bootstrap_valid() {
        let server_cert = b"\x01\x02\x03";
        let line = format!("ROSE_BOOTSTRAP 60123 {}\n", hex_encode(server_cert));
        let (port, der) = parse_bootstrap_line(&line).unwrap();
        assert_eq!(port, 60123);
        assert_eq!(der, server_cert);
    }

    #[test]
    fn parse_bootstrap_missing_prefix() {
        assert!(parse_bootstrap_line("WRONG 60123 aabbcc").is_err());
    }

    #[test]
    fn parse_bootstrap_invalid_port() {
        assert!(parse_bootstrap_line("ROSE_BOOTSTRAP notaport aabbcc").is_err());
    }

    #[test]
    fn parse_bootstrap_too_few_parts() {
        assert!(parse_bootstrap_line("ROSE_BOOTSTRAP 60123").is_err());
    }

    #[test]
    fn parse_bootstrap_empty() {
        assert!(parse_bootstrap_line("").is_err());
    }

    #[test]
    fn parse_stun_line_valid() {
        let addr = parse_stun_line("ROSE_STUN 203.0.113.5 12345").unwrap();
        assert_eq!(addr, "203.0.113.5:12345".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_stun_line_with_whitespace() {
        let addr = parse_stun_line("  ROSE_STUN 10.0.0.1 8080  \n").unwrap();
        assert_eq!(addr, "10.0.0.1:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_stun_line_missing_prefix() {
        assert!(parse_stun_line("WRONG 10.0.0.1 8080").is_err());
    }

    #[test]
    fn parse_stun_line_invalid_ip() {
        assert!(parse_stun_line("ROSE_STUN not_an_ip 8080").is_err());
    }

    #[test]
    fn parse_stun_line_invalid_port() {
        assert!(parse_stun_line("ROSE_STUN 10.0.0.1 notaport").is_err());
    }

    #[test]
    fn parse_stun_line_too_few_parts() {
        assert!(parse_stun_line("ROSE_STUN 10.0.0.1").is_err());
    }

    #[test]
    fn parse_stun_line_empty() {
        assert!(parse_stun_line("").is_err());
    }

    #[test]
    fn parse_bootstrap_invalid_hex() {
        assert!(parse_bootstrap_line("ROSE_BOOTSTRAP 60123 zzzz").is_err());
    }

    #[test]
    fn key_event_ctrl_c() {
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&key), vec![3]); // Ctrl+C = 0x03
    }

    #[test]
    fn key_event_ctrl_a() {
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&key), vec![1]); // Ctrl+A = 0x01
    }

    #[test]
    fn key_event_regular_char() {
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE);
        assert_eq!(key_event_to_bytes(&key), b"x");
    }

    #[test]
    fn key_event_unicode_char() {
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('\u{1f600}'), KeyModifiers::NONE);
        let bytes = key_event_to_bytes(&key);
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "\u{1f600}");
    }

    #[test]
    fn key_event_special_keys() {
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE
            )),
            vec![b'\r']
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Backspace,
                KeyModifiers::NONE
            )),
            vec![127]
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Tab,
                KeyModifiers::NONE
            )),
            vec![b'\t']
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Esc,
                KeyModifiers::NONE
            )),
            vec![0x1b]
        );
    }

    #[test]
    fn key_event_arrow_keys() {
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Up,
                KeyModifiers::NONE
            )),
            b"\x1b[A"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Down,
                KeyModifiers::NONE
            )),
            b"\x1b[B"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Right,
                KeyModifiers::NONE
            )),
            b"\x1b[C"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Left,
                KeyModifiers::NONE
            )),
            b"\x1b[D"
        );
    }

    #[test]
    fn key_event_navigation_keys() {
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Home,
                KeyModifiers::NONE
            )),
            b"\x1b[H"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::End,
                KeyModifiers::NONE
            )),
            b"\x1b[F"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::PageUp,
                KeyModifiers::NONE
            )),
            b"\x1b[5~"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::PageDown,
                KeyModifiers::NONE
            )),
            b"\x1b[6~"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Delete,
                KeyModifiers::NONE
            )),
            b"\x1b[3~"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Insert,
                KeyModifiers::NONE
            )),
            b"\x1b[2~"
        );
    }

    #[test]
    fn key_event_function_keys() {
        assert_eq!(f_key_escape(1), b"\x1bOP");
        assert_eq!(f_key_escape(2), b"\x1bOQ");
        assert_eq!(f_key_escape(3), b"\x1bOR");
        assert_eq!(f_key_escape(4), b"\x1bOS");
        assert_eq!(f_key_escape(5), b"\x1b[15~");
        assert_eq!(f_key_escape(6), b"\x1b[17~");
        assert_eq!(f_key_escape(7), b"\x1b[18~");
        assert_eq!(f_key_escape(8), b"\x1b[19~");
        assert_eq!(f_key_escape(9), b"\x1b[20~");
        assert_eq!(f_key_escape(10), b"\x1b[21~");
        assert_eq!(f_key_escape(11), b"\x1b[23~");
        assert_eq!(f_key_escape(12), b"\x1b[24~");
        assert_eq!(f_key_escape(13), Vec::<u8>::new());
    }

    #[test]
    fn key_event_unknown_returns_empty() {
        let key = crossterm::event::KeyEvent::new(KeyCode::Null, KeyModifiers::NONE);
        assert!(key_event_to_bytes(&key).is_empty());
    }

    #[test]
    fn key_event_f_key_via_key_event() {
        let key = crossterm::event::KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE);
        assert_eq!(key_event_to_bytes(&key), b"\x1bOP");
    }
}
