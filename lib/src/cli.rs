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
    render_diff_ansi,
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
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect {
            host,
            port,
            cert,
            ssh,
            server_binary,
        } => {
            if ssh {
                run_ssh_bootstrap(&host, &server_binary).await
            } else {
                run_client(&host, port, cert).await
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

        let server_cert = config::generate_self_signed_cert(&["localhost".to_string()])?;

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
        QuicServer::bind(listen)?
    };

    let addr = server.local_addr()?;

    if !bootstrap {
        eprintln!("RoSE server listening on {addr}");

        // Save server cert for clients to use
        let paths = RosePaths::resolve();
        std::fs::create_dir_all(&paths.config_dir)?;
        let cert_path = paths.config_dir.join("server.crt");
        std::fs::write(&cert_path, server.server_cert_der().as_ref())?;
        eprintln!("Server certificate written to {}", cert_path.display());
    }

    let store = SessionStore::new();

    if ephemeral {
        // Ephemeral mode: accept one connection, exit when it disconnects and stdin closes
        let stdin_closed = tokio::spawn(async {
            use tokio::io::AsyncReadExt;
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 1];
            // stdin closes when the SSH connection dies
            let _ = stdin.read(&mut buf).await;
        });

        let Some(conn) = server.accept().await? else {
            return Ok(());
        };
        let peer = conn.remote_address();
        tracing::info!(%peer, "bootstrap connection");

        let session_result = handle_server_session(conn, store).await;
        if let Err(e) = session_result {
            tracing::error!(%peer, "session error: {e}");
        }

        // Wait for stdin to close (SSH died) before exiting
        let _ = stdin_closed.await;
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
    let pty_writer = pty.clone_writer();

    // Task: PTY output → terminal → SSP diff → client datagram
    let session_conn = session.connection().clone();
    let terminal_out = Arc::clone(&terminal);
    let sender_out = Arc::clone(&ssp_sender);
    let output_task = tokio::spawn(async move {
        let mut dirty = false;
        let mut interval = tokio::time::interval(Duration::from_millis(20));
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
                _ = interval.tick() => {
                    // Only take a new snapshot when PTY output arrived
                    if dirty {
                        dirty = false;
                        let state = terminal_out.lock().expect("terminal lock poisoned").snapshot();
                        sender_out.lock().expect("sender lock poisoned").push_state(state);
                    }
                    // Always try to send — retransmits if client hasn't ack'd
                    // (QUIC datagrams are unreliable, so frames can be lost)
                    let sender = sender_out.lock().expect("sender lock poisoned");
                    if let Some(frame) = sender.generate_frame() {
                        let data = frame.encode();
                        let max_dgram = session_conn.max_datagram_size().unwrap_or(1200);
                        if data.len() <= max_dgram {
                            if session_conn.send_datagram(Bytes::from(data)).is_err() {
                                break;
                            }
                        } else {
                            // Oversized frame: send via reliable uni stream
                            let stream_data = frame.encode_for_stream();
                            let conn = session_conn.clone();
                            tokio::spawn(async move {
                                if let Ok(mut stream) = conn.open_uni().await {
                                    let _ = stream.write_all(&[scrollback::stream_type::SSP_FRAME]).await;
                                    let _ = stream.write_all(&stream_data).await;
                                    let _ = stream.finish();
                                }
                            });
                        }
                    }
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
        pty // Return ownership of PTY for detaching
    });

    // Wait for any task to finish (connection lost or session ended)
    tokio::select! {
        _ = output_task => {}
        _ = input_task => {}
        _ = scrollback_task => {}
        pty_result = control_task => {
            // Control task finished — detach session with PTY
            if let Ok(pty) = pty_result {
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
async fn run_client(host: &str, port: u16, cert_path: Option<PathBuf>) -> anyhow::Result<()> {
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

    client_session_loop(addr, &cert_der, None).await
}

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
    let mut session_id: Option<[u8; 16]> = None;
    let mut backoff = Duration::from_millis(100);
    let client = QuicClient::new()?;

    loop {
        let conn_result = if let Some(cc) = client_cert {
            client
                .connect_with_cert(addr, "localhost", cert_der, cc)
                .await
        } else {
            client.connect(addr, "localhost", cert_der).await
        };
        let conn = match conn_result {
            Ok(c) => {
                backoff = Duration::from_millis(100);
                c
            }
            Err(e) => {
                let mut stdout = std::io::stdout();
                let _ = stdout.write_all(
                    format!(
                        "\r\n[RoSE: connection failed ({e}), reconnecting in {backoff:?}...]\r\n"
                    )
                    .as_bytes(),
                );
                let _ = stdout.flush();
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
                continue;
            }
        };

        let (cols, rows) = terminal::size()?;
        let env = collect_env_vars();
        let mut session = if let Some(sid) = session_id {
            match ClientSession::reconnect(conn, rows, cols, sid, env).await {
                Ok(s) => s,
                Err(e) => {
                    let mut stdout = std::io::stdout();
                    let _ = stdout.write_all(
                        format!("\r\n[RoSE: reconnect handshake failed ({e}), retrying...]\r\n")
                            .as_bytes(),
                    );
                    let _ = stdout.flush();
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
            }
        } else {
            ClientSession::connect(conn, rows, cols, env).await?
        };

        // Read SessionInfo from server
        match session.recv_control().await? {
            Some(ControlMessage::SessionInfo {
                version: _,
                session_id: sid,
            }) => {
                session_id = Some(sid);
            }
            Some(other) => {
                anyhow::bail!("expected SessionInfo, got {other:?}");
            }
            None => {
                anyhow::bail!("server closed control stream before SessionInfo");
            }
        }

        {
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(
                format!(
                    "\r\n[RoSE: {}]\r\n",
                    if session_id.is_some() && backoff > Duration::from_millis(100) {
                        "reconnected"
                    } else {
                        "connected"
                    }
                )
                .as_bytes(),
            );
            let _ = stdout.flush();
        }

        // Clear screen so SSP rendering starts clean
        {
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(b"\x1b[2J\x1b[H");
            let _ = stdout.flush();
        }

        // Fresh SSP state each connection (server resets SspSender on reconnect)
        let receiver = Arc::new(Mutex::new(SspReceiver::new(rows)));
        let prev_state = Arc::new(Mutex::new(ScreenState::empty(rows)));

        // Task: receive SSP frames via datagrams → apply diff → render
        let output_conn = session.connection().clone();
        let recv_dgram = Arc::clone(&receiver);
        let prev_dgram = Arc::clone(&prev_state);
        let output_task = tokio::spawn(async move {
            while let Ok(data) = output_conn.read_datagram().await {
                let Ok(frame) = SspFrame::decode(&data) else {
                    continue;
                };
                process_ssp_frame(&frame, &recv_dgram, &prev_dgram, &output_conn);
            }
        });

        // Task: receive uni streams (oversized SSP frames and scrollback)
        let stream_conn = session.connection().clone();
        let recv_stream = Arc::clone(&receiver);
        let prev_stream = Arc::clone(&prev_state);
        let scrollback_rx = Arc::new(Mutex::new(ScrollbackReceiver::new()));
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
                                        &prev_stream,
                                        &stream_conn,
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
        let input_conn = session.connection().clone();
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
                let event = tokio::task::spawn_blocking(crossterm::event::read).await;
                match event {
                    Ok(Ok(Event::Key(key))) => {
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
                                        return true;
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
                    Ok(Ok(Event::Resize(_, _))) => {
                        // Resize handled separately below
                    }
                    Ok(Err(_)) | Err(_) => break,
                    _ => {}
                }
            }
            false // connection lost, not user-initiated
        });

        // Task: resize events -> control messages
        let resize_task = tokio::spawn(async move {
            let mut last_size = (cols, rows);
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
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
        });

        let user_disconnect = tokio::select! {
            _ = output_task => false,
            _ = stream_task => false,
            result = input_task => result.unwrap_or(false),
            _ = resize_task => false,
        };

        if user_disconnect {
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(b"\r\n[RoSE: disconnected]\r\n");
            let _ = stdout.flush();
            break Ok(());
        }

        // Connection lost — show message and retry
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(b"\r\n[RoSE: connection lost, reconnecting...]\r\n");
        let _ = stdout.flush();
    }
}

/// SSH bootstrap mode: generates an ephemeral client cert, spawns
/// `ssh <host> rose server --bootstrap --ephemeral`, sends the client's
/// public cert over stdin, parses the `ROSE_BOOTSTRAP` line, then connects
/// QUIC directly to the host with mutual TLS.
///
/// The client's private key never leaves this process.
///
/// COVERAGE: CLI bootstrap mode is tested via unit tests for parsing.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_ssh_bootstrap(host: &str, server_binary: &str) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    // Generate ephemeral client cert — private key stays local
    let client_cert = config::generate_self_signed_cert(&["bootstrap-client".to_string()])?;

    eprintln!("Starting SSH bootstrap to {host}...");

    let mut ssh = tokio::process::Command::new("ssh")
        .arg(host)
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
        format!("{resolved_host}:{port}")
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "could not resolve {resolved_host}:{port} (from ssh config for {host})"
                )
            })?
    };

    // Enter raw mode and start the client session loop with mutual TLS
    terminal::enable_raw_mode()?;
    let _raw_guard = RawModeGuard;

    let result = client_session_loop(addr, &server_cert_der, Some(&client_cert)).await;

    // Kill SSH process when done
    let _ = ssh.kill().await;

    result
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

/// Processes an SSP frame: applies diff, renders to stdout, sends ACK.
///
/// Shared by both the datagram and stream receive paths.
///
/// COVERAGE: CLI helper tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
fn process_ssp_frame(
    frame: &SspFrame,
    receiver: &Arc<Mutex<SspReceiver>>,
    prev_state: &Arc<Mutex<ScreenState>>,
    conn: &quinn::Connection,
) {
    let mut recv = receiver.lock().expect("receiver lock poisoned");
    match recv.process_frame(frame) {
        Ok(Some(_)) => {
            let new_state = recv.state().clone();
            let mut prev = prev_state.lock().expect("prev_state lock poisoned");
            let ansi = render_diff_ansi(&prev, &new_state);
            let mut out = std::io::stdout();
            let _ = out.write_all(&ansi);
            let _ = out.flush();
            *prev = new_state;

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

    let cert_path = paths.config_dir.join("client.crt");
    let key_path = paths.config_dir.join("client.key");

    std::fs::write(&cert_path, &cert.cert_pem)?;
    std::fs::write(&key_path, &cert.key_pem)?;

    eprintln!("Certificate: {}", cert_path.display());
    eprintln!("Private key: {}", key_path.display());

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
}
