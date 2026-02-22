#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use crossterm::event::{Event, KeyCode, KeyModifiers};
use crossterm::terminal;
use rose::config::{self, RosePaths};
use rose::protocol::{ClientSession, ControlMessage, ServerSession};
use rose::pty::PtySession;
use rose::ssp::{
    DATAGRAM_KEYSTROKE, DATAGRAM_SSP_ACK, ScreenState, SspFrame, SspReceiver, SspSender,
    render_diff_ansi,
};
use rose::terminal::RoseTerminal;
use rose::transport::{QuicClient, QuicServer};

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
    },
    /// Run the `RoSE` server daemon.
    Server {
        /// Address to listen on.
        #[arg(long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,
    },
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
        Commands::Connect {
            host,
            port,
            cert,
            ssh,
        } => {
            if ssh {
                anyhow::bail!("SSH bootstrap mode not yet implemented");
            }
            run_client(&host, port, cert).await
        }
        Commands::Server { listen } => run_server(listen).await,
        Commands::Keygen => run_keygen(),
    }
}

/// COVERAGE: CLI server loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_server(listen: SocketAddr) -> anyhow::Result<()> {
    let server = QuicServer::bind(listen)?;
    let addr = server.local_addr()?;
    eprintln!("RoSE server listening on {addr}");

    // Save server cert for clients to use
    let paths = RosePaths::resolve();
    std::fs::create_dir_all(&paths.config_dir)?;
    let cert_path = paths.config_dir.join("server.crt");
    std::fs::write(&cert_path, server.server_cert_der().as_ref())?;
    eprintln!("Server certificate written to {}", cert_path.display());

    loop {
        let Some(conn) = server.accept().await? else {
            break;
        };
        let peer = conn.remote_address();
        tracing::info!(%peer, "new connection");

        tokio::spawn(async move {
            if let Err(e) = handle_server_session(conn).await {
                tracing::error!(%peer, "session error: {e}");
            }
        });
    }

    Ok(())
}

/// COVERAGE: Session handler is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn handle_server_session(conn: quinn::Connection) -> anyhow::Result<()> {
    let (mut session, rows, cols) = ServerSession::accept(conn).await?;
    tracing::info!(rows, cols, "client connected");

    let pty = PtySession::open(rows, cols)?;
    let mut pty_output = pty.subscribe_output();
    let pty_writer = pty.clone_writer();

    let terminal = Arc::new(Mutex::new(RoseTerminal::new(rows, cols)));
    let ssp_sender = Arc::new(Mutex::new(SspSender::new()));

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
                    if dirty {
                        dirty = false;
                        let state = terminal_out.lock().expect("terminal lock poisoned").snapshot();
                        let mut sender = sender_out.lock().expect("sender lock poisoned");
                        sender.push_state(state);
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
                                        let _ = stream.write_all(&stream_data).await;
                                        let _ = stream.finish();
                                    }
                                });
                            }
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

    // Task: control messages (resize, goodbye)
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
    });

    // Wait for any task to finish (session over)
    tokio::select! {
        _ = output_task => {}
        _ = input_task => {}
        _ = control_task => {}
    }

    Ok(())
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

    let client = QuicClient::new()?;
    let conn = client.connect(addr, "localhost", &cert_der).await?;
    eprintln!("Connected to {addr}");

    // Get terminal size
    let (cols, rows) = terminal::size()?;
    let mut session = ClientSession::connect(conn, rows, cols).await?;

    // Enter raw mode
    terminal::enable_raw_mode()?;
    let _raw_guard = RawModeGuard;

    let mut stdout = std::io::stdout();

    // Clear screen so SSP rendering starts clean
    let _ = stdout.write_all(b"\x1b[2J\x1b[H");
    let _ = stdout.flush();

    // Shared SSP receiver state for both datagram and stream frames
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

    // Task: receive oversized SSP frames via uni streams
    let stream_conn = session.connection().clone();
    let recv_stream = Arc::clone(&receiver);
    let prev_stream = Arc::clone(&prev_state);
    let stream_task = tokio::spawn(async move {
        while let Ok(mut uni) = stream_conn.accept_uni().await {
            let mut len_buf = [0u8; 4];
            if uni.read_exact(&mut len_buf).await.is_err() {
                continue;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            match uni.read_to_end(len).await {
                Ok(data) => {
                    if let Ok(frame) = SspFrame::decode(&data) {
                        process_ssp_frame(&frame, &recv_stream, &prev_stream, &stream_conn);
                    }
                }
                Err(_) => continue,
            }
        }
    });

    // Task: stdin → prefix with 0x00 → send input datagrams
    let input_conn = session.connection().clone();
    let input_task = tokio::spawn(async move {
        loop {
            let event = tokio::task::spawn_blocking(crossterm::event::read).await;
            match event {
                Ok(Ok(Event::Key(key))) => {
                    let key_bytes = key_event_to_bytes(&key);
                    if !key_bytes.is_empty() {
                        let mut data = vec![DATAGRAM_KEYSTROKE];
                        data.extend_from_slice(&key_bytes);
                        if input_conn.send_datagram(Bytes::from(data)).is_err() {
                            break;
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

    tokio::select! {
        _ = output_task => {}
        _ = stream_task => {}
        _ = input_task => {}
        _ = resize_task => {}
    }

    // Clear line and show disconnect message
    let _ = stdout.write_all(b"\r\n[RoSE: connection closed]\r\n");
    let _ = stdout.flush();

    Ok(())
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
