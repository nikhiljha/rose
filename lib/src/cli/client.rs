use std::future::{Future, poll_fn};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use crossterm::terminal;

use super::input::{InputAction, KeyboardInput, read_keyboard_events};
use super::util::{
    RawModeGuard, connect_command, extract_peer_cert, hex_encode, load_or_generate_client_cert,
};
use crate::config::{self, CertKeyPair, RosePaths};
use crate::input::InputError;
use crate::protocol::{ClientSession, ControlMessage};
use crate::scrollback::{
    self, MAX_SCROLLBACK_BYTES, ScrollbackLine, ScrollbackRange, ScrollbackReceiver,
};
use crate::ssp::{
    DATAGRAM_SSP_ACK, MAX_STREAM_FRAME_BYTES, ScreenState, SspFrame, SspReceiver, render_diff_ansi,
    render_full_redraw,
};
use crate::transport::QuicClient;

async fn drain_ssp_frames(conn: &quinn::Connection, data: &[u8]) -> Option<SspFrame> {
    poll_fn(|cx| {
        let mut best = SspFrame::decode(data).ok();
        for _ in 0..64 {
            let read = conn.read_datagram();
            tokio::pin!(read);
            let Poll::Ready(Ok(more)) = read.poll(cx) else {
                break;
            };
            if let Ok(frame) = SspFrame::decode(&more) {
                match &best {
                    Some(b) if frame.new_num <= b.new_num => {}
                    _ => best = Some(frame),
                }
            }
        }
        Poll::Ready(best)
    })
    .await
}

async fn receive_ssp_frame(stream: &mut quinn::RecvStream) -> anyhow::Result<SspFrame> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    anyhow::ensure!(length <= MAX_STREAM_FRAME_BYTES, "oversized SSP frame");
    let data = stream.read_to_end(length).await?;
    anyhow::ensure!(data.len() == length, "truncated SSP frame");
    Ok(SspFrame::decode(&data)?)
}

async fn receive_history(
    mut stream: quinn::RecvStream,
    receiver: Arc<Mutex<ScrollbackReceiver>>,
) -> anyhow::Result<()> {
    loop {
        let mut header = [0; 12];
        match stream.read_exact(&mut header).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let length = u32::from_be_bytes(header[8..].try_into()?) as usize;
        anyhow::ensure!(length <= MAX_SCROLLBACK_BYTES, "oversized history row");
        let mut data = header.to_vec();
        data.resize(12 + length, 0);
        stream.read_exact(&mut data[12..]).await?;
        let (line, _) = ScrollbackLine::decode(&data)?;
        receiver
            .lock()
            .expect("scrollback lock poisoned")
            .add_line(line);
    }
}

async fn receive_uni_streams(
    connection: quinn::Connection,
    history: Arc<Mutex<ScrollbackReceiver>>,
    on_frame: impl Fn(&SspFrame) + Send + Sync + 'static,
) {
    let on_frame = Arc::new(on_frame);
    let mut workers = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            incoming = connection.accept_uni(), if workers.len() < 8 => {
                let Ok(mut stream) = incoming else { return; };
                let on_frame = Arc::clone(&on_frame);
                let history = Arc::clone(&history);
                workers.spawn(async move {
                    let mut prefix = [0];
                    stream.read_exact(&mut prefix).await?;
                    match prefix[0] {
                        scrollback::stream_type::SSP_FRAME => on_frame(&receive_ssp_frame(&mut stream).await?),
                        scrollback::stream_type::SCROLLBACK => receive_history(stream, history).await?,
                        _ => anyhow::bail!("unknown uni stream type {}", prefix[0]),
                    }
                    Ok::<_, anyhow::Error>(())
                });
            }
            result = workers.join_next(), if !workers.is_empty() => {
                match result {
                    Some(Ok(Err(error))) => tracing::debug!(%error, "invalid incoming stream"),
                    Some(Err(error)) => tracing::warn!(%error, "stream reader task failed"),
                    _ => {}
                }
            }
        }
    }
}

/// Marker that STUN was used for the initial connection.
///
/// When present in the reconnection loop, each reconnect attempt redoes
/// STUN discovery (the NAT mapping is lost when the network changes).
/// SSH is already killed at this point — STUN reconnection sends punch
/// packets from the server's existing endpoint, which already has the
/// firewall pinhole from the initial connection.
pub(super) struct StunReconnectContext {
    pub(super) stun_servers: Option<Vec<String>>,
}

/// Collects environment variables to forward from client to server.
///
/// Includes `TERM`, `COLORTERM`, `LANG`, and all `LC_*` locale variables.
/// TERM is always set to `xterm-256color` because the server-side terminal
/// emulator (wezterm-term) is xterm-256color compatible.
///
/// COVERAGE: Only called from `client_session_loop` which is excluded from
/// instrumented coverage (tested via e2e tests).
#[cfg_attr(coverage_nightly, coverage(off))]
fn collect_env_vars() -> Vec<(String, String)> {
    let mut vars = Vec::new();

    vars.push(("TERM".to_string(), "xterm-256color".to_string()));

    for key in ["COLORTERM", "LANG"] {
        if let Ok(val) = std::env::var(key) {
            vars.push((key.to_string(), val));
        }
    }

    for (key, val) in std::env::vars() {
        if key.starts_with("LC_") {
            vars.push((key, val));
        }
    }

    vars
}

/// COVERAGE: CLI client loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) async fn run_client(
    host: &str,
    port: u16,
    cert_path: Option<PathBuf>,
    client_cert_path: Option<PathBuf>,
    session_id: Option<[u8; 16]>,
) -> anyhow::Result<()> {
    let reattach_command = connect_command(
        host,
        port,
        cert_path.as_deref(),
        client_cert_path.as_deref(),
    );
    let paths = RosePaths::resolve();
    let cfg = config::RoseConfig::load(&paths.config_dir)?;

    let client_cert = if let Some(ref path) = client_cert_path {
        let cert_der_bytes = std::fs::read(path)?;
        let key_path = path.with_extension("key.der");
        let key_der = std::fs::read(&key_path).map_err(|e| {
            anyhow::anyhow!("failed to read client key at {}: {e}", key_path.display())
        })?;
        CertKeyPair {
            cert_pem: String::new(),
            key_pem: String::new(),
            cert_der: rustls::pki_types::CertificateDer::from(cert_der_bytes),
            key_der,
        }
    } else {
        load_or_generate_client_cert()?
    };

    let addr: SocketAddr = format!("{host}:{port}").parse().unwrap_or_else(|_| {
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

    let client_config = if cfg.require_ca_certs {
        config::build_platform_verified_client_config_with_cert(&client_cert)?
    } else {
        let cert_path = cert_path.unwrap_or_else(|| {
            paths
                .known_hosts_dir
                .join(format!("{}.crt", config::sanitize_hostname(host)))
        });
        let cert_der = if cert_path.exists() {
            let bytes = std::fs::read(&cert_path).map_err(|e| {
                anyhow::anyhow!("failed to read server cert at {}: {e}", cert_path.display())
            })?;
            rustls::pki_types::CertificateDer::from(bytes)
        } else {
            tofu_first_connect(host, addr, &client_cert, &cert_path).await?
        };
        config::build_client_config_with_cert(&cert_der, &client_cert)?
    };

    let _raw_guard = RawModeGuard::enable()?;

    client_session_loop(addr, host, client_config, session_id, reattach_command).await
}

/// Performs a TOFU (Trust On First Use) first connection: connects to the
/// server, extracts its certificate, displays the fingerprint, and prompts
/// the user to accept. If accepted, saves the cert for future connections.
async fn tofu_first_connect(
    host: &str,
    addr: SocketAddr,
    client_cert: &CertKeyPair,
    cert_save_path: &std::path::Path,
) -> anyhow::Result<rustls::pki_types::CertificateDer<'static>> {
    let tofu_config = config::build_tofu_client_config_with_cert(client_cert)?;
    let client = QuicClient::new()?;
    let conn = client
        .connect_with_config(tofu_config, addr, host)
        .await
        .map_err(|e| anyhow::anyhow!("TOFU connection to {host}:{} failed: {e}", addr.port()))?;

    let server_cert_der = extract_peer_cert(&conn)
        .ok_or_else(|| anyhow::anyhow!("server did not present a certificate"))?;

    conn.close(0u32.into(), b"tofu check");

    let fingerprint = config::cert_fingerprint(&server_cert_der);
    eprintln!("The server at {host} presented this certificate:");
    eprintln!("  SHA-256: {fingerprint}");
    eprint!("Trust this server? [y/N] ");

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !answer.trim().eq_ignore_ascii_case("y") {
        anyhow::bail!("certificate rejected by user");
    }

    if let Some(parent) = cert_save_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(cert_save_path, &server_cert_der)?;
    eprintln!("Certificate saved to {}", cert_save_path.display());

    Ok(rustls::pki_types::CertificateDer::from(server_cert_der))
}

/// Reconnection loop: connects/reconnects to the server with exponential backoff.
///
/// COVERAGE: CLI client session loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) async fn client_session_loop(
    addr: SocketAddr,
    server_name: &str,
    client_config: quinn::ClientConfig,
    session_id: Option<[u8; 16]>,
    reattach_command: String,
) -> anyhow::Result<()> {
    client_session_loop_inner(
        addr,
        server_name,
        client_config,
        None,
        None,
        session_id,
        reattach_command,
    )
    .await
}

/// Like [`client_session_loop`] but uses a pre-established connection for the
/// first iteration. Used when direct QUIC connect already succeeded.
///
/// COVERAGE: CLI client session loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) async fn client_session_loop_with_conn(
    first_conn: quinn::Connection,
    addr: SocketAddr,
    server_name: &str,
    client_config: quinn::ClientConfig,
) -> anyhow::Result<()> {
    let reattach_command = connect_command(server_name, addr.port(), None, None);
    client_session_loop_inner(
        addr,
        server_name,
        client_config,
        Some(first_conn),
        None,
        None,
        reattach_command,
    )
    .await
}

/// Like [`client_session_loop`] but uses a pre-created [`QuicClient`] for the
/// first connection and enables STUN-based reconnection via `stun_ctx`.
///
/// COVERAGE: CLI client session loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) async fn client_session_loop_with_client(
    first_client: QuicClient,
    addr: SocketAddr,
    server_name: &str,
    client_config: quinn::ClientConfig,
    stun_ctx: StunReconnectContext,
) -> anyhow::Result<()> {
    let conn = first_client
        .connect_with_config(client_config.clone(), addr, server_name)
        .await?;
    let reattach_command = connect_command(server_name, addr.port(), None, None);
    client_session_loop_inner(
        addr,
        server_name,
        client_config,
        Some(conn),
        Some(stun_ctx),
        None,
        reattach_command,
    )
    .await
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
async fn stun_reconnect(stun_servers: Option<Vec<String>>) -> anyhow::Result<QuicClient> {
    let (socket, public_addr) = tokio::task::spawn_blocking(move || {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let public_addr = crate::stun::stun_discover(&socket, stun_servers.as_deref())?;
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
    server_name: &str,
    client_config: quinn::ClientConfig,
    first_conn: Option<quinn::Connection>,
    stun_ctx: Option<StunReconnectContext>,
    mut session_id: Option<[u8; 16]>,
    reattach_command: String,
) -> anyhow::Result<()> {
    let mut backoff = Duration::from_millis(100);
    let mut initial_conn = first_conn;
    const MAX_INITIAL_RETRIES: u32 = 10;
    let mut initial_retries: u32 = 0;

    // Persistent client screen state across reconnects so the user sees
    // the last known content instead of a blank screen while reconnecting.
    let mut prev_client_screen: Option<ScreenState> = None;

    let (key_tx, key_rx) = tokio::sync::mpsc::channel(128);
    let keyboard = KeyboardInput::new(key_rx);
    std::thread::spawn(move || read_keyboard_events(key_tx));

    loop {
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

        let mut _live_client: Option<QuicClient> = None;

        let conn = if let Some(conn) = initial_conn.take() {
            backoff = Duration::from_millis(100);
            conn
        } else if let Some(ref ctx) = stun_ctx {
            match stun_reconnect(ctx.stun_servers.clone()).await {
                Ok(client) => {
                    let conn_result = tokio::time::timeout(Duration::from_secs(5), {
                        client.connect_with_config(client_config.clone(), addr, server_name)
                    })
                    .await;
                    match conn_result {
                        Ok(Ok(c)) => {
                            backoff = Duration::from_millis(100);
                            _live_client = Some(client);
                            c
                        }
                        Ok(Err(e)) => {
                            tracing::debug!(?backoff, "STUN reconnect failed: {e}");
                            if wait_or_disconnect(&keyboard, backoff, session_id, &reattach_command)
                                .await?
                            {
                                break Ok(());
                            }
                            backoff = (backoff * 2).min(Duration::from_secs(5));
                            continue;
                        }
                        Err(_) => {
                            tracing::debug!(?backoff, "STUN reconnect timed out");
                            if wait_or_disconnect(&keyboard, backoff, session_id, &reattach_command)
                                .await?
                            {
                                break Ok(());
                            }
                            backoff = (backoff * 2).min(Duration::from_secs(5));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(?backoff, "STUN rediscovery failed: {e}");
                    if wait_or_disconnect(&keyboard, backoff, session_id, &reattach_command).await?
                    {
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
                    if wait_or_disconnect(&keyboard, backoff, session_id, &reattach_command).await?
                    {
                        break Ok(());
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
            };
            let conn_result = tokio::time::timeout(Duration::from_secs(5), {
                client.connect_with_config(client_config.clone(), addr, server_name)
            })
            .await;
            match conn_result {
                Ok(Ok(c)) => {
                    backoff = Duration::from_millis(100);
                    _live_client = Some(client);
                    c
                }
                Ok(Err(e)) => {
                    eprintln!("[RoSE: {e}]");
                    if wait_or_disconnect(&keyboard, backoff, session_id, &reattach_command).await?
                    {
                        break Ok(());
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
                Err(_) => {
                    eprintln!("[RoSE: connection timed out]");
                    if wait_or_disconnect(&keyboard, backoff, session_id, &reattach_command).await?
                    {
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
                    if wait_or_disconnect(&keyboard, backoff, session_id, &reattach_command).await?
                    {
                        break Ok(());
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
            }
        } else {
            ClientSession::connect(conn, rows, cols, env).await?
        };

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
                if wait_or_disconnect(&keyboard, backoff, session_id, &reattach_command).await? {
                    break Ok(());
                }
                backoff = (backoff * 2).min(Duration::from_secs(5));
                continue;
            }
        }

        let is_reconnect = session_id.is_some() && backoff > Duration::from_millis(100);
        if is_reconnect {
            tracing::info!("reconnected");
        } else {
            tracing::info!("connected");
        }

        // Only clear the screen on first connect. On reconnect, preserve
        // the last known content so the user doesn't see a blank screen.
        if prev_client_screen.is_none() {
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(b"\x1b[3J\x1b[2J\x1b[H");
            let _ = stdout.flush();
        }

        let receiver = Arc::new(Mutex::new(SspReceiver::new(rows)));
        let client_screen = Arc::new(Mutex::new(
            prev_client_screen
                .take()
                .unwrap_or_else(|| ScreenState::empty(rows)),
        ));

        let scrollback_rx = Arc::new(Mutex::new(ScrollbackReceiver::new()));
        let rendered_sb_range = Arc::new(Mutex::new(None));

        let output_conn = session.connection().clone();
        let recv_dgram = Arc::clone(&receiver);
        let client_dgram = Arc::clone(&client_screen);
        let sb_rx_dgram = Arc::clone(&scrollback_rx);
        let sb_range_dgram = Arc::clone(&rendered_sb_range);
        let output_task = tokio::spawn(async move {
            let mut sb_check = tokio::time::interval(Duration::from_millis(200));
            loop {
                tokio::select! {
                    result = output_conn.read_datagram() => {
                        match result {
                            Ok(data) => {
                                let best = drain_ssp_frames(&output_conn, &data).await;
                                if let Some(ref frame) = best {
                                    process_ssp_frame(
                                        frame,
                                        &recv_dgram,
                                        &client_dgram,
                                        &output_conn,
                                        &sb_rx_dgram,
                                        &sb_range_dgram,
                                    );
                                }
                            }
                            Err(e) => return e,
                        }
                    }
                    _ = sb_check.tick() => {
                        maybe_render_scrollback(
                            &recv_dgram,
                            &client_dgram,
                            &sb_rx_dgram,
                            &sb_range_dgram,
                        );
                    }
                }
            }
        });

        let stream_conn = session.connection().clone();
        let recv_stream = Arc::clone(&receiver);
        let client_stream = Arc::clone(&client_screen);
        let sb_rx_stream = Arc::clone(&scrollback_rx);
        let sb_range_stream = Arc::clone(&rendered_sb_range);
        let stream_task = tokio::spawn(receive_uni_streams(
            stream_conn.clone(),
            Arc::clone(&scrollback_rx),
            move |frame| {
                process_ssp_frame(
                    frame,
                    &recv_stream,
                    &client_stream,
                    &stream_conn,
                    &sb_rx_stream,
                    &sb_range_stream,
                );
            },
        ));

        let input_conn = session.connection().clone();
        let input_buffer = keyboard.buffer.clone();
        let input_transport_task =
            tokio::spawn(async move { input_buffer.connect(&input_conn).await });
        let input = keyboard.clone();
        let input_task = tokio::spawn(async move {
            loop {
                if let Some(action) = input.next().await? {
                    return Ok::<_, InputError>(action);
                }
            }
        });

        let check_conn = session.connection().clone();

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
            InputRejected(InputError),
        }

        let mut output_task = output_task;
        let mut stream_task = stream_task;
        let mut input_task = input_task;
        let mut input_transport_task = input_transport_task;
        let mut control_task = control_task;
        let exit = tokio::select! {
            _ = &mut output_task => SessionExit::ConnectionLost,
            _ = &mut stream_task => SessionExit::ConnectionLost,
            result = &mut input_task => {
                match result {
                    Ok(Ok(InputAction::Disconnect)) => SessionExit::UserDisconnect,
                    Ok(Ok(InputAction::Detach)) => SessionExit::UserDetach,
                    Ok(Err(error)) => SessionExit::InputRejected(error),
                    Err(_) => SessionExit::ConnectionLost,
                }
            },
            result = &mut input_transport_task => {
                match result {
                    Ok(Err(error @ (InputError::Offset { .. } | InputError::Length))) =>
                        SessionExit::InputRejected(error),
                    _ => SessionExit::ConnectionLost,
                }
            },
            result = &mut control_task => {
                if result.unwrap_or(false) {
                    SessionExit::UserDisconnect
                } else {
                    SessionExit::ConnectionLost
                }
            },
        };

        output_task.abort();
        stream_task.abort();
        input_task.abort();
        input_transport_task.abort();
        control_task.abort();

        let exit = match exit {
            SessionExit::ConnectionLost => {
                // The CONNECTION_CLOSE frame may still be in-flight when the
                // select fires.  Wait briefly so quinn can process it before
                // we inspect `close_reason()`.
                let close_reason =
                    tokio::time::timeout(Duration::from_millis(200), check_conn.closed())
                        .await
                        .ok()
                        .and_then(|_| check_conn.close_reason());

                // Fall back to an immediate check if the timeout elapsed.
                let close_reason = close_reason.or_else(|| check_conn.close_reason());

                match close_reason {
                    Some(quinn::ConnectionError::ApplicationClosed(ref close))
                        if close.error_code == quinn::VarInt::from_u32(0) =>
                    {
                        SessionExit::ShellExited
                    }
                    _ => SessionExit::ConnectionLost,
                }
            }
            other => other,
        };

        match exit {
            SessionExit::InputRejected(error) => {
                check_conn.close(1u32.into(), b"input state mismatch");
                return Err(error.into());
            }
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
                // Explicitly close the QUIC connection so the server
                // receives a CONNECTION_CLOSE frame and immediately
                // returns to accept() for the reconnecting client.
                check_conn.close(0u32.into(), b"detaching");
                // Give the I/O driver a moment to flush the frame.
                tokio::time::sleep(Duration::from_millis(50)).await;

                print_detached(session_id, &reattach_command);
                break Ok(());
            }
            SessionExit::ConnectionLost => {
                tracing::debug!("connection lost, reconnecting");
                // Preserve the last rendered screen so it can be shown
                // while reconnecting instead of a blank terminal.
                prev_client_screen = Some(
                    client_screen
                        .lock()
                        .expect("client screen lock poisoned")
                        .clone(),
                );
            }
        }
    }
}

/// Retains input during backoff, while honoring local escape commands.
async fn wait_or_disconnect(
    keyboard: &KeyboardInput,
    duration: Duration,
    session_id: Option<[u8; 16]>,
    reattach_command: &str,
) -> Result<bool, InputError> {
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        tokio::select! {
            action = keyboard.next() => {
                if let Some(action) = action? {
                    match action {
                        InputAction::Detach => print_detached(session_id, reattach_command),
                        InputAction::Disconnect => {
                            let mut stdout = std::io::stdout();
                            let _ = stdout.write_all(b"\r\n[RoSE: disconnected]\r\n");
                            let _ = stdout.flush();
                        }
                    }
                    return Ok(true);
                }
            }
            () = tokio::time::sleep(remaining) => {
                return Ok(false);
            }
        }
    }
}

fn print_detached(session_id: Option<[u8; 16]>, command: &str) {
    let _ = terminal::disable_raw_mode();
    let mut stdout = std::io::stdout();
    let message = session_id.map_or_else(
        || "\r\n[RoSE: disconnected before session creation]\r\n".to_owned(),
        |id| {
            format!(
                "\r\n[RoSE: detached]\r\n[RoSE: to reattach, run: {command} --session {}]\r\n",
                hex_encode(&id),
            )
        },
    );
    let _ = stdout.write_all(message.as_bytes());
    let _ = stdout.flush();
}

/// Performs a full terminal redraw (scrollback + visible) and resets the
/// client terminal to match.
///
/// COVERAGE: CLI helper tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
fn do_full_redraw(
    scrollback_rx: &Mutex<ScrollbackReceiver>,
    rendered_sb_range: &Mutex<ScrollbackRange>,
    new_state: &ScreenState,
    screen: &mut ScreenState,
) {
    let sb = scrollback_rx.lock().expect("scrollback lock poisoned");
    let mut count = rendered_sb_range
        .lock()
        .expect("rendered range lock poisoned");

    let ansi = render_full_redraw(sb.lines(), new_state);
    *count = sb.range_before_viewport(new_state.viewport);
    drop(sb);
    drop(count);

    let mut out = std::io::BufWriter::new(std::io::stdout());
    let _ = out.write_all(&ansi);
    let _ = out.flush();

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
    rendered_sb_range: &Arc<Mutex<ScrollbackRange>>,
) {
    let recv = receiver.lock().expect("receiver lock poisoned");
    let needs_redraw = {
        let sb = scrollback_rx.lock().expect("scrollback lock poisoned");
        let count = rendered_sb_range
            .lock()
            .expect("rendered range lock poisoned");
        sb.range_before_viewport(recv.state().viewport) != *count
    };
    if !needs_redraw {
        return;
    }

    let state = recv.state().clone();
    drop(recv);

    let mut screen = client_screen.lock().expect("client screen lock poisoned");
    do_full_redraw(scrollback_rx, rendered_sb_range, &state, &mut screen);
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
    rendered_sb_range: &Arc<Mutex<ScrollbackRange>>,
) {
    let mut recv = receiver.lock().expect("receiver lock poisoned");
    let first_frame = recv.ack_num() == 0;
    match recv.process_frame(frame) {
        Ok(Some(_)) => {
            let new_state = recv.state().clone();
            let mut screen = client_screen.lock().expect("client screen lock poisoned");

            let needs_full_redraw = {
                let sb = scrollback_rx.lock().expect("scrollback lock poisoned");
                let count = rendered_sb_range
                    .lock()
                    .expect("rendered range lock poisoned");
                first_frame
                    || sb.range_before_viewport(new_state.viewport) != *count
                    || new_state.rows.len() != screen.rows.len()
            };

            if needs_full_redraw {
                do_full_redraw(scrollback_rx, rendered_sb_range, &new_state, &mut screen);
            } else {
                let ansi = render_diff_ansi(&screen, &new_state);
                let mut out = std::io::BufWriter::new(std::io::stdout());
                let _ = out.write_all(&ansi);
                let _ = out.flush();
                *screen = new_state;
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("SSP frame error: {e}");
            return;
        }
    }
    if frame.diff.is_some() {
        let ack = SspFrame::ack_only(recv.ack_num());
        let mut ack_data = vec![DATAGRAM_SSP_ACK];
        ack_data.extend_from_slice(&ack.encode());
        let _ = conn.send_datagram(Bytes::from(ack_data));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crossterm::event::{Event, KeyCode};

    use super::*;

    fn observe_stream_frames(
        connection: quinn::Connection,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::mpsc::UnboundedReceiver<SspFrame>,
    ) {
        let (frames, received) = tokio::sync::mpsc::unbounded_channel();
        let reader = tokio::spawn(receive_uni_streams(
            connection,
            Arc::new(Mutex::new(ScrollbackReceiver::new())),
            move |frame| {
                frames.send(frame.clone()).unwrap();
            },
        ));
        (reader, received)
    }

    #[tokio::test]
    async fn cancelling_stream_receiver_stops_its_history_reader() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let history = Arc::new(Mutex::new(ScrollbackReceiver::new()));
        let reader = tokio::spawn(receive_uni_streams(
            client.clone(),
            Arc::clone(&history),
            |_| {},
        ));
        let mut send = server.open_uni().await.unwrap();
        send.write_all(&[scrollback::stream_type::SCROLLBACK])
            .await
            .unwrap();
        send.write_all(
            &ScrollbackLine {
                stable_row: 0,
                text: "ready".to_owned(),
            }
            .encode(),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while history.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        reader.abort();
        let _ = reader.await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), send.stopped())
                .await
                .expect("history reader outlived its connection task")
                .unwrap()
                .is_some()
        );
        assert!(client.close_reason().is_none());
    }

    #[tokio::test]
    async fn incoming_stream_workers_are_bounded_and_slots_are_reused() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let (reader, mut received) = observe_stream_frames(client.clone());
        let mut histories = Vec::new();
        for _ in 0..8 {
            let mut stream = server.open_uni().await.unwrap();
            stream
                .write_all(&[scrollback::stream_type::SCROLLBACK])
                .await
                .unwrap();
            histories.push(stream);
        }
        let mut frame = server.open_uni().await.unwrap();
        frame
            .write_all(&[scrollback::stream_type::SSP_FRAME])
            .await
            .unwrap();
        frame
            .write_all(&SspFrame::ack_only(0).encode_for_stream())
            .await
            .unwrap();
        frame.finish().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), received.recv())
                .await
                .is_err(),
            "receiver exceeded its stream worker bound"
        );
        histories[0].finish().unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), received.recv())
                .await
                .unwrap()
                .map(|frame| frame.new_num),
            Some(0)
        );
        reader.abort();
        let _ = reader.await;
        for stream in &mut histories[1..] {
            assert!(
                tokio::time::timeout(Duration::from_secs(1), stream.stopped())
                    .await
                    .unwrap()
                    .unwrap()
                    .is_some()
            );
        }
        assert!(client.close_reason().is_none());
    }

    #[tokio::test]
    async fn invalid_streams_do_not_block_a_later_valid_screen() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let (reader, mut received) = observe_stream_frames(client.clone());
        let frame = SspFrame::ack_only(7).encode();
        let mut malformed = vec![vec![], vec![255], vec![1, 0, 0], vec![1, 0, 0, 0, 0]];
        for length in [frame.len() - 1, frame.len() + 1] {
            let mut data = vec![scrollback::stream_type::SSP_FRAME];
            data.extend_from_slice(&(length as u32).to_be_bytes());
            data.extend_from_slice(&frame);
            malformed.push(data);
        }
        for data in malformed {
            let mut stream = server.open_uni().await.unwrap();
            stream.write_all(&data).await.unwrap();
            stream.finish().unwrap();
        }
        let mut stream = server.open_uni().await.unwrap();
        stream
            .write_all(&[scrollback::stream_type::SSP_FRAME])
            .await
            .unwrap();
        for chunk in SspFrame::ack_only(7).encode_for_stream().chunks(3) {
            stream.write_all(chunk).await.unwrap();
        }
        stream.finish().unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), received.recv())
                .await
                .unwrap()
                .map(|frame| frame.ack_num),
            Some(7)
        );
        client.close(0u32.into(), b"finished");
        tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn fragmented_history_preserves_unicode_and_multiple_records() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let lines = [
            ScrollbackLine {
                stable_row: 7,
                text: "\x1b[31m界é\x1b[0m".repeat(500),
            },
            ScrollbackLine {
                stable_row: 8,
                text: String::new(),
            },
        ];
        let mut stream = server.open_uni().await.unwrap();
        for line in &lines {
            for chunk in line.encode().chunks(997) {
                stream.write_all(chunk).await.unwrap();
            }
        }
        stream.finish().unwrap();
        let history = Arc::new(Mutex::new(ScrollbackReceiver::new()));
        receive_history(client.accept_uni().await.unwrap(), Arc::clone(&history))
            .await
            .unwrap();
        assert_eq!(history.lock().unwrap().lines(), lines);
    }

    #[tokio::test]
    async fn oversized_screen_length_is_rejected_without_waiting_for_payload() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let mut send = server.open_uni().await.unwrap();
        send.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let mut receive = client.accept_uni().await.unwrap();
        let result =
            tokio::time::timeout(Duration::from_millis(100), receive_ssp_frame(&mut receive))
                .await
                .expect("oversized screen header was not rejected");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn oversized_history_length_is_rejected_without_waiting_for_payload() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let mut send = server.open_uni().await.unwrap();
        let mut header = [0; 12];
        header[8..].copy_from_slice(&u32::MAX.to_be_bytes());
        send.write_all(&header).await.unwrap();
        let receive = client.accept_uni().await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            receive_history(receive, Arc::new(Mutex::new(ScrollbackReceiver::new()))),
        )
        .await
        .expect("oversized history header was not rejected");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn truncated_and_invalid_history_is_rejected_at_eof() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let encoded = ScrollbackLine {
            stable_row: 0,
            text: "ab".to_owned(),
        }
        .encode();
        let mut invalid = encoded.clone();
        invalid[12] = 255;
        for bytes in [encoded[..8].to_vec(), encoded[..13].to_vec(), invalid] {
            let mut send = server.open_uni().await.unwrap();
            send.write_all(&bytes).await.unwrap();
            send.finish().unwrap();
            let receive = client.accept_uni().await.unwrap();
            assert!(
                receive_history(receive, Arc::new(Mutex::new(ScrollbackReceiver::new())))
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn backoff_honors_local_disconnect_and_keyboard_eof() {
        for explicit in [true, false] {
            let (send, receive) = tokio::sync::mpsc::channel(8);
            let keyboard = KeyboardInput::new(receive);
            if explicit {
                for code in [
                    KeyCode::Enter,
                    KeyCode::Char('x'),
                    KeyCode::Enter,
                    KeyCode::Enter,
                    KeyCode::Char('~'),
                    KeyCode::Char('.'),
                ] {
                    send.send(Event::Key(crossterm::event::KeyEvent::new(
                        code,
                        crossterm::event::KeyModifiers::NONE,
                    )))
                    .await
                    .unwrap();
                }
            } else {
                drop(send);
            }
            assert!(
                !wait_or_disconnect(&keyboard, Duration::ZERO, None, "")
                    .await
                    .unwrap()
            );
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    wait_or_disconnect(&keyboard, Duration::from_secs(5), None, ""),
                )
                .await
                .expect("local disconnect waited for the reconnect backoff")
                .unwrap()
            );
        }
    }

    #[tokio::test]
    async fn backoff_detach_resumes_after_prior_input_is_acknowledged() {
        for session_id in [None, Some([3; 16])] {
            let (send, receive) = tokio::sync::mpsc::channel(8);
            let keyboard = KeyboardInput::new(receive);
            for event in [
                Event::Resize(80, 24),
                Event::Key(crossterm::event::KeyEvent::new(
                    KeyCode::Enter,
                    crossterm::event::KeyModifiers::NONE,
                )),
                Event::Key(crossterm::event::KeyEvent::new(
                    KeyCode::Char('~'),
                    crossterm::event::KeyModifiers::NONE,
                )),
                Event::Key(crossterm::event::KeyEvent::new(
                    KeyCode::Char('d'),
                    crossterm::event::KeyModifiers::NONE,
                )),
            ] {
                send.send(event).await.unwrap();
            }
            assert!(
                !wait_or_disconnect(&keyboard, Duration::from_millis(20), session_id, "rose")
                    .await
                    .unwrap()
            );
            let file = tempfile::NamedTempFile::new().unwrap();
            let input = crate::input::ServerInput::new(Arc::new(Mutex::new(Box::new(
                file.reopen().unwrap(),
            ))));
            let connection =
                crate::testutil::InputConnection::new(input, keyboard.buffer.clone()).await;
            assert!(
                wait_or_disconnect(&keyboard, Duration::from_secs(2), session_id, "rose")
                    .await
                    .unwrap()
            );
            assert_eq!(std::fs::read(file.path()).unwrap(), b"\r");
            connection.close().await;
        }
    }

    #[tokio::test]
    async fn backoff_preserves_typed_input_for_the_next_connection() {
        let (send, receive) = tokio::sync::mpsc::channel(8);
        let keyboard = KeyboardInput::new(receive);
        for code in [KeyCode::Char('a'), KeyCode::Char('b'), KeyCode::Enter] {
            send.send(Event::Key(crossterm::event::KeyEvent::new(
                code,
                crossterm::event::KeyModifiers::NONE,
            )))
            .await
            .unwrap();
        }
        assert!(
            !wait_or_disconnect(&keyboard, Duration::from_millis(20), None, "")
                .await
                .unwrap()
        );
        let file = tempfile::NamedTempFile::new().unwrap();
        let input =
            crate::input::ServerInput::new(Arc::new(Mutex::new(Box::new(file.reopen().unwrap()))));
        let connection =
            crate::testutil::InputConnection::new(input, keyboard.buffer.clone()).await;
        tokio::time::timeout(
            Duration::from_secs(2),
            keyboard
                .buffer
                .wait_for_capacity(crate::input::MAX_PENDING_INPUT),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(file.path()).unwrap(), b"ab\r");
        connection.close().await;
    }

    #[tokio::test]
    async fn duplicate_and_unknown_base_frames_acknowledge_current_state() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let receiver = Arc::new(Mutex::new(SspReceiver::new(4)));
        let screen = Arc::new(Mutex::new(ScreenState::empty(4)));
        let history = Arc::new(Mutex::new(ScrollbackReceiver::new()));
        let rendered = Arc::new(Mutex::new(None));
        let initial = SspFrame {
            old_num: 0,
            new_num: 2,
            ack_num: 0,
            diff: Some(ScreenState::empty(4).diff_from_empty()),
        };
        let unknown_base = SspFrame {
            old_num: 1,
            new_num: 3,
            ..initial.clone()
        };
        for frame in [&initial, &initial, &unknown_base] {
            process_ssp_frame(frame, &receiver, &screen, &client, &history, &rendered);
            let data = tokio::time::timeout(Duration::from_secs(1), server.read_datagram())
                .await
                .expect("every valid screen frame must elicit an ACK")
                .unwrap();
            assert_eq!(data[0], DATAGRAM_SSP_ACK);
            assert_eq!(SspFrame::decode(&data[1..]).unwrap().ack_num, 2);
        }
    }

    #[tokio::test]
    async fn empty_datagram_drain_is_immediately_ready() {
        let (client, _server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let data = SspFrame::ack_only(1).encode();
        let drain = drain_ssp_frames(&client, &data);
        tokio::pin!(drain);
        assert!(matches!(
            poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx))).await,
            Poll::Ready(Some(_))
        ));
        client.close(0u32.into(), b"done");
        assert!(drain_ssp_frames(&client, b"invalid").await.is_none());
    }

    #[tokio::test]
    async fn datagram_drain_selects_newest_valid_frame_and_bounds_work() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        for new_num in 1..=66 {
            let data = if new_num == 10 {
                b"invalid".to_vec()
            } else {
                SspFrame {
                    new_num: if new_num == 20 { 1 } else { new_num },
                    ..SspFrame::ack_only(0)
                }
                .encode()
            };
            server.send_datagram(data.into()).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while client.stats().frame_rx.datagram < 66 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            drain_ssp_frames(&client, b"invalid").await.unwrap().new_num,
            64
        );
        let remaining = client.read_datagram().await.unwrap();
        assert_eq!(SspFrame::decode(&remaining).unwrap().new_num, 65);
        assert_eq!(
            drain_ssp_frames(&client, &remaining).await.unwrap().new_num,
            66
        );
    }
}
