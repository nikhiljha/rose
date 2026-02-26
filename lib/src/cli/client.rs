use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use crossterm::event::{Event, KeyCode};
use crossterm::terminal;

use super::input::{EscapeState, key_event_to_bytes};
use super::util::{RawModeGuard, extract_peer_cert, load_or_generate_client_cert};
use crate::config::{self, CertKeyPair, RosePaths};
use crate::protocol::{ClientSession, ControlMessage};
use crate::scrollback::{self, ScrollbackLine, ScrollbackReceiver};
use crate::ssp::{
    DATAGRAM_KEYSTROKE, DATAGRAM_SSP_ACK, ScreenState, SspFrame, SspReceiver, render_diff_ansi,
    render_full_redraw,
};
use crate::transport::QuicClient;

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
/// Defaults `TERM` to `xterm-256color` if unset (matches wezterm-term capabilities).
///
/// COVERAGE: Only called from `client_session_loop` which is excluded from
/// instrumented coverage (tested via e2e tests).
#[cfg_attr(coverage_nightly, coverage(off))]
fn collect_env_vars() -> Vec<(String, String)> {
    let mut vars = Vec::new();

    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    vars.push(("TERM".to_string(), term));

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
) -> anyhow::Result<()> {
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

    terminal::enable_raw_mode()?;
    let _raw_guard = RawModeGuard;

    client_session_loop(addr, host, client_config).await
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
/// When `client_cert` is `Some`, mutual TLS is used (for SSH bootstrap mode).
///
/// COVERAGE: CLI client session loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) async fn client_session_loop(
    addr: SocketAddr,
    server_name: &str,
    client_config: quinn::ClientConfig,
) -> anyhow::Result<()> {
    client_session_loop_inner(addr, server_name, client_config, None, None).await
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
    client_session_loop_inner(addr, server_name, client_config, Some(first_conn), None).await
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
    client_session_loop_inner(addr, server_name, client_config, Some(conn), Some(stun_ctx)).await
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
) -> anyhow::Result<()> {
    let mut session_id: Option<[u8; 16]> = None;
    let mut backoff = Duration::from_millis(100);
    let mut initial_conn = first_conn;
    const MAX_INITIAL_RETRIES: u32 = 10;
    let mut initial_retries: u32 = 0;

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
                    eprintln!("[RoSE: connection timed out]");
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

        {
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(b"\x1b[3J\x1b[2J\x1b[H");
            let _ = stdout.flush();
        }

        let receiver = Arc::new(Mutex::new(SspReceiver::new(rows)));
        let client_screen = Arc::new(Mutex::new(ScreenState::empty(rows)));

        let scrollback_rx = Arc::new(Mutex::new(ScrollbackReceiver::new()));
        let rendered_sb_count = Arc::new(Mutex::new(0usize));

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

        let stream_conn = session.connection().clone();
        let recv_stream = Arc::clone(&receiver);
        let client_stream = Arc::clone(&client_screen);
        let sb_rx_stream = Arc::clone(&scrollback_rx);
        let sb_count_stream = Arc::clone(&rendered_sb_count);
        let stream_task = tokio::spawn(async move {
            while let Ok(mut uni) = stream_conn.accept_uni().await {
                let mut type_buf = [0u8; 1];
                if uni.read_exact(&mut type_buf).await.is_err() {
                    continue;
                }
                match type_buf[0] {
                    scrollback::stream_type::SSP_FRAME => {
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

        let input_conn = session.connection().clone();
        let input_key_rx = Arc::clone(&key_rx);
        #[derive(Clone, Copy)]
        enum InputResult {
            Disconnect,
            Detach,
            ConnectionLost,
        }

        let input_task = tokio::spawn(async move {
            let mut escape = EscapeState::Normal;

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
                                    escape = EscapeState::AfterTilde;
                                } else if key.code == crossterm::event::KeyCode::Enter {
                                    if !send_keys(&input_conn, &key_bytes) {
                                        break;
                                    }
                                } else {
                                    escape = EscapeState::Normal;
                                    if !send_keys(&input_conn, &key_bytes) {
                                        break;
                                    }
                                }
                            }
                            EscapeState::AfterTilde => match key.code {
                                crossterm::event::KeyCode::Char('.') => {
                                    return InputResult::Disconnect;
                                }
                                crossterm::event::KeyCode::Char('d') => {
                                    return InputResult::Detach;
                                }
                                crossterm::event::KeyCode::Char('~') => {
                                    escape = EscapeState::Normal;
                                    if !send_keys(&input_conn, b"~") {
                                        break;
                                    }
                                }
                                crossterm::event::KeyCode::Char('?') => {
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
                                    escape = EscapeState::Normal;
                                    if !send_keys(&input_conn, b"~") {
                                        break;
                                    }
                                    if !send_keys(&input_conn, &key_bytes) {
                                        break;
                                    }
                                }
                            },
                        }
                    }
                    Some(Event::Resize(_, _)) => {}
                    None => break,
                    _ => {}
                }
            }
            InputResult::ConnectionLost
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

        let exit = match exit {
            SessionExit::ConnectionLost => {
                // The CONNECTION_CLOSE frame may still be in-flight when the
                // select fires.  Wait briefly so quinn can process it before
                // we inspect `close_reason()`.
                let close_reason = tokio::time::timeout(
                    Duration::from_millis(200),
                    check_conn.closed(),
                )
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

                let _ = terminal::disable_raw_mode();
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
                *screen = new_state;
            }

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
