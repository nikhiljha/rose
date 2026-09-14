use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use portable_pty::CommandBuilder;

use super::util::{
    FrameSendResult, SspFrameSender, extract_peer_cert, hex_decode, hex_encode, parse_stun_line,
    rand_session_id, rand_u16, write_private_key,
};
use crate::config::{self, CertKeyPair, RosePaths};
use crate::protocol::{self, ControlMessage, ServerSession};
use crate::pty::PtySession;
use crate::scrollback::{self, ScrollbackSender};
use crate::session::{DetachedSession, SessionStore};
use crate::ssp::{DATAGRAM_KEYSTROKE, DATAGRAM_SSP_ACK, SspFrame, SspSender};
use crate::terminal::RoseTerminal;
use crate::transport::QuicServer;

type SessionTuple = (
    [u8; 16],
    PtySession,
    Arc<Mutex<RoseTerminal>>,
    Arc<Mutex<SspSender>>,
    u16,
    u16,
);

/// Server-side allowlist for environment variables that clients may set.
const ALLOWED_ENV_VARS: &[&str] = &["TERM", "COLORTERM", "LANG"];

/// Returns true if the environment variable name is allowed by the server.
fn is_allowed_env_var(name: &str) -> bool {
    ALLOWED_ENV_VARS.contains(&name) || name.starts_with("LC_")
}

/// Filters environment variables from the client, keeping only safe entries.
///
/// TERM is always forced to `xterm-256color` because the server-side terminal
/// emulator (wezterm-term) is xterm-256color compatible.  Forwarding the
/// client's real TERM (e.g. `xterm-ghostty`) would make the shell emit escape
/// sequences that the emulator doesn't understand, causing rendering bugs.
fn filter_env_vars(env_vars: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = env_vars
        .iter()
        .filter(|(k, _)| is_allowed_env_var(k) && k != "TERM")
        .cloned()
        .collect();
    out.push(("TERM".to_string(), "xterm-256color".to_string()));
    out
}

/// COVERAGE: CLI server loop is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) async fn run_server(
    listen: SocketAddr,
    bootstrap: bool,
    hostname: Vec<String>,
) -> anyhow::Result<()> {
    let server = if bootstrap {
        use std::io::BufRead;

        let mut client_cert_hex = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut client_cert_hex)
            .map_err(|e| anyhow::anyhow!("failed to read client cert from stdin: {e}"))?;
        let client_cert_der = hex_decode(client_cert_hex.trim())?;

        let paths = RosePaths::resolve();
        std::fs::create_dir_all(&paths.config_dir)?;
        let cert_path = paths.config_dir.join("server.crt");
        let key_path = paths.config_dir.join("server.key");
        let san = if hostname.is_empty() {
            vec!["localhost".to_string()]
        } else {
            hostname.clone()
        };
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
            let cert = config::generate_self_signed_cert(&san)?;
            std::fs::write(&cert_path, cert.cert_der.as_ref())?;
            write_private_key(&key_path, &cert.key_der)?;
            cert
        };

        let auth_dir = tempfile::tempdir()?;
        std::fs::write(
            auth_dir.path().join("bootstrap-client.crt"),
            &client_cert_der,
        )?;

        let mut bound = None;
        for _ in 0..100 {
            let port = 60000 + (rand_u16() % 1000);
            let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
            match QuicServer::bind_mutual_tls(addr, server_cert.clone(), auth_dir.path()) {
                Ok(s) => {
                    bound = Some(s);
                    break;
                }
                Err(_) => continue,
            }
        }
        drop(auth_dir);

        let server =
            bound.ok_or_else(|| anyhow::anyhow!("failed to bind to any port in 60000-61000"))?;

        let addr = server.local_addr()?;
        let server_cert_hex = hex_encode(server.server_cert_der().as_ref());
        println!(
            "ROSE_BOOTSTRAP {port} {server_cert_hex}",
            port = addr.port()
        );

        server
    } else {
        let paths = RosePaths::resolve();
        std::fs::create_dir_all(&paths.config_dir)?;
        let cert_path = paths.config_dir.join("server.crt");
        let key_path = paths.config_dir.join("server.key");

        let san = if hostname.is_empty() {
            vec!["localhost".to_string()]
        } else {
            hostname
        };
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
            let cert = config::generate_self_signed_cert(&san)?;
            std::fs::write(&cert_path, cert.cert_der.as_ref())?;
            write_private_key(&key_path, &cert.key_der)?;
            eprintln!("Generated new certificate at {}", cert_path.display());
            cert
        };

        std::fs::create_dir_all(&paths.authorized_certs_dir)?;
        QuicServer::bind_mutual_tls(listen, cert, &paths.authorized_certs_dir)?
    };

    let addr = server.local_addr()?;

    if !bootstrap {
        eprintln!("RoSE server listening on {addr}");
    }

    let store = SessionStore::new();
    let rose_config =
        config::RoseConfig::load(&RosePaths::resolve().config_dir).unwrap_or_default();
    let max_sessions = rose_config.max_sessions;
    let idle_timeout = rose_config
        .session_idle_timeout_secs
        .map(Duration::from_secs);
    let active_sessions = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    if bootstrap {
        let punch_server = server.clone_for_punch();
        let rt_handle = tokio::runtime::Handle::current();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            let mut line = String::new();
            if stdin.lock().read_line(&mut line).is_ok()
                && !line.is_empty()
                && let Ok(client_addr) = parse_stun_line(line.trim())
            {
                let _guard = rt_handle.enter();
                punch_server.punch_hole(client_addr);
            }
        });
    }

    loop {
        let conn = match server.accept().await {
            Ok(Some(conn)) => conn,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                continue;
            }
        };
        let peer = conn.remote_address();
        tracing::info!(%peer, "new connection");

        if let Some(timeout) = idle_timeout {
            let pruned = store.prune_idle(timeout);
            if pruned > 0 {
                tracing::info!(pruned, "pruned idle detached sessions");
            }
        }
        let _ = store.prune_exited();

        if bootstrap {
            if let Err(e) = handle_server_session(conn, store.clone(), true).await {
                tracing::error!(%peer, "session error: {e}");
            }
            if store.is_empty() {
                break;
            }
        } else {
            if let Some(limit) = max_sessions {
                let total =
                    active_sessions.load(std::sync::atomic::Ordering::Relaxed) + store.len();
                if total >= limit {
                    tracing::warn!(%peer, total, limit, "max sessions reached, refusing");
                    conn.close(0u32.into(), b"max sessions reached");
                    continue;
                }
            }
            let store = store.clone();
            let active = Arc::clone(&active_sessions);
            active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::spawn(async move {
                if let Err(e) = handle_server_session(conn, store, false).await {
                    tracing::error!(%peer, "session error: {e}");
                }
                active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    Ok(())
}

/// COVERAGE: Tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn reattach_session(
    session: &mut ServerSession,
    session_id: [u8; 16],
    mut detached: DetachedSession,
    rows: u16,
    cols: u16,
    store: &SessionStore,
) -> anyhow::Result<SessionTuple> {
    tracing::info!(rows, cols, "reattaching session");

    if let Err(error) = prepare_reattach(session, session_id, &mut detached, rows, cols).await {
        let _ = store.insert(session_id, detached);
        return Err(error);
    }

    {
        let mut sender = detached.ssp_sender.lock().expect("sender lock poisoned");
        *sender = SspSender::new();

        // Push the current terminal state so the retransmit loop has a frame
        // to send immediately. Without this, a reconnecting client sees a
        // blank screen until the PTY produces new output.
        let state = detached
            .terminal
            .lock()
            .expect("terminal lock poisoned")
            .snapshot();
        sender.push_state(state);
    }

    Ok((
        session_id,
        detached.pty,
        detached.terminal,
        detached.ssp_sender,
        rows,
        cols,
    ))
}

async fn prepare_reattach(
    session: &mut ServerSession,
    session_id: [u8; 16],
    detached: &mut DetachedSession,
    rows: u16,
    cols: u16,
) -> anyhow::Result<()> {
    {
        let mut terminal = detached.terminal.lock().expect("terminal lock poisoned");
        if terminal.size() != (usize::from(rows), usize::from(cols)) {
            detached.pty.resize(rows, cols)?;
            terminal.resize(rows, cols);
        }
        detached.rows = rows;
        detached.cols = cols;
    }
    session
        .send_control(&ControlMessage::SessionInfo {
            version: protocol::PROTOCOL_VERSION,
            session_id,
        })
        .await?;
    Ok(())
}

/// COVERAGE: Tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn new_session(
    session: &mut ServerSession,
    rows: u16,
    cols: u16,
    env_vars: &[(String, String)],
) -> anyhow::Result<SessionTuple> {
    let session_id: [u8; 16] = rand_session_id();
    tracing::info!(rows, cols, "new session");

    let filtered = filter_env_vars(env_vars);
    let mut command = CommandBuilder::new_default_prog();
    for (key, value) in filtered {
        command.env(key, value);
    }
    let pty = PtySession::open_terminal(rows, cols, command)?;
    let terminal = Arc::clone(pty.terminal().expect("terminal enabled"));
    let ssp_sender = Arc::new(Mutex::new(SspSender::new()));

    session
        .send_control(&ControlMessage::SessionInfo {
            version: protocol::PROTOCOL_VERSION,
            session_id,
        })
        .await?;

    Ok((session_id, pty, terminal, ssp_sender, rows, cols))
}

/// COVERAGE: Session handler is tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn handle_server_session(
    conn: quinn::Connection,
    store: SessionStore,
    bootstrap: bool,
) -> anyhow::Result<()> {
    let peer_cert = extract_peer_cert(&conn);
    let (mut session, handshake) = ServerSession::accept_any(conn).await?;

    let (session_id, mut pty, terminal, ssp_sender, rows, cols) = match handshake {
        ControlMessage::Hello {
            version: _,
            rows,
            cols,
            env_vars,
        } => {
            let detached = if bootstrap {
                let candidate = store.remove_any();
                if let Some((id, ref det)) = candidate {
                    if det.owner_cert_der.as_deref() == peer_cert.as_deref() {
                        candidate
                    } else {
                        let _ = store.insert(id, candidate.unwrap().1);
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
            if let Some((session_id, detached)) = detached {
                reattach_session(&mut session, session_id, detached, rows, cols, &store).await?
            } else {
                new_session(&mut session, rows, cols, &env_vars).await?
            }
        }
        ControlMessage::Reconnect {
            version: _,
            rows,
            cols,
            session_id,
            env_vars: _,
        } => {
            let detached = store
                .remove(&session_id)
                .ok_or_else(|| anyhow::anyhow!("session not found for reconnect"))?;
            if detached.owner_cert_der.as_deref() != peer_cert.as_deref() {
                let _ = store.insert(session_id, detached);
                anyhow::bail!("client certificate does not match session owner");
            }
            reattach_session(&mut session, session_id, detached, rows, cols, &store).await?
        }
        _ => anyhow::bail!("unexpected handshake message"),
    };

    let pty_output = pty.subscribe_output();
    let pty_closed = pty.closed();
    let child_exited = Arc::new(tokio::sync::Notify::new());
    let pty_writer = pty.clone_writer();

    let session_conn = session.connection().clone();
    let terminal_out = Arc::clone(&terminal);
    let sender_out = Arc::clone(&ssp_sender);
    let resize_notify = Arc::new(tokio::sync::Notify::new());
    let resize_out = Arc::clone(&resize_notify);
    let output_task = tokio::spawn(forward_pty_output(
        pty_output,
        wait_for_output_end(pty_closed, Arc::clone(&child_exited)),
        terminal_out,
        sender_out,
        session_conn,
        resize_out,
    ));

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
            for line in &new_lines {
                let encoded = line.encode();
                if s.write_all(&encoded).await.is_err() {
                    return;
                }
            }
        }
    });

    let close_conn = session.connection().clone();

    let (control_shutdown_tx, mut control_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let terminal_ctrl = Arc::clone(&terminal);
    let control_task = tokio::spawn(async move {
        let mut child_poll = tokio::time::interval(Duration::from_millis(100));
        let mut child_reaped = false;
        loop {
            let message = session.recv_control();
            tokio::pin!(message);
            let result = loop {
                tokio::select! {
                    _ = &mut control_shutdown_rx => return pty,
                    msg = &mut message => break msg,
                    _ = child_poll.tick(), if !child_reaped => {
                        if pty.try_wait().ok().flatten().is_some() {
                            child_reaped = true;
                            child_exited.notify_one();
                        }
                    }
                }
            };
            match result {
                Ok(Some(ControlMessage::Resize { rows, cols })) => {
                    tracing::info!(rows, cols, "resize");
                    let mut terminal = terminal_ctrl.lock().expect("terminal lock poisoned");
                    if pty.resize(rows, cols).is_ok() {
                        terminal.resize(rows, cols);
                    }
                    resize_notify.notify_one();
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

    let mut output_task = output_task;
    let mut input_task = input_task;
    let mut scrollback_task = scrollback_task;
    let mut control_task = control_task;
    let mut control_shutdown_tx = Some(control_shutdown_tx);
    let mut shell_exited;
    let pty_from_control;
    tokio::select! {
        result = &mut output_task => {
            tracing::debug!(?session_id, ?result, "output task ended");
            shell_exited = result.unwrap_or(false);
            pty_from_control = None;
        },
        _ = &mut input_task => {
            tracing::debug!(?session_id, "input task ended");
            shell_exited = false;
            pty_from_control = None;
        },
        _ = &mut scrollback_task => {
            tracing::debug!(?session_id, "scrollback task ended");
            shell_exited = false;
            pty_from_control = None;
        },
        result = &mut control_task => {
            tracing::debug!(?session_id, success = result.is_ok(), "control task ended");
            shell_exited = false;
            pty_from_control = result.ok();
        },
    };

    output_task.abort();
    input_task.abort();
    scrollback_task.abort();

    let mut detached_pty = None;
    if !shell_exited {
        detached_pty = if let Some(pty) = pty_from_control {
            Some(pty)
        } else {
            if let Some(tx) = control_shutdown_tx.take() {
                let _ = tx.send(());
            }
            tracing::debug!(?session_id, "waiting for PTY ownership");
            control_task.await.ok()
        };

        if let Some(pty) = detached_pty.as_mut()
            && pty.try_wait().ok().flatten().is_some()
        {
            shell_exited = true;
            detached_pty = None;
        }
    }

    if shell_exited {
        close_conn.close(0u32.into(), b"shell exited");
        // Give the I/O driver a moment to flush the CONNECTION_CLOSE
        // frame so the client receives it before we return.
        tokio::time::sleep(Duration::from_millis(50)).await;
    } else {
        close_conn.close(0u32.into(), b"detaching session");
        if let Some(pty) = detached_pty {
            tracing::debug!(?session_id, "storing detached PTY");
            let _ = store.insert(
                session_id,
                DetachedSession {
                    pty,
                    terminal,
                    ssp_sender,
                    rows,
                    cols,
                    owner_cert_der: peer_cert,
                    detached_at: std::time::Instant::now(),
                },
            );
        }
    }

    Ok(())
}

async fn wait_for_output_end(
    pty_closed: Arc<tokio::sync::Notify>,
    child_exited: Arc<tokio::sync::Notify>,
) {
    let eof = pty_closed.notified();
    tokio::pin!(eof);
    tokio::select! {
        () = &mut eof => return,
        () = child_exited.notified() => {}
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), eof).await;
}

async fn forward_pty_output(
    mut pty_output: tokio::sync::broadcast::Receiver<bytes::Bytes>,
    output_end: impl Future<Output = ()>,
    terminal_out: Arc<Mutex<RoseTerminal>>,
    sender_out: Arc<Mutex<SspSender>>,
    session_conn: quinn::Connection,
    resize_out: Arc<tokio::sync::Notify>,
) -> bool {
    let frame_sender = SspFrameSender::new(session_conn.clone());
    let mut dirty = false;
    let mut last_send = tokio::time::Instant::now();
    let min_frame_interval = Duration::from_millis(5);
    let mut retransmit = tokio::time::interval(Duration::from_millis(20));
    tokio::pin!(output_end);
    loop {
        let retransmit_due = tokio::select! {
            result = pty_output.recv() => {
                match result {
                    Ok(_) => {
                        dirty = true;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(n, "output subscriber lagged");
                        dirty = true;
                    }
                }
                false
            }
            () = resize_out.notified() => { dirty = true; false },
            () = tokio::time::sleep_until(last_send + min_frame_interval), if dirty => false,
            _ = retransmit.tick() => true,
            () = &mut output_end => break,
        };

        if dirty && last_send.elapsed() >= min_frame_interval {
            dirty = false;
            let state = terminal_out
                .lock()
                .expect("terminal lock poisoned")
                .snapshot();
            last_send = tokio::time::Instant::now();

            sender_out
                .lock()
                .expect("sender lock poisoned")
                .push_state(state);
        } else if !retransmit_due {
            continue;
        }
        let frame = sender_out
            .lock()
            .expect("sender lock poisoned")
            .generate_frame();
        match frame_sender.send(frame.as_ref()) {
            FrameSendResult::Sent => {}
            FrameSendResult::TooLarge => {
                tracing::warn!("dropping unrepresentable screen update");
            }
            FrameSendResult::Disconnected => return false,
        }
    }
    drop(frame_sender);
    let state = terminal_out
        .lock()
        .expect("terminal lock poisoned")
        .snapshot()
        .bounded_for_transport();
    let diff = state.diff_from_empty();
    let new_num = {
        let mut sender = sender_out.lock().expect("sender lock poisoned");
        sender.push_state(state);
        sender.current_num()
    };
    let frame = SspFrame {
        old_num: 0,
        new_num,
        ack_num: 0,
        diff: Some(diff),
    };
    match tokio::time::timeout(
        Duration::from_secs(2),
        deliver_final_frame(&session_conn, &sender_out, &frame),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::debug!(%error, "final screen delivery failed"),
        Err(_) => tracing::warn!("final screen delivery timed out"),
    }
    true
}

async fn deliver_final_frame(
    conn: &quinn::Connection,
    sender: &Mutex<SspSender>,
    frame: &SspFrame,
) -> anyhow::Result<()> {
    let data = frame.encode_for_stream();
    let mut retry = tokio::time::interval(Duration::from_millis(100));
    let mut check_ack = tokio::time::interval(Duration::from_millis(10));
    loop {
        tokio::select! {
            _ = retry.tick() => {
                let mut stream = conn.open_uni().await?;
                stream.write_all(&[scrollback::stream_type::SSP_FRAME]).await?;
                stream.write_all(&data).await?;
                stream.finish()?;
                if stream.stopped().await?.is_some() {
                    anyhow::bail!("client rejected final screen");
                }
            }
            _ = check_ack.tick() => {
                if sender.lock().expect("sender lock poisoned").generate_frame().is_none() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    use super::*;
    use crate::protocol::ClientSession;
    use crate::ssp::SspReceiver;
    use crate::testutil::MtlsFixture;
    use crate::transport::QuicClient;

    async fn receive_stream_frame(conn: &quinn::Connection) -> SspFrame {
        let mut stream = conn.accept_uni().await.unwrap();
        let mut kind = [0];
        stream.read_exact(&mut kind).await.unwrap();
        assert_eq!(kind[0], scrollback::stream_type::SSP_FRAME);
        let mut length = [0; 4];
        stream.read_exact(&mut length).await.unwrap();
        let data = stream
            .read_to_end(u32::from_be_bytes(length) as usize)
            .await
            .unwrap();
        SspFrame::decode(&data).unwrap()
    }

    struct NativeSession {
        session: ClientSession,
        task: tokio::task::JoinHandle<anyhow::Result<()>>,
        store: SessionStore,
        session_id: [u8; 16],
        _fixture: MtlsFixture,
        _client: QuicClient,
    }

    impl NativeSession {
        async fn new() -> Self {
            let fixture = MtlsFixture::new();
            let store = SessionStore::new();
            let client = QuicClient::new().unwrap();
            let (server_conn, client_conn) =
                tokio::join!(fixture.server.accept(), fixture.connect(&client));
            let task = tokio::spawn(handle_server_session(
                server_conn.unwrap().unwrap(),
                store.clone(),
                false,
            ));
            let mut session = ClientSession::connect(client_conn, 5, 80, vec![])
                .await
                .unwrap();
            let Some(ControlMessage::SessionInfo { session_id, .. }) =
                session.recv_control().await.unwrap()
            else {
                panic!("missing session metadata");
            };
            Self {
                session,
                task,
                store,
                session_id,
                _fixture: fixture,
                _client: client,
            }
        }

        fn send_command(&self, command: &str) {
            let mut data = vec![DATAGRAM_KEYSTROKE];
            data.extend_from_slice(command.as_bytes());
            data.push(b'\r');
            self.session.send_input(data.into()).unwrap();
        }

        async fn wait_for_marker(&self, marker: &str) {
            let mut receiver = SspReceiver::new(5);
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let data = self.session.recv_output().await.unwrap();
                    receiver
                        .process_frame(&SspFrame::decode(&data).unwrap())
                        .unwrap();
                    if receiver.state().rows.iter().any(|row| row == marker) {
                        break;
                    }
                }
            })
            .await
            .expect("remote program did not produce its marker");
        }
    }

    #[tokio::test]
    async fn detached_output_reaches_the_authoritative_terminal() {
        let native = NativeSession::new().await;
        let gate_dir = tempfile::tempdir().unwrap();
        let gate = gate_dir.path().join("continue");
        native.send_command(&format!(
            "printf '\\033[0m\\033[2J\\033[HREADY'; \
             while [ ! -e '{}' ]; do sleep 0.01; done; \
             printf '\\033[0m\\033[2J\\033[HAFTER_DETACH\\n'",
            gate.display()
        ));
        native.wait_for_marker("READY").await;
        native.session.connection().close(0u32.into(), b"detach");
        tokio::time::timeout(Duration::from_secs(5), native.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let detached = native.store.remove(&native.session_id).unwrap();
        std::fs::write(gate, b"continue").unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if detached
                    .terminal
                    .lock()
                    .unwrap()
                    .snapshot()
                    .rows
                    .iter()
                    .any(|row| row == "AFTER_DETACH")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("detached PTY output was not interpreted");

        let _ = native.store.insert(native.session_id, detached);
        let (server_conn, client_conn) = tokio::join!(
            native._fixture.server.accept(),
            native._fixture.connect(&native._client)
        );
        let task = tokio::spawn(handle_server_session(
            server_conn.unwrap().unwrap(),
            native.store.clone(),
            false,
        ));
        let mut session = ClientSession::reconnect(client_conn, 5, 80, native.session_id, vec![])
            .await
            .unwrap();
        assert!(matches!(
            session.recv_control().await.unwrap(),
            Some(ControlMessage::SessionInfo { .. })
        ));
        let data = tokio::time::timeout(Duration::from_secs(5), session.recv_output())
            .await
            .unwrap()
            .unwrap();
        let mut receiver = SspReceiver::new(5);
        receiver
            .process_frame(&SspFrame::decode(&data).unwrap())
            .unwrap();
        assert_eq!(receiver.state().rows[0], "AFTER_DETACH");
        session.connection().close(0u32.into(), b"done");
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn terminal_queries_receive_a_response_from_the_authority() {
        let native = NativeSession::new().await;
        native.send_command(
            "stty -echo -icanon min 1 time 0; \
             printf '\\033[0m\\033[2J\\033[H\\033[6n'; \
             reply=$(dd bs=1 count=6 2>/dev/null); stty sane; \
             if [ \"$reply\" = \"$(printf '\\033[1;1R')\" ]; \
             then printf 'QUERY_OK\\n'; fi",
        );
        native.wait_for_marker("QUERY_OK").await;
        native.session.connection().close(0u32.into(), b"done");
        native.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn closed_pty_delivers_unpublished_state_over_a_reliable_stream() {
        let (client_conn, server_conn, _fixture, _client) = crate::testutil::connected_pair().await;
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let terminal = Arc::new(Mutex::new(RoseTerminal::new(5, 20)));
        let sender = Arc::new(Mutex::new(SspSender::new()));
        let closed = Arc::new(tokio::sync::Notify::new());
        let output = forward_pty_output(
            rx,
            closed.notified(),
            Arc::clone(&terminal),
            Arc::clone(&sender),
            server_conn.clone(),
            Arc::new(tokio::sync::Notify::new()),
        );
        tokio::pin!(output);
        terminal.lock().unwrap().advance(b"first");
        tx.send(bytes::Bytes::from_static(b"first")).unwrap();
        assert!(
            poll_fn(|cx| Poll::Ready(output.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        terminal.lock().unwrap().advance(b"\rfinal");
        closed.notify_one();

        let receive = async {
            let frame = receive_stream_frame(&client_conn).await;
            let mut receiver = SspReceiver::new(5);
            receiver.process_frame(&frame).unwrap();
            assert_eq!(receiver.state().rows[0], "final");
            let retry = receive_stream_frame(&client_conn).await;
            assert_eq!(retry, frame);
            let mut ack = vec![DATAGRAM_SSP_ACK];
            ack.extend_from_slice(&SspFrame::ack_only(receiver.ack_num()).encode());
            client_conn.send_datagram(ack.into()).unwrap();
            let ack = server_conn.read_datagram().await.unwrap();
            sender
                .lock()
                .unwrap()
                .process_ack(SspFrame::decode(&ack[1..]).unwrap().ack_num);
        };
        let (exited, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(output, receive)
        })
        .await
        .expect("final authoritative screen was not delivered");
        assert!(exited);
    }

    #[tokio::test]
    async fn unrepresentable_screen_does_not_end_a_healthy_connection() {
        let (client_conn, server_conn, _fixture, _client) = crate::testutil::connected_pair().await;
        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        let mut protocol = SspSender::new();
        protocol.push_state(crate::ssp::ScreenState {
            viewport: None,
            rows: vec!["x".repeat(60_000); 300],
            cursor_x: 0,
            cursor_y: 0,
        });
        let output = forward_pty_output(
            rx,
            std::future::pending(),
            Arc::new(Mutex::new(RoseTerminal::new(300, 300))),
            Arc::new(Mutex::new(protocol)),
            server_conn,
            Arc::new(tokio::sync::Notify::new()),
        );
        tokio::pin!(output);
        let frame = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                result = &mut output => panic!("healthy output forwarder ended: {result}"),
                data = client_conn.read_datagram() => SspFrame::decode(&data.unwrap()).unwrap(),
            }
        })
        .await
        .expect("oversized screen was not replaced with a display notice");
        assert!(frame.encode().len() <= crate::ssp::MAX_STREAM_FRAME_BYTES);
        assert!(
            poll_fn(|cx| Poll::Ready(output.as_mut().poll(cx)))
                .await
                .is_pending()
        );
    }

    #[tokio::test]
    async fn exiting_shell_waits_for_final_screen_acknowledgment() {
        let native = NativeSession::new().await;
        native.send_command("printf '\\033[0m\\033[2J\\033[HFINAL_OUTPUT\\n'; exit");
        let frame = tokio::time::timeout(
            Duration::from_secs(5),
            receive_stream_frame(native.session.connection()),
        )
        .await
        .unwrap();
        let mut receiver = SspReceiver::new(5);
        receiver.process_frame(&frame).unwrap();
        assert_eq!(receiver.state().rows[0], "FINAL_OUTPUT");
        assert!(!native.task.is_finished());
        let mut ack = vec![DATAGRAM_SSP_ACK];
        ack.extend_from_slice(&SspFrame::ack_only(receiver.ack_num()).encode());
        native.session.send_input(ack.into()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), native.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(native.store.is_empty());
    }

    #[tokio::test]
    async fn rejected_final_stream_ends_delivery() {
        let (client_conn, server_conn, _fixture, _client) = crate::testutil::connected_pair().await;
        let (_tx, rx) = tokio::sync::broadcast::channel(16);
        let terminal = Arc::new(Mutex::new(RoseTerminal::new(512, 256)));
        terminal
            .lock()
            .unwrap()
            .advance("x".repeat(128 * 1024).as_bytes());
        let output = forward_pty_output(
            rx,
            std::future::ready(()),
            terminal,
            Arc::new(Mutex::new(SspSender::new())),
            server_conn,
            Arc::new(tokio::sync::Notify::new()),
        );
        let reject = async {
            let mut stream = client_conn.accept_uni().await.unwrap();
            let mut kind = [0];
            stream.read_exact(&mut kind).await.unwrap();
            assert_eq!(kind[0], scrollback::stream_type::SSP_FRAME);
            stream.stop(42u32.into()).unwrap();
        };
        let (exited, ()) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(output, reject)
        })
        .await
        .expect("rejected final stream kept retrying");
        assert!(exited);
    }

    #[tokio::test]
    async fn child_polling_preserves_fragmented_control_messages() {
        let (client_conn, server_conn, _fixture, _client) = crate::testutil::connected_pair().await;
        let task = tokio::spawn(handle_server_session(
            server_conn,
            SessionStore::new(),
            false,
        ));
        let (mut send, mut recv) = client_conn.open_bi().await.unwrap();
        protocol::write_control(
            &mut send,
            &ControlMessage::Hello {
                version: protocol::PROTOCOL_VERSION,
                rows: 5,
                cols: 20,
                env_vars: vec![],
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            protocol::read_control(&mut recv).await.unwrap(),
            Some(ControlMessage::SessionInfo { .. })
        ));
        let resize = ControlMessage::Resize { rows: 8, cols: 20 }.encode();
        let length = u32::try_from(resize.len()).unwrap().to_be_bytes();
        send.write_all(&length[..2]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        send.write_all(&length[2..]).await.unwrap();
        send.write_all(&resize[..2]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        send.write_all(&resize[2..]).await.unwrap();
        let mut receiver = SspReceiver::new(5);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let data = client_conn.read_datagram().await.unwrap();
                receiver
                    .process_frame(&SspFrame::decode(&data).unwrap())
                    .unwrap();
                if receiver.state().rows.len() == 8 {
                    break;
                }
            }
        })
        .await
        .expect("child polling interrupted a partial resize message");
        client_conn.close(0u32.into(), b"done");
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn exiting_shell_is_not_held_open_by_a_descendant() {
        let native = NativeSession::new().await;
        native.send_command(
            "sh -c 'trap \"\" HUP; printf \"\\033[2J\\033[HHOLDER_READY\\n\"; sleep 8' &",
        );
        native.wait_for_marker("HOLDER_READY").await;
        native.send_command("printf '\\033[2J\\033[HCHILD_FINAL\\n'; exit");
        let frame = tokio::time::timeout(
            Duration::from_secs(3),
            receive_stream_frame(native.session.connection()),
        )
        .await
        .expect("descendant held the exited shell open");
        let mut receiver = SspReceiver::new(5);
        receiver.process_frame(&frame).unwrap();
        assert_eq!(receiver.state().rows[0], "CHILD_FINAL");
        let mut ack = vec![DATAGRAM_SSP_ACK];
        ack.extend_from_slice(&SspFrame::ack_only(receiver.ack_num()).encode());
        native.session.send_input(ack.into()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), native.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(native.store.is_empty());
    }

    #[tokio::test]
    async fn exiting_shell_does_not_wait_forever_for_a_screen_acknowledgment() {
        let native = NativeSession::new().await;
        native.send_command("exit");
        let _ = receive_stream_frame(native.session.connection()).await;
        assert!(!native.task.is_finished());
        tokio::time::timeout(Duration::from_secs(3), native.task)
            .await
            .expect("unacknowledged final screen kept the session alive")
            .unwrap()
            .unwrap();
        assert!(native.store.is_empty());
    }

    #[tokio::test]
    async fn failed_reattach_keeps_the_shell_available_for_retry() {
        let (client_conn, server_conn, fixture, client) = crate::testutil::connected_pair().await;
        let _client_session = ClientSession::connect(client_conn.clone(), 5, 20, vec![])
            .await
            .unwrap();
        let (mut server_session, ..) = ServerSession::accept(server_conn.clone()).await.unwrap();
        client_conn.close(0u32.into(), b"lost during reattach");
        server_conn.closed().await;
        let store = SessionStore::new();
        let pty = PtySession::open_command(5, 20, "cat", &[]).unwrap();
        let terminal = Arc::new(Mutex::new(RoseTerminal::new(5, 20)));
        terminal.lock().unwrap().advance(b"preserved");
        let detached = DetachedSession {
            pty,
            terminal,
            ssp_sender: Arc::new(Mutex::new(SspSender::new())),
            rows: 5,
            cols: 20,
            owner_cert_der: Some(fixture.client_cert.cert_der.to_vec()),
            detached_at: std::time::Instant::now(),
        };
        let session_id = [17; 16];
        assert!(
            reattach_session(&mut server_session, session_id, detached, 8, 40, &store)
                .await
                .is_err()
        );
        let mut retained = store
            .remove(&session_id)
            .expect("failed handshake destroyed detached session");
        assert!(retained.pty.try_wait().unwrap().is_none());
        assert_eq!(retained.terminal.lock().unwrap().size(), (8, 40));
        assert_eq!((retained.rows, retained.cols), (8, 40));
        let _ = store.insert(session_id, retained);

        let (server_conn, client_conn) =
            tokio::join!(fixture.server.accept(), fixture.connect(&client));
        let task = tokio::spawn(handle_server_session(
            server_conn.unwrap().unwrap(),
            store,
            false,
        ));
        let mut session = ClientSession::reconnect(client_conn, 5, 20, session_id, vec![])
            .await
            .unwrap();
        assert!(matches!(
            session.recv_control().await.unwrap(),
            Some(ControlMessage::SessionInfo { .. })
        ));
        let data = session.recv_output().await.unwrap();
        let mut receiver = SspReceiver::new(5);
        receiver
            .process_frame(&SspFrame::decode(&data).unwrap())
            .unwrap();
        assert_eq!(receiver.state().rows[0], "preserved");
        assert_eq!(receiver.state().rows.len(), 5);
        session.connection().close(0u32.into(), b"done");
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pending_output_obeys_frame_deadline() {
        let (client_conn, server_conn, _fixture, _client) = crate::testutil::connected_pair().await;
        tokio::time::pause();
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let terminal = Arc::new(Mutex::new(RoseTerminal::new(5, 20)));
        let sender = Arc::new(Mutex::new(SspSender::new()));
        let resized = Arc::new(tokio::sync::Notify::new());
        let closed = Arc::new(tokio::sync::Notify::new());
        let output = forward_pty_output(
            rx,
            closed.notified(),
            Arc::clone(&terminal),
            Arc::clone(&sender),
            server_conn,
            Arc::clone(&resized),
        );
        tokio::pin!(output);
        terminal.lock().unwrap().advance(b"first");
        tx.send(bytes::Bytes::from_static(b"first")).unwrap();
        assert!(
            poll_fn(|cx| Poll::Ready(output.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        // Tokio's timer wheel rounds deadlines up to the next millisecond.
        for (advance_ms, expected_num) in [(4, 0), (2, 1)] {
            tokio::time::advance(Duration::from_millis(advance_ms)).await;
            assert!(
                poll_fn(|cx| Poll::Ready(output.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            assert_eq!(sender.lock().unwrap().current_num(), expected_num);
        }
        terminal.lock().unwrap().resize(8, 20);
        resized.notify_one();
        assert!(
            poll_fn(|cx| Poll::Ready(output.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        assert_eq!(sender.lock().unwrap().current_num(), 1);
        tokio::time::advance(Duration::from_millis(6)).await;
        assert!(
            poll_fn(|cx| Poll::Ready(output.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        assert_eq!(sender.lock().unwrap().current_num(), 2);
        assert_eq!(
            sender
                .lock()
                .unwrap()
                .generate_frame()
                .unwrap()
                .diff
                .unwrap()
                .total_rows,
            8
        );
        tokio::time::advance(Duration::from_millis(9)).await;
        assert!(
            poll_fn(|cx| Poll::Ready(output.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        assert_eq!(sender.lock().unwrap().current_num(), 2);
        tokio::time::resume();
        for expected in [1, 2, 2] {
            let data = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(SspFrame::decode(&data).unwrap().new_num, expected);
        }
        closed.notify_one();
        assert!(output.await);
    }

    #[tokio::test]
    async fn idle_session_resize_sends_updated_screen() {
        let fixture = MtlsFixture::new();
        let store = SessionStore::new();
        let session_id = [1; 16];
        let pty = PtySession::open_command(5, 20, "cat", &[]).unwrap();
        let terminal = Arc::new(Mutex::new(RoseTerminal::new(5, 20)));
        terminal.lock().unwrap().advance(b"idle");
        let _ = store.insert(
            session_id,
            DetachedSession {
                pty,
                terminal,
                ssp_sender: Arc::new(Mutex::new(SspSender::new())),
                rows: 5,
                cols: 20,
                owner_cert_der: Some(fixture.client_cert.cert_der.to_vec()),
                detached_at: std::time::Instant::now(),
            },
        );

        let client = QuicClient::new().unwrap();
        let (server_conn, client_conn) =
            tokio::join!(fixture.server.accept(), fixture.connect(&client));
        let server_task = tokio::spawn(handle_server_session(
            server_conn.unwrap().unwrap(),
            store,
            false,
        ));
        let mut session = ClientSession::reconnect(client_conn, 5, 20, session_id, vec![])
            .await
            .unwrap();
        let info = tokio::time::timeout(Duration::from_secs(5), session.recv_control())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(info, Some(ControlMessage::SessionInfo { .. })));

        let mut receiver = SspReceiver::new(5);
        let output = tokio::time::timeout(Duration::from_secs(5), session.recv_output())
            .await
            .unwrap()
            .unwrap();
        receiver
            .process_frame(&SspFrame::decode(&output).unwrap())
            .unwrap();
        assert!(receiver.state().rows[0].contains("idle"));
        let mut ack = vec![DATAGRAM_SSP_ACK];
        ack.extend_from_slice(&SspFrame::ack_only(receiver.ack_num()).encode());
        session.send_input(ack.into()).unwrap();
        session
            .send_control(&ControlMessage::Resize { rows: 8, cols: 20 })
            .await
            .unwrap();

        let resized = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let output = session.recv_output().await.unwrap();
                receiver
                    .process_frame(&SspFrame::decode(&output).unwrap())
                    .unwrap();
                if receiver.state().rows.len() == 8 {
                    break;
                }
            }
        })
        .await;
        session
            .send_control(&ControlMessage::Goodbye)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(resized.is_ok(), "resize was not sent without PTY output");
        assert!(receiver.state().rows[0].contains("idle"));
    }

    #[test]
    fn filter_env_vars_allows_safe_vars() {
        let input = vec![
            ("TERM".into(), "xterm".into()),
            ("LANG".into(), "en_US.UTF-8".into()),
            ("COLORTERM".into(), "truecolor".into()),
            ("LC_ALL".into(), "C".into()),
        ];
        let filtered = filter_env_vars(&input);
        assert_eq!(filtered.len(), 4);
    }

    #[test]
    fn filter_env_vars_blocks_dangerous_vars() {
        let input = vec![
            ("TERM".into(), "xterm".into()),
            ("LD_PRELOAD".into(), "/evil.so".into()),
            ("PATH".into(), "/tmp/evil".into()),
            ("LD_LIBRARY_PATH".into(), "/tmp".into()),
            ("SHELL".into(), "/bin/evil".into()),
        ];
        let filtered = filter_env_vars(&input);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, "TERM");
    }

    #[test]
    fn filter_env_vars_overrides_term_to_xterm_256color() {
        // The server-side wezterm-term emulator is xterm-256color compatible.
        // If the client forwards a different TERM (e.g. xterm-ghostty),
        // the shell may emit escape sequences that wezterm-term doesn't
        // understand, causing rendering bugs.
        let input = vec![
            ("TERM".into(), "xterm-ghostty".into()),
            ("COLORTERM".into(), "truecolor".into()),
        ];
        let filtered = filter_env_vars(&input);
        let term = filtered
            .iter()
            .find(|(k, _)| k == "TERM")
            .expect("TERM must be present");
        assert_eq!(
            term.1, "xterm-256color",
            "TERM must always be xterm-256color to match the server-side wezterm-term emulator"
        );
    }

    #[test]
    fn filter_env_vars_adds_term_when_missing() {
        // Even if the client doesn't send TERM at all, the server should
        // ensure it's set to xterm-256color for the PTY.
        let input = vec![("LANG".into(), "en_US.UTF-8".into())];
        let filtered = filter_env_vars(&input);
        let term = filtered
            .iter()
            .find(|(k, _)| k == "TERM")
            .expect("TERM must be present");
        assert_eq!(term.1, "xterm-256color");
    }
}
