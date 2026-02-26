use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::util::{
    extract_peer_cert, hex_decode, hex_encode, parse_stun_line, rand_session_id, rand_u16,
    send_ssp_frame, write_private_key,
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
fn filter_env_vars(env_vars: &[(String, String)]) -> Vec<(String, String)> {
    env_vars
        .iter()
        .filter(|(k, _)| is_allowed_env_var(k))
        .cloned()
        .collect()
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
    detached: DetachedSession,
    rows: u16,
    cols: u16,
) -> anyhow::Result<SessionTuple> {
    tracing::info!(rows, cols, "reattaching session");

    if detached.rows != rows || detached.cols != cols {
        let _ = detached.pty.resize(rows, cols);
        detached
            .terminal
            .lock()
            .expect("terminal lock poisoned")
            .resize(rows, cols);
    }

    session
        .send_control(&ControlMessage::SessionInfo {
            version: protocol::PROTOCOL_VERSION,
            session_id,
        })
        .await?;

    {
        let mut sender = detached.ssp_sender.lock().expect("sender lock poisoned");
        *sender = SspSender::new();
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
    let pty = PtySession::open_with_env(rows, cols, &filtered)?;
    let terminal = Arc::new(Mutex::new(RoseTerminal::new(rows, cols)));
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
                reattach_session(&mut session, session_id, detached, rows, cols).await?
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
            reattach_session(&mut session, session_id, detached, rows, cols).await?
        }
        _ => anyhow::bail!("unexpected handshake message"),
    };

    let mut pty_output = pty.subscribe_output();
    let pty_closed = pty.closed();
    let pty_writer = pty.clone_writer();

    let session_conn = session.connection().clone();
    let terminal_out = Arc::clone(&terminal);
    let sender_out = Arc::clone(&ssp_sender);
    let output_task = tokio::spawn(async move {
        let mut dirty = false;
        let mut last_send = tokio::time::Instant::now();
        let min_frame_interval = Duration::from_millis(5);
        let mut retransmit = tokio::time::interval(Duration::from_millis(20));
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
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return true,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(n, "output subscriber lagged");
                            dirty = true;
                        }
                    }
                }
                _ = retransmit.tick() => {}
                () = &mut pty_closed_notified => return true,
            }

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
                    return false;
                }
            } else {
                let sender = sender_out.lock().expect("sender lock poisoned");
                let frame = sender.generate_frame();
                drop(sender);
                if let Some(ref f) = frame
                    && !send_ssp_frame(f, &session_conn)
                {
                    return false;
                }
            }
        }
    });

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
        loop {
            tokio::select! {
                _ = &mut control_shutdown_rx => break,
                msg = session.recv_control() => {
                    match msg {
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
                _ = child_poll.tick() => {
                    if pty.try_wait().ok().flatten().is_some() {
                        break;
                    }
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
            shell_exited = result.unwrap_or(false);
            pty_from_control = None;
        },
        _ = &mut input_task => {
            shell_exited = false;
            pty_from_control = None;
        },
        _ = &mut scrollback_task => {
            shell_exited = false;
            pty_from_control = None;
        },
        result = &mut control_task => {
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

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
}
