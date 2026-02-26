//! Integration tests ported from the mosh project's test suite.
//!
//! These tests exercise end-to-end behavior that requires `RoSE`'s transport,
//! protocol, and PTY layers working together. They are expected to fail until
//! those layers are implemented.
//!
//! Each test is annotated with the mosh test it was ported from.

mod common;
use common::MtlsFixture;

// ---------------------------------------------------------------------------
// Ported from mosh: window-resize.test
//
// Tests that window resize events (SIGWINCH) propagate correctly from the
// client through the protocol to the server PTY, and that the application
// running in the PTY redraws correctly.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_window_resize() {
    use bytes::Bytes;
    use rose::protocol::{ClientSession, ControlMessage, ServerSession};
    use rose::pty::PtySession;
    use rose::ssp::DATAGRAM_KEYSTROKE;
    use rose::transport::QuicClient;
    use std::time::Duration;

    let fixture = MtlsFixture::new();

    let server_task = tokio::spawn({
        let endpoint = fixture.server.endpoint.clone();
        async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let (mut session, rows, cols) = ServerSession::accept(conn).await.unwrap();
            let pty = PtySession::open_command(rows, cols, "sh", &[]).unwrap();
            let pty_writer = pty.clone_writer();
            let mut rx = pty.subscribe_output();

            // Forward PTY output -> client datagrams
            let output_conn = session.connection().clone();
            let output_fwd = tokio::spawn(async move {
                while let Ok(chunk) = rx.recv().await {
                    if output_conn
                        .send_datagram(Bytes::from(chunk.to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            });

            // Forward client datagrams -> PTY input (strip keystroke prefix)
            let input_conn = session.connection().clone();
            let input_fwd = tokio::spawn(async move {
                while let Ok(data) = input_conn.read_datagram().await {
                    if data.is_empty() {
                        continue;
                    }
                    if data[0] == DATAGRAM_KEYSTROKE {
                        let mut w = pty_writer.lock().expect("writer lock poisoned");
                        if std::io::Write::write_all(&mut *w, &data[1..]).is_err() {
                            break;
                        }
                        let _ = std::io::Write::flush(&mut *w);
                    }
                }
            });

            // Handle control messages (resize)
            let control_task = tokio::spawn(async move {
                loop {
                    match session.recv_control().await {
                        Ok(Some(ControlMessage::Resize { rows, cols })) => {
                            let _ = pty.resize(rows, cols);
                        }
                        Ok(Some(ControlMessage::Goodbye) | None) => break,
                        Ok(Some(_)) => {}
                        Err(_) => break,
                    }
                }
            });

            tokio::select! {
                _ = output_fwd => {}
                _ = input_fwd => {}
                _ = control_task => {}
            }
        }
    });

    let client = QuicClient::new().unwrap();
    let client_conn = fixture.connect(&client).await;
    let mut client_session = ClientSession::connect(client_conn, 24, 80, vec![])
        .await
        .unwrap();

    // Wait for shell to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send resize to 24x120
    client_session
        .send_control(&ControlMessage::Resize {
            rows: 24,
            cols: 120,
        })
        .await
        .unwrap();

    // Wait for resize to propagate
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send "tput cols\n" as keystroke to query the column count
    let mut data = vec![DATAGRAM_KEYSTROKE];
    data.extend_from_slice(b"tput cols\n");
    client_session.send_input(Bytes::from(data)).unwrap();

    // Read output until we see "120"
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut collected = String::new();
    let mut found = false;

    loop {
        let timeout = tokio::time::timeout_at(deadline, client_session.recv_output()).await;
        match timeout {
            Ok(Ok(data)) => {
                collected.push_str(&String::from_utf8_lossy(&data));
                if collected.contains("120") {
                    found = true;
                    break;
                }
            }
            _ => break,
        }
    }

    assert!(
        found,
        "expected '120' in output after resize, got: {collected:?}"
    );

    server_task.abort();
}

// ---------------------------------------------------------------------------
// Ported from mosh: e2e-success.test
//
// Basic smoke test: client connects to server, runs a command, and
// disconnects cleanly.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_basic_connection() {
    use bytes::Bytes;
    use rose::protocol::{ClientSession, ServerSession};
    use rose::pty::PtySession;
    use rose::transport::QuicClient;
    use std::time::Duration;

    let fixture = MtlsFixture::new();

    let server_task = tokio::spawn({
        let endpoint = fixture.server.endpoint.clone();
        async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let (session, rows, cols) = ServerSession::accept(conn).await.unwrap();
            let pty = PtySession::open_command(rows, cols, "cat", &[]).unwrap();
            let pty_writer = pty.clone_writer();
            let mut rx = pty.subscribe_output();

            let output_conn = session.connection().clone();
            let output_fwd = tokio::spawn(async move {
                while let Ok(chunk) = rx.recv().await {
                    if output_conn
                        .send_datagram(Bytes::from(chunk.to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            });

            let input_conn = session.connection().clone();
            let input_fwd = tokio::spawn(async move {
                while let Ok(data) = input_conn.read_datagram().await {
                    let mut w = pty_writer.lock().expect("writer lock poisoned");
                    if std::io::Write::write_all(&mut *w, &data).is_err() {
                        break;
                    }
                    let _ = std::io::Write::flush(&mut *w);
                }
            });

            tokio::select! {
                _ = output_fwd => {}
                _ = input_fwd => {}
            }

            drop(pty);
            drop(session);
        }
    });

    let client = QuicClient::new().unwrap();
    let client_conn = fixture.connect(&client).await;
    let client_session = ClientSession::connect(client_conn, 24, 80, vec![])
        .await
        .unwrap();

    // Send some input
    client_session
        .send_input(Bytes::from_static(b"hello_e2e\n"))
        .unwrap();

    // Read output — cat should echo our input back
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut collected = String::new();
    let mut found = false;

    loop {
        let timeout = tokio::time::timeout_at(deadline, client_session.recv_output()).await;
        match timeout {
            Ok(Ok(data)) => {
                collected.push_str(&String::from_utf8_lossy(&data));
                if collected.contains("hello_e2e") {
                    found = true;
                    break;
                }
            }
            _ => break,
        }
    }

    assert!(
        found,
        "expected 'hello_e2e' in echoed output, got: {collected:?}"
    );

    server_task.abort();
}

// ---------------------------------------------------------------------------
// Ported from mosh: repeat.test
//
// Tests repeated connect/disconnect cycles to verify no resource leaks.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_repeat_connections() {
    use bytes::Bytes;
    use rose::protocol::{ClientSession, ServerSession};
    use rose::pty::PtySession;
    use rose::transport::QuicClient;
    use std::time::Duration;

    for i in 0..5 {
        let marker = format!("repeat_marker_{i}");

        let fixture = MtlsFixture::new();

        let marker_clone = marker.clone();
        let server_task = tokio::spawn({
            let endpoint = fixture.server.endpoint.clone();
            async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let (session, rows, cols) = ServerSession::accept(conn).await.unwrap();
                let pty = PtySession::open_command(rows, cols, "echo", &[&marker_clone]).unwrap();
                let mut rx = pty.subscribe_output();

                let output_conn = session.connection().clone();
                while let Ok(chunk) = rx.recv().await {
                    if output_conn
                        .send_datagram(Bytes::from(chunk.to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }

                drop(pty);
                drop(session);
            }
        });

        let client = QuicClient::new().unwrap();
        let client_conn = fixture.connect(&client).await;
        let client_session = ClientSession::connect(client_conn, 24, 80, vec![])
            .await
            .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut collected = String::new();
        let mut found = false;

        loop {
            let timeout = tokio::time::timeout_at(deadline, client_session.recv_output()).await;
            match timeout {
                Ok(Ok(data)) => {
                    collected.push_str(&String::from_utf8_lossy(&data));
                    if collected.contains(&marker) {
                        found = true;
                        break;
                    }
                }
                _ => break,
            }
        }

        assert!(
            found,
            "iteration {i}: expected '{marker}' in output, got: {collected:?}"
        );

        server_task.abort();
    }
}

// ---------------------------------------------------------------------------
// Ported from mosh: network-no-diff.test
//
// Regression test: the server should not spin CPU when the screen state
// has not changed (e.g., cursor blink writes overwriting the same character).
// ---------------------------------------------------------------------------

#[test]
fn protocol_no_diff_no_spin() {
    use rose::ssp::SspSender;
    use rose::terminal::RoseTerminal;

    let mut term = RoseTerminal::new(24, 80);
    let mut sender = SspSender::new();

    // Write initial state
    term.advance(b"x");
    let snap1 = term.snapshot();
    sender.push_state(snap1);

    // Client acks state 1
    sender.process_ack(1);

    // Now repeatedly write "\x08x" (backspace, then rewrite x) — the screen
    // state remains identical each time (cursor moves back, same char written).
    for _ in 0..10 {
        term.advance(b"\x08x");
        let snap = term.snapshot();
        sender.push_state(snap);

        // The frame should have an empty diff (no changed rows) since the
        // visible state hasn't changed from the ack'd state.
        let frame = sender.generate_frame().unwrap();
        let diff = frame.diff.as_ref().unwrap();
        assert!(
            diff.changed_rows.is_empty(),
            "expected no changed rows when screen is unchanged, got: {:?}",
            diff.changed_rows
        );

        sender.process_ack(sender.current_num());
    }
}

// ---------------------------------------------------------------------------
// Ported from mosh: prediction-unicode.test
//
// Regression test: client prediction should correctly handle multi-byte
// Unicode characters. Previously, mosh would show garbled predictions
// for characters like ü (U+00FC) because the prediction engine would
// emit the low byte as an 8-bit character.
// ---------------------------------------------------------------------------

#[test]
fn prediction_unicode_multibyte() {
    use rose::ssp::Predictor;

    let mut predictor = Predictor::new(24, 80);

    // Type "glück" keystroke by keystroke
    // g, l, ü (UTF-8: 0xC3 0xBC), c, k
    let keystrokes: &[&[u8]] = &[b"g", b"l", "ü".as_bytes(), b"c", b"k"];
    let mut last_state = predictor.predicted_state();

    for ks in keystrokes {
        last_state = predictor.predict_keystroke(ks);
    }

    // The predicted state should show "glück" on the first row
    assert!(
        last_state.rows[0].contains("glück"),
        "expected 'glück' in predicted state, got: {:?}",
        last_state.rows[0]
    );

    // Also test "faĩl" (ĩ = U+0129, UTF-8: 0xC4 0xA9)
    let mut predictor2 = Predictor::new(24, 80);
    let keystrokes2: &[&[u8]] = &[b"f", b"a", "ĩ".as_bytes(), b"l"];

    for ks in keystrokes2 {
        last_state = predictor2.predict_keystroke(ks);
    }

    assert!(
        last_state.rows[0].contains("faĩl"),
        "expected 'faĩl' in predicted state, got: {:?}",
        last_state.rows[0]
    );
}

// ---------------------------------------------------------------------------
// Ported from mosh: pty-deadlock.test
//
// Regression test for BSD PTY flow control bug: on FreeBSD/OpenBSD/macOS,
// a PTY master can block on read() after select() indicates data available,
// if ^S (XOFF) is written between select() and read().
// ---------------------------------------------------------------------------

#[test]
fn pty_flow_control_no_deadlock() {
    use rose::pty::PtySession;
    use std::time::{Duration, Instant};

    // Spawn `yes` which produces output at maximum rate, overwhelming
    // the broadcast channel's 256-slot buffer.
    let session = PtySession::open_command(24, 80, "yes", &[]).unwrap();
    let mut rx = session.subscribe_output();

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut lagged = false;

    while Instant::now() < deadline {
        match rx.try_recv() {
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                lagged = true;
                // Keep reading to exercise the recovery path
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
        }
    }

    assert!(
        lagged,
        "expected broadcast channel to lag under backpressure from `yes`"
    );

    // Drop session — this kills `yes` and should not deadlock.
    // The reader thread must exit cleanly when the PTY closes.
    drop(rx);
    drop(session);
    // If we get here without hanging, the test passes.
}

// ---------------------------------------------------------------------------
// RoSE-specific: session persistence across network changes
//
// Inspired by mosh's core value proposition but not directly ported from
// a specific mosh test. Verifies that a session survives simulated
// network disruption.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_persists_across_network_disruption() {
    use bytes::Bytes;
    use rose::protocol::{ClientSession, ControlMessage, ServerSession};
    use rose::pty::PtySession;
    use rose::session::{DetachedSession, SessionStore};
    use rose::ssp::{DATAGRAM_KEYSTROKE, SspSender};
    use rose::terminal::RoseTerminal;
    use rose::transport::QuicClient;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let fixture = MtlsFixture::new();
    let store = SessionStore::new();

    let session_id: [u8; 16];
    {
        let store_clone = store.clone();
        let server_task = tokio::spawn({
            let endpoint = fixture.server.endpoint.clone();
            async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let (mut session, handshake) = ServerSession::accept_any(conn).await.unwrap();

                let ControlMessage::Hello {
                    version: _,
                    rows,
                    cols,
                    ..
                } = handshake
                else {
                    panic!("expected Hello");
                };

                let sid = [42u8; 16]; // Deterministic for test
                session
                    .send_control(&ControlMessage::SessionInfo {
                        version: rose::protocol::PROTOCOL_VERSION,
                        session_id: sid,
                    })
                    .await
                    .unwrap();

                let pty = PtySession::open_command(rows, cols, "cat", &[]).unwrap();
                let pty_writer = pty.clone_writer();
                let terminal = Arc::new(Mutex::new(RoseTerminal::new(rows, cols)));
                let ssp_sender = Arc::new(Mutex::new(SspSender::new()));
                let mut rx = pty.subscribe_output();

                // Forward I/O
                let output_conn = session.connection().clone();
                let output_fwd = tokio::spawn(async move {
                    while let Ok(chunk) = rx.recv().await {
                        if output_conn
                            .send_datagram(Bytes::from(chunk.to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                });

                let input_conn = session.connection().clone();
                let input_fwd = tokio::spawn(async move {
                    while let Ok(data) = input_conn.read_datagram().await {
                        if data.is_empty() {
                            continue;
                        }
                        if data[0] == DATAGRAM_KEYSTROKE {
                            let mut w = pty_writer.lock().expect("writer lock poisoned");
                            if std::io::Write::write_all(&mut *w, &data[1..]).is_err() {
                                break;
                            }
                            let _ = std::io::Write::flush(&mut *w);
                        }
                    }
                });

                tokio::select! {
                    _ = output_fwd => {}
                    _ = input_fwd => {}
                }

                // Connection lost — detach session
                let _ = store_clone.insert(
                    sid,
                    DetachedSession {
                        pty,
                        terminal,
                        ssp_sender,
                        rows,
                        cols,
                        owner_cert_der: None,
                        detached_at: std::time::Instant::now(),
                    },
                );

                sid
            }
        });

        let client = QuicClient::new().unwrap();
        let client_conn = fixture.connect(&client).await;
        let mut client_session = ClientSession::connect(client_conn, 24, 80, vec![])
            .await
            .unwrap();

        // Read SessionInfo
        let info = client_session.recv_control().await.unwrap().unwrap();
        let ControlMessage::SessionInfo {
            version: _,
            session_id: sid,
        } = info
        else {
            panic!("expected SessionInfo, got {info:?}");
        };
        session_id = sid;

        // Send a command
        let mut data = vec![DATAGRAM_KEYSTROKE];
        data.extend_from_slice(b"hello_persist\n");
        client_session.send_input(Bytes::from(data)).unwrap();

        // Read echo
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut collected = String::new();
        loop {
            let timeout = tokio::time::timeout_at(deadline, client_session.recv_output()).await;
            match timeout {
                Ok(Ok(data)) => {
                    collected.push_str(&String::from_utf8_lossy(&data));
                    if collected.contains("hello_persist") {
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            collected.contains("hello_persist"),
            "expected echo before disconnect"
        );

        // Drop client connection to simulate network disruption
        drop(client_session);
        drop(client);

        // Wait for server to detach
        let _ = server_task.await.unwrap();

        // Phase 2: Reconnect with same session_id
        let store_clone2 = store.clone();

        let server_task2 = tokio::spawn({
            let endpoint = fixture.server.endpoint.clone();
            async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let (mut session, handshake) = ServerSession::accept_any(conn).await.unwrap();

                let ControlMessage::Reconnect {
                    version: _,
                    rows: _,
                    cols: _,
                    session_id: rsid,
                    ..
                } = handshake
                else {
                    panic!("expected Reconnect, got {handshake:?}");
                };
                assert_eq!(rsid, session_id);

                let detached = store_clone2.remove(&rsid).unwrap();

                session
                    .send_control(&ControlMessage::SessionInfo {
                        version: rose::protocol::PROTOCOL_VERSION,
                        session_id: rsid,
                    })
                    .await
                    .unwrap();

                // The PTY is still alive — send another command through it
                let pty_writer = detached.pty.clone_writer();
                let mut rx = detached.pty.subscribe_output();

                let output_conn = session.connection().clone();
                let output_fwd = tokio::spawn(async move {
                    while let Ok(chunk) = rx.recv().await {
                        if output_conn
                            .send_datagram(Bytes::from(chunk.to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                });

                let input_conn = session.connection().clone();
                let input_fwd = tokio::spawn(async move {
                    while let Ok(data) = input_conn.read_datagram().await {
                        if data.is_empty() {
                            continue;
                        }
                        if data[0] == DATAGRAM_KEYSTROKE {
                            let mut w = pty_writer.lock().expect("writer lock poisoned");
                            if std::io::Write::write_all(&mut *w, &data[1..]).is_err() {
                                break;
                            }
                            let _ = std::io::Write::flush(&mut *w);
                        }
                    }
                });

                tokio::select! {
                    _ = output_fwd => {}
                    _ = input_fwd => {}
                }
            }
        });

        let client2 = QuicClient::new().unwrap();
        let client_conn2 = fixture.connect(&client2).await;
        let mut client_session2 =
            ClientSession::reconnect(client_conn2, 24, 80, session_id, vec![])
                .await
                .unwrap();

        // Read SessionInfo confirming reconnection
        let info2 = client_session2.recv_control().await.unwrap().unwrap();
        assert!(matches!(info2, ControlMessage::SessionInfo { .. }));

        // Send another command to verify PTY is still alive
        let mut data2 = vec![DATAGRAM_KEYSTROKE];
        data2.extend_from_slice(b"still_alive\n");
        client_session2.send_input(Bytes::from(data2)).unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut collected2 = String::new();
        loop {
            let timeout = tokio::time::timeout_at(deadline, client_session2.recv_output()).await;
            match timeout {
                Ok(Ok(data)) => {
                    collected2.push_str(&String::from_utf8_lossy(&data));
                    if collected2.contains("still_alive") {
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            collected2.contains("still_alive"),
            "expected 'still_alive' after reconnect, got: {collected2:?}"
        );

        server_task2.abort();
    }
}

// ---------------------------------------------------------------------------
// RoSE-specific: scrollback synchronization
//
// Unique to RoSE (mosh doesn't support scrollback). Verifies that
// scrollback history is synchronized over the dedicated QUIC stream.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scrollback_sync_over_reliable_stream() {
    use rose::protocol::{ClientSession, ServerSession};
    use rose::scrollback::{self, ScrollbackLine, ScrollbackSender};
    use rose::terminal::RoseTerminal;
    use rose::transport::QuicClient;
    use std::time::Duration;

    let fixture = MtlsFixture::new();

    let server_task = tokio::spawn({
        let endpoint = fixture.server.endpoint.clone();
        async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let (session, _, _) = ServerSession::accept(conn).await.unwrap();

            let mut term = RoseTerminal::new(4, 80);
            let mut sb_sender = ScrollbackSender::new();

            // Generate scrollback by writing more lines than terminal height
            for i in 0..20 {
                term.advance(format!("scrollback line {i}\r\n").as_bytes());
            }

            let new_lines = sb_sender.collect_new_lines(&term);
            assert!(!new_lines.is_empty(), "should have scrollback lines");

            // Open a scrollback uni stream
            let conn = session.connection().clone();
            let mut stream = conn.open_uni().await.unwrap();
            stream
                .write_all(&[scrollback::stream_type::SCROLLBACK])
                .await
                .unwrap();
            for line in &new_lines {
                stream.write_all(&line.encode()).await.unwrap();
            }
            stream.finish().unwrap();

            // Keep alive for client to read
            tokio::time::sleep(Duration::from_secs(2)).await;
            (session, new_lines.len())
        }
    });

    let client = QuicClient::new().unwrap();
    let client_conn = fixture.connect(&client).await;
    let _client_session = ClientSession::connect(client_conn.clone(), 4, 80, vec![])
        .await
        .unwrap();

    let mut uni = tokio::time::timeout(Duration::from_secs(5), client_conn.accept_uni())
        .await
        .unwrap()
        .unwrap();

    // Read type prefix
    let mut type_buf = [0u8; 1];
    uni.read_exact(&mut type_buf).await.unwrap();
    assert_eq!(type_buf[0], scrollback::stream_type::SCROLLBACK);

    // Read all scrollback data
    let data = uni.read_to_end(1024 * 1024).await.unwrap();
    let mut lines = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let (line, consumed) = ScrollbackLine::decode(&data[offset..]).unwrap();
        lines.push(line);
        offset += consumed;
    }

    assert!(!lines.is_empty(), "should have received scrollback lines");
    // Verify the first scrollback line contains expected content
    assert!(
        lines[0].text.contains("scrollback line"),
        "first scrollback line should contain 'scrollback line', got: {:?}",
        lines[0].text
    );

    let (_, server_line_count) = server_task.await.unwrap();
    assert_eq!(
        lines.len(),
        server_line_count,
        "client should receive same number of lines as server sent"
    );
}

// ---------------------------------------------------------------------------
// RoSE-specific: SSH bootstrap mode
//
// Tests the SSH bootstrap connection mode where RoSE automatically SSHs
// in, starts a temporary server, exchanges certificates, and switches
// to QUIC.
// ---------------------------------------------------------------------------

mod ssh_bootstrap_helpers {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use russh::ChannelId;
    use russh::server::{Auth, Config, Handler, Msg, Session};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    pub struct TestHandler {
        home: std::path::PathBuf,
        stdin_tx: Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>>,
        child_exited: Arc<AtomicBool>,
    }

    impl Handler for TestHandler {
        type Error = russh::Error;

        async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<Msg>,
            _session: &mut Session,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let command = String::from_utf8_lossy(data).to_string();
            session.channel_success(channel)?;

            let parts: Vec<&str> = command.split_whitespace().collect();
            let (program, args) = parts.split_first().expect("empty command");

            self.child_exited.store(false, Ordering::SeqCst);
            let mut child = tokio::process::Command::new(program)
                .args(args)
                .env("HOME", &self.home)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("failed to spawn command");

            let child_stdin = child.stdin.take().unwrap();
            let child_stdout = child.stdout.take().unwrap();

            let handle = session.handle();
            tokio::spawn(async move {
                let mut reader = tokio::io::BufReader::new(child_stdout);
                let mut line = String::new();
                while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                    let _ = handle.data(channel, line.as_bytes().into()).await;
                    line.clear();
                }
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            self.stdin_tx.lock().unwrap().replace(tx);

            tokio::spawn(async move {
                let mut stdin = child_stdin;
                while let Some(data) = rx.recv().await {
                    if stdin.write_all(&data).await.is_err() {
                        break;
                    }
                    let _ = stdin.flush().await;
                }
            });

            let child_exited = self.child_exited.clone();
            tokio::spawn(async move {
                let _ = child.wait().await;
                child_exited.store(true, Ordering::SeqCst);
            });

            Ok(())
        }

        async fn data(
            &mut self,
            _channel: ChannelId,
            data: &[u8],
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            if let Some(tx) = self.stdin_tx.lock().unwrap().as_ref() {
                let _ = tx.send(data.to_vec());
            }
            Ok(())
        }
    }

    pub fn build_rose_binary() -> String {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().unwrap();

        // Fast path: reuse a previously-built binary so we don't invoke
        // `cargo build` during the test.  Running `cargo build` from inside
        // a nextest run acquires the global cargo lock and can trigger a
        // slow recompile (profile mismatch between `cargo test` and
        // `cargo build`), which blocks the tokio runtime thread and causes
        // the bootstrap tests to hang when executed in parallel.
        //
        // Check both `target/debug` (normal) and `target/llvm-cov-target/debug`
        // (coverage runs) so the fast path also works in CI.
        let candidates = [
            workspace_root.join("target").join("debug").join("rose"),
            workspace_root
                .join("target")
                .join("llvm-cov-target")
                .join("debug")
                .join("rose"),
        ];
        for bin_path in &candidates {
            if bin_path.exists() {
                return bin_path.to_str().unwrap().to_string();
            }
        }

        let build_output = std::process::Command::new("cargo")
            .arg("build")
            .arg("-p")
            .arg("rose-cli")
            .arg("--message-format=json")
            .current_dir(workspace_root)
            .output()
            .expect("failed to run cargo build");
        assert!(
            build_output.status.success(),
            "cargo build failed: {}",
            String::from_utf8_lossy(&build_output.stderr)
        );
        let stdout = String::from_utf8_lossy(&build_output.stdout);
        stdout
            .lines()
            .filter(|line| line.contains(r#""reason":"compiler-artifact""#))
            .filter(|line| line.contains(r#""name":"rose""#))
            .filter(|line| line.contains(r#""bin""#))
            .find_map(|line| {
                let marker = r#""executable":""#;
                let start = line.find(marker)? + marker.len();
                let end = line[start..].find('"')? + start;
                Some(line[start..end].to_string())
            })
            .expect("could not find rose binary in cargo build output")
    }

    pub struct SshServer {
        pub port: u16,
        pub child_exited: Arc<AtomicBool>,
    }

    pub async fn start_ssh_server(home: std::path::PathBuf) -> SshServer {
        use base64::Engine;
        let child_exited = Arc::new(AtomicBool::new(false));
        let stdin_tx: Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>> =
            Arc::new(Mutex::new(None));
        let key_pem = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(concat!(
                    "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K",
                    "YjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFF",
                    "Ym05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpR",
                    "eU5UVXhPUUFBQUNDQ0hSOXNZTHBteUYzNlFZaTdIWDViV2NK",
                    "VXpUaThZRXVCcnNIdWdhbjNOQUFBQUpCQ1V2S29RbEx5CnFB",
                    "QUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDQ0NIUjlzWUxwbXlG",
                    "MzZRWWk3SFg1YldjSlV6VGk4WUV1QnJzSHVnYW4zTkEKQUFB",
                    "RUFWbEFMN3docTEyM2swTnllakEwcFMxcWxQSk8zd0FjcUFS",
                    "WWVsMXF4K1dJSWRIMnhndW1iSVhmcEJpTHNkZmx0Wgp3bFRO",
                    "T0x4Z1M0R3V3ZTZCcWZjMEFBQUFDWFJsYzNSQWNtOXpaUUVD",
                    "QXdRPQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0t",
                    "LS0K",
                ))
                .unwrap(),
        )
        .unwrap();
        let key = russh::keys::ssh_key::PrivateKey::from_openssh(&key_pem).unwrap();
        let config = Arc::new(Config {
            keys: vec![key],
            auth_rejection_time: std::time::Duration::from_secs(0),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            ..Config::default()
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_port = listener.local_addr().unwrap().port();

        let child_exited_clone = child_exited.clone();
        let stdin_tx_clone = stdin_tx.clone();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let cfg = config.clone();
                let handler = TestHandler {
                    home: home.clone(),
                    stdin_tx: stdin_tx_clone.clone(),
                    child_exited: child_exited_clone.clone(),
                };
                tokio::spawn(async move {
                    let _ = russh::server::run_stream(cfg, socket, handler).await;
                });
            }
        });

        SshServer {
            port: ssh_port,
            child_exited,
        }
    }

    pub struct PtyChild {
        pub child: Box<dyn portable_pty::Child + Send + Sync>,
        pub writer: Option<Box<dyn std::io::Write + Send>>,
        pub output: Arc<Mutex<String>>,
        pub reader_handle: Option<std::thread::JoinHandle<()>>,
    }

    impl PtyChild {
        pub fn captured_output(&self) -> String {
            self.output.lock().unwrap().clone()
        }

        pub fn finish(&mut self) -> String {
            self.writer.take();
            if let Some(h) = self.reader_handle.take() {
                let _ = h.join();
            }
            self.captured_output()
        }
    }

    pub fn spawn_in_pty(cmd: CommandBuilder) -> PtyChild {
        let pty_system = native_pty_system();
        let pty_pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("failed to open PTY");

        let child = pty_pair
            .slave
            .spawn_command(cmd)
            .expect("failed to spawn command in PTY");

        let writer = pty_pair.master.take_writer().unwrap();
        let mut reader = pty_pair.master.try_clone_reader().unwrap();
        drop(pty_pair.slave);

        let output = Arc::new(Mutex::new(String::new()));
        let output_clone = output.clone();
        let reader_handle = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match std::io::Read::read(&mut reader, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&buf[..n]);
                        output_clone.lock().unwrap().push_str(&text);
                    }
                }
            }
        });

        PtyChild {
            child,
            writer: Some(writer),
            output,
            reader_handle: Some(reader_handle),
        }
    }

    pub fn isolated_home_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rose-test-home-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    pub fn bootstrap_cmd(rose_bin: &str, ssh_port: u16, home: &std::path::Path) -> CommandBuilder {
        let mut cmd = CommandBuilder::new(rose_bin);
        cmd.env("HOME", home.as_os_str());
        cmd.args([
            "connect",
            "--ssh",
            "--ssh-port",
            &ssh_port.to_string(),
            "--ssh-option",
            "StrictHostKeyChecking=no",
            "--ssh-option",
            "UserKnownHostsFile=/dev/null",
            "--ssh-option",
            "PreferredAuthentications=none",
            "127.0.0.1",
            "--server-binary",
            rose_bin,
        ]);
        cmd
    }

    pub async fn wait_for_exit(
        child: &mut Box<dyn portable_pty::Child + Send + Sync>,
        timeout_secs: u64,
    ) -> Option<portable_pty::ExitStatus> {
        tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), async {
            loop {
                if let Ok(Some(status)) = child.try_wait() {
                    return status;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .ok()
    }

    pub async fn wait_for_output_contains(pty: &PtyChild, needle: &str, timeout_secs: u64) -> bool {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        while tokio::time::Instant::now() < deadline {
            if pty.captured_output().contains(needle) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        false
    }

    pub async fn wait_for_bootstrap_child_exit(
        child_exited: &AtomicBool,
        timeout_secs: u64,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        while tokio::time::Instant::now() < deadline {
            if child_exited.load(Ordering::SeqCst) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        child_exited.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn ssh_bootstrap_mode() {
    use ssh_bootstrap_helpers::*;

    let home = isolated_home_dir();
    let ssh = start_ssh_server(home.clone()).await;
    let rose_bin = build_rose_binary();

    let cmd = bootstrap_cmd(&rose_bin, ssh.port, &home);
    let mut pty = spawn_in_pty(cmd);

    assert!(
        wait_for_output_contains(&pty, "Bootstrap: server on port", 30).await,
        "bootstrap did not start. output:\n{}",
        pty.captured_output()
    );

    // Send a text probe to verify the full pipeline is up.  Text works
    // in both cooked and raw terminal modes, unlike Ctrl-D which is
    // interpreted as EOF in cooked mode.  The "Bootstrap: server on port"
    // message is printed *before* the QUIC connection is established and
    // raw mode is enabled, so we cannot send control characters yet.
    //
    // Under llvm-cov in Docker the QUIC connect + session setup + shell
    // start can take 15+ seconds, so we use a generous 60 s timeout.
    let marker = format!("rose_exit_probe_{}", std::process::id());
    {
        let w = pty.writer.as_mut().unwrap();
        let probe = format!("echo {marker}\n");
        std::io::Write::write_all(w, probe.as_bytes()).unwrap();
        std::io::Write::flush(w).unwrap();
    }

    assert!(
        wait_for_output_contains(&pty, &marker, 60).await,
        "shell not responding. output:\n{}",
        pty.captured_output()
    );

    // Now we know the shell is alive and raw mode is active.
    // Send Ctrl-D to close the shell.
    {
        let w = pty.writer.as_mut().unwrap();
        std::io::Write::write_all(w, &[4]).unwrap();
        std::io::Write::flush(w).unwrap();
    }

    // Wait for the client to acknowledge the shell exit.
    assert!(
        wait_for_output_contains(&pty, "shell exited", 30).await,
        "shell exit not detected. output:\n{}",
        pty.captured_output()
    );

    // Give the process a brief window to exit on its own (fast without
    // instrumentation), then force-kill so the test doesn't block under
    // llvm-cov.
    let status = wait_for_exit(&mut pty.child, 3).await;
    if status.is_none() {
        let _ = pty.child.kill();
    }
    let captured = pty.finish();

    assert!(
        !captured.contains("connection error") && !captured.contains("connection failed"),
        "QUIC connection failed. output:\n{captured}"
    );
}

#[tokio::test]
async fn ssh_bootstrap_detach_reconnect() {
    use portable_pty::CommandBuilder;
    use ssh_bootstrap_helpers::*;

    fn extract_tagged_value(output: &str, tag: &str) -> String {
        for (idx, _) in output.rmatch_indices(tag) {
            let value: String = output[idx + tag.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !value.is_empty() {
                return value;
            }
        }
        panic!("missing tagged value {tag} in output:\n{output}");
    }

    // 120 s outer timeout: under llvm-cov in Docker CI the process
    // startup and shutdown are significantly slower than bare metal.
    let result = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        let home = isolated_home_dir();
        let ssh = start_ssh_server(home.clone()).await;
        let rose_bin = build_rose_binary();
        let marker = format!("rose_reconnect_marker_{}", std::process::id());

        let cmd = bootstrap_cmd(&rose_bin, ssh.port, &home);
        let mut pty = spawn_in_pty(cmd);

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        {
            let w = pty.writer.as_mut().unwrap();
            let probe = format!(
                "ROSE_MARK={marker}; printf \"__PID1__%s __MARK1__%s\\n\" \"$$\" \"$ROSE_MARK\"\r"
            );
            std::io::Write::write_all(w, probe.as_bytes()).unwrap();
            std::io::Write::flush(w).unwrap();
        }

        assert!(
            wait_for_output_contains(&pty, &format!("__MARK1__{marker}"), 10).await,
            "did not capture initial shell probe. output:\n{}",
            pty.captured_output()
        );
        let pre_detach_output = pty.captured_output();
        let pid1 = extract_tagged_value(&pre_detach_output, "__PID1__");
        let mark1 = extract_tagged_value(&pre_detach_output, "__MARK1__");
        assert_eq!(mark1, marker, "initial shell marker did not persist");

        {
            let w = pty.writer.as_mut().unwrap();
            std::io::Write::write_all(w, b"\r").unwrap();
            std::io::Write::flush(w).unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        {
            let w = pty.writer.as_mut().unwrap();
            std::io::Write::write_all(w, b"~").unwrap();
            std::io::Write::flush(w).unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        {
            let w = pty.writer.as_mut().unwrap();
            std::io::Write::write_all(w, b"d").unwrap();
            std::io::Write::flush(w).unwrap();
        }

        let status = wait_for_exit(&mut pty.child, 10).await;
        if status.is_none() {
            let _ = pty.child.kill();
        }
        let captured = pty.finish();

        let status = status.unwrap_or_else(|| {
            panic!("rose client timed out during detach. output:\n{captured}");
        });
        assert!(
            status.exit_code() == 0,
            "rose client exited with {status:?} during detach. output:\n{captured}"
        );
        assert!(
            captured.contains("detached"),
            "detach message not found. output:\n{captured}"
        );

        let port_line = captured
            .lines()
            .find(|l| l.contains("Bootstrap: server on port"))
            .expect("bootstrap port line not found in output");
        let port: u16 = port_line
            .split("port ")
            .nth(1)
            .unwrap()
            .trim()
            .parse()
            .expect("failed to parse port from bootstrap output");

        let mut cmd = CommandBuilder::new(&rose_bin);
        cmd.env("HOME", home.as_os_str());
        cmd.args(["connect", "127.0.0.1", "--port", &port.to_string()]);
        let mut pty2 = spawn_in_pty(cmd);

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        {
            let w = pty2.writer.as_mut().unwrap();
            std::io::Write::write_all(
                w,
                b"printf \"__PID2__%s __MARK2__%s\\n\" \"$$\" \"$ROSE_MARK\"\r",
            )
            .unwrap();
            std::io::Write::flush(w).unwrap();
        }

        assert!(
            wait_for_output_contains(&pty2, &format!("__MARK2__{marker}"), 10).await,
            "did not capture reattached shell probe. output:\n{}",
            pty2.captured_output()
        );
        let reconnect_probe_output = pty2.captured_output();
        let pid2 = extract_tagged_value(&reconnect_probe_output, "__PID2__");
        let mark2 = extract_tagged_value(&reconnect_probe_output, "__MARK2__");

        assert_eq!(pid2, pid1, "reconnect attached to a different shell process");
        assert_eq!(mark2, marker, "reconnect did not preserve shell environment");

        {
            let w = pty2.writer.as_mut().unwrap();
            std::io::Write::write_all(w, b"exit\r").unwrap();
            std::io::Write::flush(w).unwrap();
        }

        // Wait for the "shell exited" message to confirm correct
        // behaviour, then force-kill if the process is slow to shut down
        // (common under llvm-cov instrumentation).
        assert!(
            wait_for_output_contains(&pty2, "shell exited", 15).await,
            "shell exit not detected on reconnect. output:\n{}",
            pty2.captured_output()
        );

        let status2 = wait_for_exit(&mut pty2.child, 3).await;
        if status2.is_none() {
            let _ = pty2.child.kill();
        }
        let captured2 = pty2.finish();

        assert!(
            !captured2.contains("connection error"),
            "QUIC connection error on reconnect. output:\n{captured2}"
        );

        assert!(
            wait_for_bootstrap_child_exit(&ssh.child_exited, 10).await,
            "bootstrap server did not exit after shell exit. detach output:\n{captured}\nreconnect output:\n{captured2}"
        );
    })
    .await;
    assert!(
        result.is_ok(),
        "ssh_bootstrap_detach_reconnect timed out after 120s"
    );
}

// ---------------------------------------------------------------------------
// RoSE-specific: certificate-based authentication (native mode)
//
// Tests that mutual TLS authentication works with X.509 certificates.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn native_mode_mutual_tls_auth() {
    use rose::config::generate_self_signed_cert;
    use rose::protocol::{ClientSession, ServerSession};
    use rose::transport::{QuicClient, QuicServer};
    use std::time::Duration;

    let dir = std::env::temp_dir().join(format!("rose-mtls-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let auth_dir = dir.join("authorized_certs");
    std::fs::create_dir_all(&auth_dir).unwrap();

    let authorized_client = generate_self_signed_cert(&["authorized-client".to_string()]).unwrap();
    let unauthorized_client =
        generate_self_signed_cert(&["unauthorized-client".to_string()]).unwrap();

    // Place the authorized client cert in the server's authorized_certs dir
    std::fs::write(
        auth_dir.join("authorized.crt"),
        authorized_client.cert_der.as_ref(),
    )
    .unwrap();

    // Test 1: authorized client connects successfully
    {
        let server = QuicServer::bind_mutual_tls(
            "127.0.0.1:0".parse().unwrap(),
            generate_self_signed_cert(&["localhost".to_string()]).unwrap(),
            &auth_dir,
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let cert_der = server.server_cert_der().clone();

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().unwrap();
            ServerSession::accept(conn).await
        });

        let client = QuicClient::new().unwrap();
        let client_conn = client
            .connect_with_cert(addr, "localhost", &cert_der, &authorized_client)
            .await
            .unwrap();

        let _client_session = ClientSession::connect(client_conn, 24, 80, vec![])
            .await
            .unwrap();
        let (_, rows, cols) = server_task.await.unwrap().unwrap();
        assert_eq!(rows, 24);
        assert_eq!(cols, 80);
    }

    // Test 2: unauthorized client is rejected
    {
        let server = QuicServer::bind_mutual_tls(
            "127.0.0.1:0".parse().unwrap(),
            generate_self_signed_cert(&["localhost".to_string()]).unwrap(),
            &auth_dir,
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let cert_der = server.server_cert_der().clone();

        let server_task = tokio::spawn(async move {
            // Server may reject at the connection level or at the handshake level
            let conn_result = server.accept().await;
            match conn_result {
                Ok(Some(conn)) => ServerSession::accept(conn).await.is_err(),
                _ => true, // connection-level rejection
            }
        });

        let client = QuicClient::new().unwrap();
        let result = client
            .connect_with_cert(addr, "localhost", &cert_der, &unauthorized_client)
            .await;

        // Either the client connection fails or the server rejects
        tokio::time::sleep(Duration::from_millis(200)).await;
        let server_rejected = server_task.await.unwrap();
        let rejected = result.is_err() || server_rejected;
        assert!(rejected, "unauthorized client should be rejected");
    }

    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// RoSE-specific: TOFU (Trust On First Use) for self-signed server certs
// ---------------------------------------------------------------------------

#[test]
fn native_mode_tofu_self_signed() {
    use rose::config::{TofuResult, generate_self_signed_cert, tofu_check};

    let dir = std::env::temp_dir().join(format!("rose-tofu-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let cert1 = generate_self_signed_cert(&["localhost".to_string()]).unwrap();
    let cert2 = generate_self_signed_cert(&["localhost".to_string()]).unwrap();

    // First connection: cert is saved
    let result = tofu_check(&dir, "testhost", cert1.cert_der.as_ref()).unwrap();
    assert_eq!(result, TofuResult::FirstConnection);

    // Second connection with same cert: verified
    let result = tofu_check(&dir, "testhost", cert1.cert_der.as_ref()).unwrap();
    assert_eq!(result, TofuResult::Verified);

    // Third connection with different cert: mismatch (TOFU violation)
    let result = tofu_check(&dir, "testhost", cert2.cert_der.as_ref()).unwrap();
    assert!(
        matches!(result, TofuResult::Mismatch { .. }),
        "expected Mismatch for changed cert, got {result:?}"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}
