//! Integration tests ported from the mosh project's test suite.
//!
//! These tests exercise end-to-end behavior that requires `RoSE`'s transport,
//! protocol, and PTY layers working together. They are expected to fail until
//! those layers are implemented.
//!
//! Each test is annotated with the mosh test it was ported from.

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
    use rose::transport::{QuicClient, QuicServer};
    use std::time::Duration;

    let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let cert = server.server_cert_der().clone();

    // Server: accept, spawn sh, handle resize + I/O
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
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
    });

    // Client: connect, send resize, then query columns
    let client = QuicClient::new().unwrap();
    let client_conn = client.connect(addr, "localhost", &cert).await.unwrap();
    let mut client_session = ClientSession::connect(client_conn, 24, 80).await.unwrap();

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
    use rose::transport::{QuicClient, QuicServer};
    use std::time::Duration;

    let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let cert = server.server_cert_der().clone();

    // Server: accept, spawn cat, forward I/O in both directions
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (session, rows, cols) = ServerSession::accept(conn).await.unwrap();
        let pty = PtySession::open_command(rows, cols, "cat", &[]).unwrap();
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

        // Forward client datagrams -> PTY input
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
    });

    // Client: connect, send data, read echo
    let client = QuicClient::new().unwrap();
    let client_conn = client.connect(addr, "localhost", &cert).await.unwrap();
    let client_session = ClientSession::connect(client_conn, 24, 80).await.unwrap();

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
// Ported from mosh: local.test
//
// Tests local (loopback) connection mode.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_local_connection() {
    use bytes::Bytes;
    use rose::protocol::{ClientSession, ServerSession};
    use rose::pty::PtySession;
    use rose::transport::{QuicClient, QuicServer};
    use std::time::Duration;

    let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let cert = server.server_cert_der().clone();

    // Server: accept, spawn cat, forward I/O
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
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
    });

    let client = QuicClient::new().unwrap();
    let client_conn = client.connect(addr, "localhost", &cert).await.unwrap();
    let client_session = ClientSession::connect(client_conn, 24, 80).await.unwrap();

    client_session
        .send_input(Bytes::from_static(b"local_e2e_test\n"))
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut collected = String::new();
    let mut found = false;

    loop {
        let timeout = tokio::time::timeout_at(deadline, client_session.recv_output()).await;
        match timeout {
            Ok(Ok(data)) => {
                collected.push_str(&String::from_utf8_lossy(&data));
                if collected.contains("local_e2e_test") {
                    found = true;
                    break;
                }
            }
            _ => break,
        }
    }

    assert!(
        found,
        "expected 'local_e2e_test' in echoed output, got: {collected:?}"
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
    use rose::transport::{QuicClient, QuicServer};
    use std::time::Duration;

    for i in 0..5 {
        let marker = format!("repeat_marker_{i}");

        // Create a fresh server + client pair each iteration to verify
        // clean resource lifecycle
        let iter_server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let iter_addr = iter_server.local_addr().unwrap();
        let iter_cert = iter_server.server_cert_der().clone();

        let marker_clone = marker.clone();
        let server_task = tokio::spawn(async move {
            let conn = iter_server.accept().await.unwrap().unwrap();
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
        });

        let client = QuicClient::new().unwrap();
        let client_conn = client
            .connect(iter_addr, "localhost", &iter_cert)
            .await
            .unwrap();
        let client_session = ClientSession::connect(client_conn, 24, 80).await.unwrap();

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
#[ignore = "requires prediction engine (mosh: prediction-unicode.test)"]
fn prediction_unicode_multibyte() {
    // TODO: Set up a client with prediction enabled. Type "glück" and
    // "faĩl" with delays between characters. Verify the predicted
    // display shows the correct Unicode characters at all times, never
    // showing replacement characters or wrong characters.
    unimplemented!("unicode prediction test");
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

#[test]
#[ignore = "requires transport layer"]
fn session_persists_across_network_disruption() {
    // TODO: Establish a RoSE session. Simulate a network disruption
    // (drop all datagrams for N seconds). Resume. Verify the session
    // is still alive and the screen state synchronizes correctly.
    unimplemented!("session persistence test");
}

// ---------------------------------------------------------------------------
// RoSE-specific: scrollback synchronization
//
// Unique to RoSE (mosh doesn't support scrollback). Verifies that
// scrollback history is synchronized over the dedicated QUIC stream.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires scrollback sync"]
fn scrollback_sync_over_reliable_stream() {
    // TODO: Establish a session. Generate enough output to fill the
    // scrollback buffer. Verify the client can scroll back and see
    // the history, and that it was delivered over the reliable QUIC
    // stream (not datagrams).
    unimplemented!("scrollback sync test");
}

// ---------------------------------------------------------------------------
// RoSE-specific: SSH bootstrap mode
//
// Tests the SSH bootstrap connection mode where RoSE automatically SSHs
// in, starts a temporary server, exchanges certificates, and switches
// to QUIC.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires SSH bootstrap implementation"]
fn ssh_bootstrap_mode() {
    // TODO: Start an SSH server (or mock). Run `rose connect --ssh`.
    // Verify the client:
    // 1. SSHs in
    // 2. Starts rose server on a high port
    // 3. Exchanges certificates
    // 4. Connects via QUIC
    // 5. Drops the SSH connection
    // 6. The session works over QUIC
    unimplemented!("SSH bootstrap mode test");
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

        let _client_session = ClientSession::connect(client_conn, 24, 80).await.unwrap();
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
