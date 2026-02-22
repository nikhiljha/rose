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

#[test]
#[ignore = "requires transport + protocol layers (mosh: window-resize.test)"]
fn e2e_window_resize() {
    // TODO: Start a RoSE server with a PTY running a program that redraws
    // on resize (e.g., `less` or a custom test program). Connect a client.
    // Resize the client terminal. Verify the server PTY receives SIGWINCH
    // and the program redraws correctly.
    unimplemented!("window resize e2e test");
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

#[test]
#[ignore = "requires transport + protocol layers (mosh: local.test)"]
fn e2e_local_connection() {
    // TODO: Start server and client on localhost. Verify they connect
    // and can exchange data.
    unimplemented!("local connection e2e test");
}

// ---------------------------------------------------------------------------
// Ported from mosh: repeat.test
//
// Tests repeated connect/disconnect cycles to verify no resource leaks.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires transport + protocol layers (mosh: repeat.test)"]
fn e2e_repeat_connections() {
    // TODO: Connect and disconnect 5+ times in sequence. Verify each
    // connection works and there are no leaked file descriptors, ports,
    // or PTYs.
    unimplemented!("repeat connections e2e test");
}

// ---------------------------------------------------------------------------
// Ported from mosh: network-no-diff.test
//
// Regression test: the server should not spin CPU when the screen state
// has not changed (e.g., cursor blink writes overwriting the same character).
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires protocol layer (mosh: network-no-diff.test)"]
fn protocol_no_diff_no_spin() {
    // TODO: Set up a server terminal and repeatedly write the same
    // character at the same position (e.g., "x\b" in a loop). Verify
    // that the diff engine produces no output / minimal CPU usage
    // when the framebuffer hasn't actually changed.
    unimplemented!("no-diff optimization test");
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
#[ignore = "requires PTY layer (mosh: pty-deadlock.test)"]
fn pty_flow_control_no_deadlock() {
    // TODO: Start a RoSE server running a program that produces high
    // output volume. Send ^S (XOFF) to pause output, wait, then send
    // ^Q (XON) to resume. Verify the server does not deadlock and the
    // program eventually produces a clean exit message.
    unimplemented!("PTY flow control deadlock test");
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

#[test]
#[ignore = "requires certificate management"]
fn native_mode_mutual_tls_auth() {
    // TODO: Generate client and server certificates with `rose keygen`.
    // Place client cert in server's authorized_certs. Start server.
    // Connect client. Verify mutual TLS authentication succeeds.
    // Also test rejection when the client cert is not authorized.
    unimplemented!("mutual TLS auth test");
}

// ---------------------------------------------------------------------------
// RoSE-specific: TOFU (Trust On First Use) for self-signed server certs
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires certificate management"]
fn native_mode_tofu_self_signed() {
    // TODO: Generate a self-signed server certificate. Connect a client
    // for the first time — should prompt/succeed and cache the cert in
    // known_hosts. Connect again — should verify against cached cert.
    // Change the server cert — should reject (TOFU violation).
    unimplemented!("TOFU self-signed cert test");
}
