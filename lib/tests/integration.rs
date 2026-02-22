//! Integration tests exercising multiple `RoSE` layers together.

use std::time::Duration;

// ---------------------------------------------------------------------------
// PTY + Terminal: spawn a command in a PTY and feed output to RoseTerminal
// ---------------------------------------------------------------------------

#[test]
fn pty_output_renders_in_terminal() {
    use rose::pty::PtySession;
    use rose::terminal::RoseTerminal;
    use std::time::Instant;

    let mut session = PtySession::open_command(24, 80, "echo", &["hello_world"]).unwrap();
    let mut rx = session.subscribe_output();

    let mut term = RoseTerminal::new(24, 80);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut found = false;

    while Instant::now() < deadline {
        match rx.try_recv() {
            Ok(chunk) => {
                term.advance(&chunk);
                if term.screen_text().contains("hello_world") {
                    found = true;
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }

    assert!(
        found,
        "expected 'hello_world' on terminal screen, got:\n{}",
        term.screen_text()
    );
    session.wait().unwrap();
}

// ---------------------------------------------------------------------------
// Transport + Protocol: full QUIC handshake + datagram echo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transport_protocol_handshake_and_datagram() {
    use bytes::Bytes;
    use rose::protocol::{ClientSession, ServerSession};
    use rose::transport::{QuicClient, QuicServer};

    let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let cert = server.server_cert_der().clone();
    let client = QuicClient::new().unwrap();

    // Server: accept in a background task
    let server_accept = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let result = ServerSession::accept(conn).await.unwrap();
        // Return both the session and the server (to keep endpoint alive)
        (result, server)
    });

    // Client: connect and handshake
    let client_conn = client.connect(addr, "localhost", &cert).await.unwrap();
    let client_session = ClientSession::connect(client_conn, 24, 80).await.unwrap();

    let ((server_session, rows, cols), _server) = server_accept.await.unwrap();
    assert_eq!(rows, 24);
    assert_eq!(cols, 80);

    // Datagram: client -> server
    client_session
        .send_input(Bytes::from_static(b"test input"))
        .unwrap();
    let received = server_session.recv_input().await.unwrap();
    assert_eq!(&received[..], b"test input");

    // Datagram: server -> client
    server_session
        .send_output(Bytes::from_static(b"test output"))
        .unwrap();
    let received = client_session.recv_output().await.unwrap();
    assert_eq!(&received[..], b"test output");
}

// ---------------------------------------------------------------------------
// End-to-end: server with PTY + client, send command, verify output
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_echo_command() {
    use bytes::Bytes;
    use rose::protocol::{ClientSession, ServerSession};
    use rose::pty::PtySession;
    use rose::transport::{QuicClient, QuicServer};

    let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let cert = server.server_cert_der().clone();

    // Server: accept connection, spawn PTY, forward I/O
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (session, rows, cols) = ServerSession::accept(conn).await.unwrap();
        let pty = PtySession::open_command(rows, cols, "echo", &["e2e_test_output"]).unwrap();
        let mut rx = pty.subscribe_output();

        // Forward PTY output to client
        while let Ok(chunk) = rx.recv().await {
            if session.send_output(Bytes::from(chunk.to_vec())).is_err() {
                break;
            }
        }
        // Keep everything alive until we finish
        drop(pty);
        drop(session);
    });

    // Client: connect, send hello, read output
    let client = QuicClient::new().unwrap();
    let client_conn = client.connect(addr, "localhost", &cert).await.unwrap();
    let client_session = ClientSession::connect(client_conn, 24, 80).await.unwrap();

    // Read output until we find our marker
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut collected = String::new();
    let mut found = false;

    loop {
        let timeout = tokio::time::timeout_at(deadline, client_session.recv_output()).await;
        match timeout {
            Ok(Ok(data)) => {
                collected.push_str(&String::from_utf8_lossy(&data));
                if collected.contains("e2e_test_output") {
                    found = true;
                    break;
                }
            }
            _ => break,
        }
    }

    assert!(
        found,
        "expected 'e2e_test_output' in client output, got: {collected:?}"
    );

    // Clean up
    server_task.abort();
}
