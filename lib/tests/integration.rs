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
    let client_session = ClientSession::connect(client_conn, 24, 80, vec![])
        .await
        .unwrap();

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
// Terminal snapshot captures screen state correctly
// ---------------------------------------------------------------------------

#[test]
fn terminal_snapshot() {
    use rose::terminal::RoseTerminal;

    let mut term = RoseTerminal::new(24, 80);
    term.advance(b"hello world\r\nline two");

    let snap = term.snapshot();
    assert_eq!(snap.rows.len(), 24);
    // snapshot() now returns ANSI-encoded rows; plain text with default attrs
    // produces identical output to the old trim_end() behavior.
    assert_eq!(snap.rows[0], "hello world");
    assert_eq!(snap.rows[1], "line two");
    assert_eq!(snap.rows[2], ""); // empty row
    assert_eq!(snap.cursor_x, 8); // "line two" is 8 chars
    assert_eq!(snap.cursor_y, 1);

    // Verify via line_text() for plain-text content checks
    assert_eq!(term.line_text(0).trim_end(), "hello world");
    assert_eq!(term.line_text(1).trim_end(), "line two");
}

// ---------------------------------------------------------------------------
// SSP sender → receiver roundtrip (no network)
// ---------------------------------------------------------------------------

#[test]
fn ssp_sender_receiver_roundtrip() {
    use rose::ssp::{ScreenState, SspReceiver, SspSender};

    let mut sender = SspSender::new();
    let mut receiver = SspReceiver::new(24);

    // Push first state
    let mut rows1 = vec![String::new(); 24];
    rows1[0] = "first".into();
    sender.push_state(ScreenState {
        rows: rows1,
        cursor_x: 5,
        cursor_y: 0,
    });

    // Generate and apply init frame
    let frame1 = sender.generate_frame().unwrap();
    let result = receiver.process_frame(&frame1).unwrap();
    assert!(result.is_some());
    assert_eq!(receiver.state().rows[0], "first");

    // Ack and push second state
    sender.process_ack(receiver.ack_num());
    let mut rows2 = vec![String::new(); 24];
    rows2[0] = "first".into();
    rows2[1] = "second".into();
    sender.push_state(ScreenState {
        rows: rows2,
        cursor_x: 6,
        cursor_y: 1,
    });

    // Generate and apply incremental frame
    let frame2 = sender.generate_frame().unwrap();
    let result = receiver.process_frame(&frame2).unwrap();
    assert!(result.is_some());
    assert_eq!(receiver.state().rows[0], "first");
    assert_eq!(receiver.state().rows[1], "second");
    assert_eq!(receiver.state().cursor_x, 6);

    // After ack, no new frame needed
    sender.process_ack(receiver.ack_num());
    assert!(sender.generate_frame().is_none());
}

// ---------------------------------------------------------------------------
// SSP sender → receiver roundtrip with colored text
// ---------------------------------------------------------------------------

#[test]
fn ssp_colored_text_roundtrip() {
    use rose::ssp::{ScreenState, SspReceiver, SspSender, render_diff_ansi};
    use rose::terminal::RoseTerminal;

    let mut term = RoseTerminal::new(24, 80);
    term.advance(b"\x1b[31mred\x1b[0m \x1b[1;32mbold green\x1b[0m");

    let snap = term.snapshot();
    // Snapshot should contain SGR codes
    assert!(
        snap.rows[0].contains("\x1b["),
        "snapshot should contain ANSI SGR"
    );

    // SSP roundtrip
    let mut sender = SspSender::new();
    sender.push_state(snap.clone());
    let frame = sender.generate_frame().unwrap();

    let mut receiver = SspReceiver::new(24);
    receiver.process_frame(&frame).unwrap();

    // Receiver should have the ANSI-encoded row
    assert_eq!(receiver.state().rows[0], snap.rows[0]);

    // render_diff_ansi should pass through the SGR codes
    let empty = ScreenState::empty(24);
    let ansi_output = render_diff_ansi(&empty, receiver.state());
    let output_str = String::from_utf8(ansi_output).unwrap();
    assert!(
        output_str.contains("31m"),
        "render output should preserve red SGR: {output_str:?}"
    );
    assert!(
        output_str.contains("red"),
        "render output should contain 'red'"
    );
}

// ---------------------------------------------------------------------------
// SSP over QUIC: server sends state update, client receives and applies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ssp_over_quic() {
    use bytes::Bytes;
    use rose::protocol::{ClientSession, ServerSession};
    use rose::ssp::{DATAGRAM_SSP_ACK, ScreenState, SspFrame, SspReceiver, SspSender};
    use rose::transport::{QuicClient, QuicServer};

    let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let cert = server.server_cert_der().clone();

    // Server: accept, create SSP state, send frame
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (session, _, _) = ServerSession::accept(conn).await.unwrap();

        let mut sender = SspSender::new();
        let mut rows = vec![String::new(); 24];
        rows[0] = "ssp over quic".into();
        rows[1] = "line two".into();
        sender.push_state(ScreenState {
            rows,
            cursor_x: 8,
            cursor_y: 1,
        });

        let frame = sender.generate_frame().unwrap();
        session.send_output(Bytes::from(frame.encode())).unwrap();

        // Wait for ACK
        let ack_data = session.recv_input().await.unwrap();
        assert_eq!(ack_data[0], DATAGRAM_SSP_ACK);
        let ack_frame = SspFrame::decode(&ack_data[1..]).unwrap();
        assert_eq!(ack_frame.ack_num, 1);

        // Keep alive for clean shutdown
        drop(session);
        drop(server);
    });

    // Client: connect, receive frame, verify state
    let client = QuicClient::new().unwrap();
    let client_conn = client.connect(addr, "localhost", &cert).await.unwrap();
    let client_session = ClientSession::connect(client_conn, 24, 80, vec![])
        .await
        .unwrap();

    let data = tokio::time::timeout(Duration::from_secs(5), client_session.recv_output())
        .await
        .unwrap()
        .unwrap();

    let frame = SspFrame::decode(&data).unwrap();
    let mut receiver = SspReceiver::new(24);
    let result = receiver.process_frame(&frame).unwrap();
    assert!(result.is_some());
    assert_eq!(receiver.state().rows[0], "ssp over quic");
    assert_eq!(receiver.state().rows[1], "line two");
    assert_eq!(receiver.state().cursor_x, 8);

    // Send ACK back
    let ack = SspFrame::ack_only(receiver.ack_num());
    let mut ack_data = vec![DATAGRAM_SSP_ACK];
    ack_data.extend_from_slice(&ack.encode());
    client_session.send_input(Bytes::from(ack_data)).unwrap();

    // Wait a moment for server to process
    tokio::time::sleep(Duration::from_millis(100)).await;
    server_task.abort();
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
    let client_session = ClientSession::connect(client_conn, 24, 80, vec![])
        .await
        .unwrap();

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

// ---------------------------------------------------------------------------
// SSP stream fallback: oversized frames sent via uni stream
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ssp_oversized_frame_via_stream() {
    use rose::protocol::{ClientSession, ServerSession};
    use rose::scrollback;
    use rose::ssp::{ScreenState, SspFrame, SspReceiver, SspSender};
    use rose::transport::{QuicClient, QuicServer};

    let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let cert = server.server_cert_der().clone();

    // Server: accept, build a large screen state, send via uni stream
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (session, _, _) = ServerSession::accept(conn).await.unwrap();

        let mut sender = SspSender::new();
        // Create a state with long rows to produce an oversized frame
        let rows: Vec<String> = (0..24)
            .map(|i| format!("row_{i}_{}", "X".repeat(200)))
            .collect();
        sender.push_state(ScreenState {
            rows,
            cursor_x: 0,
            cursor_y: 0,
        });

        let frame = sender.generate_frame().unwrap();
        let stream_data = frame.encode_for_stream();

        // Send via uni stream with type prefix (simulating the oversized fallback)
        let conn = session.connection().clone();
        let mut stream = conn.open_uni().await.unwrap();
        stream
            .write_all(&[scrollback::stream_type::SSP_FRAME])
            .await
            .unwrap();
        stream.write_all(&stream_data).await.unwrap();
        stream.finish().unwrap();

        // Keep alive for client to read
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(session);
        drop(server);
    });

    // Client: connect, accept uni stream, decode frame
    let client = QuicClient::new().unwrap();
    let client_conn = client.connect(addr, "localhost", &cert).await.unwrap();
    let _client_session = ClientSession::connect(client_conn.clone(), 24, 80, vec![])
        .await
        .unwrap();

    let mut uni = tokio::time::timeout(Duration::from_secs(5), client_conn.accept_uni())
        .await
        .unwrap()
        .unwrap();

    // Read type prefix byte
    let mut type_buf = [0u8; 1];
    uni.read_exact(&mut type_buf).await.unwrap();
    assert_eq!(type_buf[0], scrollback::stream_type::SSP_FRAME);

    // Read length prefix
    let mut len_buf = [0u8; 4];
    uni.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let data = uni.read_to_end(len).await.unwrap();

    let frame = SspFrame::decode(&data).unwrap();
    let mut receiver = SspReceiver::new(24);
    let result = receiver.process_frame(&frame).unwrap();
    assert!(result.is_some());
    assert!(receiver.state().rows[0].starts_with("row_0_"));
    assert_eq!(receiver.state().rows.len(), 24);

    server_task.abort();
}
