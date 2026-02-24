//! Integration tests exercising multiple `RoSE` layers together.

use std::time::Duration;

mod mtls_helper {
    use rose::config::{self, CertKeyPair};
    use rose::transport::{QuicClient, QuicServer};
    use std::net::SocketAddr;
    use std::path::PathBuf;

    pub struct MtlsFixture {
        pub server: QuicServer,
        pub client_cert: CertKeyPair,
        _auth_dir: PathBuf,
    }

    impl MtlsFixture {
        pub fn new() -> Self {
            let server_cert =
                config::generate_self_signed_cert(&["localhost".to_string()]).unwrap();
            let client_cert =
                config::generate_self_signed_cert(&["localhost".to_string()]).unwrap();

            let auth_dir = std::env::temp_dir().join(format!(
                "rose-integ-test-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&auth_dir).unwrap();
            std::fs::write(auth_dir.join("client.crt"), client_cert.cert_der.as_ref()).unwrap();

            let server =
                QuicServer::bind_mutual_tls("127.0.0.1:0".parse().unwrap(), server_cert, &auth_dir)
                    .unwrap();

            Self {
                server,
                client_cert,
                _auth_dir: auth_dir,
            }
        }

        pub fn addr(&self) -> SocketAddr {
            self.server.local_addr().unwrap()
        }

        pub async fn connect(&self, client: &QuicClient) -> quinn::Connection {
            client
                .connect_with_cert(
                    self.addr(),
                    "localhost",
                    self.server.server_cert_der(),
                    &self.client_cert,
                )
                .await
                .unwrap()
        }
    }

    impl Drop for MtlsFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self._auth_dir);
        }
    }
}

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
    use rose::transport::QuicClient;

    let fixture = mtls_helper::MtlsFixture::new();

    let server_accept = tokio::spawn({
        let endpoint = fixture.server.endpoint.clone();
        async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            ServerSession::accept(conn).await.unwrap()
        }
    });

    let client = QuicClient::new().unwrap();
    let client_conn = fixture.connect(&client).await;
    let client_session = ClientSession::connect(client_conn, 24, 80, vec![])
        .await
        .unwrap();

    let (server_session, rows, cols) = server_accept.await.unwrap();
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
// SSP rendering E2E: server terminal → SSP → render_diff_ansi → client
// wezterm terminal. After scrolling, the client terminal must have
// scrollback lines (meaning render_diff_ansi caused real terminal scrolling,
// not just absolute cursor repositioning).
// ---------------------------------------------------------------------------

/// End-to-end SSP rendering test with a real wezterm terminal on the client
/// side. Verifies that:
/// 1. Visible content matches between server and client after scrolling
/// 2. The client terminal has scrollback lines (render caused real scrolling)
///
/// Regression test: previously `render_diff_ansi` used absolute cursor
/// positioning which never caused the client terminal to scroll.
#[test]
fn ssp_render_scrollback_in_client_terminal() {
    use rose::ssp::{SspReceiver, SspSender, render_diff_ansi};
    use rose::terminal::RoseTerminal;

    let rows: u16 = 5;
    let cols: u16 = 40;

    // Server side
    let mut server_term = RoseTerminal::new(rows, cols);
    let mut sender = SspSender::new();

    // Client side: SSP receiver + a real wezterm terminal that receives
    // the ANSI output from render_diff_ansi (simulating the user's terminal)
    let mut receiver = SspReceiver::new(rows);
    let mut client_term = RoseTerminal::new(rows, cols);
    // Clear client terminal (same as client_session_loop does)
    client_term.advance(b"\x1b[2J\x1b[H");

    // Helper: run one SSP cycle (matches process_ssp_frame: diffs against
    // the client terminal's actual screen, not the previous SSP state)
    let ssp_cycle = |server_term: &RoseTerminal,
                     sender: &mut SspSender,
                     receiver: &mut SspReceiver,
                     client_term: &mut RoseTerminal| {
        let snap = server_term.snapshot();
        sender.push_state(snap);
        let frame = sender.generate_frame().expect("should have a frame");
        receiver.process_frame(&frame).expect("frame should apply");
        let new_state = receiver.state().clone();
        let ansi = render_diff_ansi(&client_term.snapshot(), &new_state);
        client_term.advance(&ansi);
        sender.process_ack(receiver.ack_num());
    };

    // Fill the screen (5 lines in 5-row terminal)
    server_term.advance(b"line 1\r\nline 2\r\nline 3\r\nline 4\r\nline 5");
    ssp_cycle(&server_term, &mut sender, &mut receiver, &mut client_term);

    // No scrollback yet — screen isn't full enough to scroll
    assert!(
        client_term.scrollback_lines().is_empty(),
        "no scrollback before scroll"
    );

    // Write 10 more lines — forces server terminal to scroll repeatedly
    for i in 6..=15 {
        server_term.advance(format!("\r\nline {i}").as_bytes());
        ssp_cycle(&server_term, &mut sender, &mut receiver, &mut client_term);
    }

    // Server terminal has scrolled — verify it has scrollback
    let server_scrollback = server_term.scrollback_lines();
    assert!(
        !server_scrollback.is_empty(),
        "server should have scrollback after writing 15 lines to 5-row terminal"
    );

    // Client terminal visible content should match server
    let server_text = server_term.screen_text();
    let client_text = client_term.screen_text();
    let server_lines: Vec<&str> = server_text.lines().map(str::trim_end).collect();
    let client_lines: Vec<&str> = client_text.lines().map(str::trim_end).collect();
    assert_eq!(
        server_lines, client_lines,
        "client visible content should match server"
    );

    // KEY ASSERTION: client terminal must also have scrollback.
    // If render_diff_ansi used absolute positioning only, the client
    // terminal never actually scrolled, so scrollback will be empty.
    let client_scrollback = client_term.scrollback_lines();
    assert!(
        !client_scrollback.is_empty(),
        "client terminal should have scrollback lines after server scrolled, \
         but got none — render_diff_ansi is using absolute positioning instead \
         of real scroll operations"
    );

    // ---------------------------------------------------------------
    // Phase 2: after scrolling, non-scroll updates must still render.
    // This reproduces the real-world freeze: ls scrolls, then the
    // shell prompt (a non-scroll single-row change) fails to display.
    // ---------------------------------------------------------------

    // Simulate typing a character (non-scroll change: only bottom row changes)
    server_term.advance(b"$ ");
    ssp_cycle(&server_term, &mut sender, &mut receiver, &mut client_term);

    let server_text = server_term.screen_text();
    let client_text = client_term.screen_text();
    let server_lines: Vec<&str> = server_text.lines().map(str::trim_end).collect();
    let client_lines: Vec<&str> = client_text.lines().map(str::trim_end).collect();
    assert_eq!(
        server_lines, client_lines,
        "after scroll, non-scroll update (prompt) should render correctly"
    );

    // Type more characters — simulates user typing after ls output
    for ch in ['h', 'e', 'l', 'l', 'o'] {
        server_term.advance(format!("{ch}").as_bytes());
        ssp_cycle(&server_term, &mut sender, &mut receiver, &mut client_term);
    }

    let server_text = server_term.screen_text();
    let client_text = client_term.screen_text();
    let server_lines: Vec<&str> = server_text.lines().map(str::trim_end).collect();
    let client_lines: Vec<&str> = client_text.lines().map(str::trim_end).collect();
    assert_eq!(
        server_lines, client_lines,
        "typing after scroll should render correctly on client"
    );
    // Verify the typed text is visible
    assert!(
        client_lines.iter().any(|l| l.contains("$ hello")),
        "client should show typed text '$ hello', got: {client_lines:?}"
    );

    // Phase 3: another scroll after non-scroll updates
    server_term.advance(b"\r\nmore output\r\nand more\r\nkeep going\r\nstill more\r\nfinal");
    ssp_cycle(&server_term, &mut sender, &mut receiver, &mut client_term);

    let server_text = server_term.screen_text();
    let client_text = client_term.screen_text();
    let server_lines: Vec<&str> = server_text.lines().map(str::trim_end).collect();
    let client_lines: Vec<&str> = client_text.lines().map(str::trim_end).collect();
    assert_eq!(
        server_lines, client_lines,
        "second scroll after typing should render correctly"
    );
}

// ---------------------------------------------------------------------------
// Resize + line wrapping: snapshot test with insta
// ---------------------------------------------------------------------------

#[test]
fn terminal_resize_wrapping() {
    use rose::terminal::RoseTerminal;

    /// Renders visible screen state as a human-readable string for snapshot
    /// comparison. Each row is shown with its index, pipe-delimited, with
    /// trailing whitespace trimmed.
    fn render_screen(term: &RoseTerminal) -> String {
        let (rows, cols) = term.size();
        let (cx, cy) = term.cursor_pos();
        let mut out = format!("size: {rows}x{cols}  cursor: ({cx},{cy})\n");
        for r in 0..rows {
            let text = term.line_text(r);
            let trimmed = text.trim_end();
            out.push_str(&format!("{r:2}|{trimmed}\n"));
        }
        out
    }

    let mut term = RoseTerminal::new(6, 20);
    // Write text that will wrap at 20 columns
    term.advance(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    // Also write a second line
    term.advance(b"\r\nshort line");

    insta::assert_snapshot!("initial_20col", render_screen(&term));

    // Resize wider — wrapped content should reflow
    term.resize(6, 40);
    insta::assert_snapshot!("after_widen_40col", render_screen(&term));

    // Resize very narrow — content wraps more aggressively
    term.resize(6, 10);
    insta::assert_snapshot!("after_narrow_10col", render_screen(&term));

    // Resize back to original
    term.resize(6, 20);
    insta::assert_snapshot!("after_restore_20col", render_screen(&term));
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
    use rose::transport::QuicClient;

    let fixture = mtls_helper::MtlsFixture::new();

    let server_task = tokio::spawn({
        let endpoint = fixture.server.endpoint.clone();
        async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
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

            let ack_data = session.recv_input().await.unwrap();
            assert_eq!(ack_data[0], DATAGRAM_SSP_ACK);
            let ack_frame = SspFrame::decode(&ack_data[1..]).unwrap();
            assert_eq!(ack_frame.ack_num, 1);

            drop(session);
        }
    });

    let client = QuicClient::new().unwrap();
    let client_conn = fixture.connect(&client).await;
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
    use rose::transport::QuicClient;

    let fixture = mtls_helper::MtlsFixture::new();

    let server_task = tokio::spawn({
        let endpoint = fixture.server.endpoint.clone();
        async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let (session, rows, cols) = ServerSession::accept(conn).await.unwrap();
            let pty = PtySession::open_command(rows, cols, "echo", &["e2e_test_output"]).unwrap();
            let mut rx = pty.subscribe_output();

            while let Ok(chunk) = rx.recv().await {
                if session.send_output(Bytes::from(chunk.to_vec())).is_err() {
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
    use rose::transport::QuicClient;

    let fixture = mtls_helper::MtlsFixture::new();

    let server_task = tokio::spawn({
        let endpoint = fixture.server.endpoint.clone();
        async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let (session, _, _) = ServerSession::accept(conn).await.unwrap();

            let mut sender = SspSender::new();
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

            let conn = session.connection().clone();
            let mut stream = conn.open_uni().await.unwrap();
            stream
                .write_all(&[scrollback::stream_type::SSP_FRAME])
                .await
                .unwrap();
            stream.write_all(&stream_data).await.unwrap();
            stream.finish().unwrap();

            tokio::time::sleep(Duration::from_secs(2)).await;
            drop(session);
        }
    });

    let client = QuicClient::new().unwrap();
    let client_conn = fixture.connect(&client).await;
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
