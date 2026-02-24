//! End-to-end keystroke latency benchmark.
//!
//! Measures the full round-trip time for a keystroke through the `RoSE` pipeline:
//! client sends key via QUIC datagram -> server receives -> PTY write -> PTY echo
//! -> server reads PTY output -> terminal processes -> SSP diff -> datagram sent
//! -> client receives and decodes.
//!
//! Set `ROSE_BENCH_TRACE=1` to emit a Chrome trace file (`rose-bench-trace.json`,
//! viewable at <https://ui.perfetto.dev>).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};

use rose::config::generate_self_signed_cert;
use rose::protocol::{ClientSession, ServerSession};
use rose::pty::PtySession;
use rose::ssp::{
    DATAGRAM_KEYSTROKE, DATAGRAM_SSP_ACK, ScreenState, SspFrame, SspReceiver, SspSender,
    render_diff_ansi,
};
use rose::terminal::RoseTerminal;
use rose::transport::{QuicClient, QuicServer};

fn keystroke_roundtrip(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let _trace_guard = if std::env::var("ROSE_BENCH_TRACE").is_ok() {
        use tracing_subscriber::prelude::*;

        let (chrome_layer, guard) = tracing_chrome::ChromeLayerBuilder::new()
            .file("rose-bench-trace.json")
            .build();
        let filter =
            tracing_subscriber::filter::Targets::new().with_target("rose", tracing::Level::TRACE);
        tracing_subscriber::registry()
            .with(chrome_layer.with_filter(filter))
            .init();
        Some(guard)
    } else {
        None
    };

    let (client_conn, _keep_alive) = rt.block_on(async {
        let server_cert = generate_self_signed_cert(&["localhost".to_string()]).unwrap();
        let client_cert = generate_self_signed_cert(&["bench-client".to_string()]).unwrap();

        let auth_dir = std::env::temp_dir().join(format!("rose-bench-auth-{}", std::process::id()));
        std::fs::create_dir_all(&auth_dir).unwrap();
        std::fs::write(auth_dir.join("client.crt"), client_cert.cert_der.as_ref()).unwrap();

        let server =
            QuicServer::bind_mutual_tls("127.0.0.1:0".parse().unwrap(), server_cert, &auth_dir)
                .unwrap();
        let addr = server.local_addr().unwrap();
        let cert_der = server.server_cert_der().clone();

        let server_handle = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().unwrap();
            let (session, rows, cols) = ServerSession::accept(conn).await.unwrap();

            let pty = PtySession::open_command(rows, cols, "cat", &[]).unwrap();
            let mut pty_output = pty.subscribe_output();
            let pty_writer = pty.clone_writer();

            let server_conn = session.connection().clone();
            let terminal = Arc::new(Mutex::new(RoseTerminal::new(rows, cols)));
            let sender = Arc::new(Mutex::new(SspSender::new()));

            // Server input: client datagrams -> PTY write / ACK processing
            let input_conn = server_conn.clone();
            let sender_in = Arc::clone(&sender);
            let input_task = tokio::spawn(async move {
                while let Ok(data) = input_conn.read_datagram().await {
                    if data.is_empty() {
                        continue;
                    }
                    match data[0] {
                        DATAGRAM_KEYSTROKE => {
                            let mut w = pty_writer.lock().expect("writer lock");
                            let _ = std::io::Write::write_all(&mut *w, &data[1..]);
                            let _ = std::io::Write::flush(&mut *w);
                        }
                        DATAGRAM_SSP_ACK => {
                            if let Ok(frame) = SspFrame::decode(&data[1..]) {
                                sender_in
                                    .lock()
                                    .expect("sender lock")
                                    .process_ack(frame.ack_num);
                            }
                        }
                        _ => {}
                    }
                }
            });

            // Server output: PTY -> terminal -> SSP -> datagram (no rate limiting)
            let output_conn = server_conn;
            let output_task = tokio::spawn(async move {
                while let Ok(data) = pty_output.recv().await {
                    {
                        terminal.lock().expect("terminal lock").advance(&data);
                    }
                    let state = terminal.lock().expect("terminal lock").snapshot();
                    let mut s = sender.lock().expect("sender lock");
                    s.push_state(state);
                    if let Some(frame) = s.generate_frame() {
                        let encoded = frame.encode();
                        let _ = output_conn.send_datagram(Bytes::from(encoded));
                    }
                }
            });

            // Keep server alive until tasks finish
            tokio::select! {
                _ = input_task => {},
                _ = output_task => {},
            }
            drop(pty);
            drop(session);
        });

        let client = QuicClient::new().unwrap();
        let client_conn = client
            .connect_with_cert(addr, "localhost", &cert_der, &client_cert)
            .await
            .unwrap();
        let client_session = ClientSession::connect(client_conn.clone(), 24, 80, vec![])
            .await
            .unwrap();

        // Wait for server to finish setup, then drain any initial PTY output
        // (e.g., terminal line discipline setup sequences)
        tokio::time::sleep(Duration::from_millis(200)).await;
        let drain_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        while let Ok(Ok(_)) =
            tokio::time::timeout_at(drain_deadline, client_conn.read_datagram()).await
        {}

        let conn = client_session.connection().clone();
        (conn, (client, client_session, server_handle))
    });

    let receiver = Arc::new(Mutex::new(SspReceiver::new(24)));

    // --- Benchmark: send keystroke, wait for SSP frame response ---
    c.bench_function("keystroke_roundtrip", |b| {
        b.to_async(&rt).iter(|| {
            let conn = client_conn.clone();
            let recv = Arc::clone(&receiver);
            async move {
                // Send keystroke 'x'
                let mut data = vec![DATAGRAM_KEYSTROKE];
                data.push(b'x');
                conn.send_datagram(Bytes::from(data)).unwrap();

                // Wait for SSP frame response
                let frame_data = conn.read_datagram().await.unwrap();
                let frame = SspFrame::decode(&frame_data).unwrap();

                // Apply diff and send ACK
                {
                    let mut r = recv.lock().expect("receiver lock");
                    let _ = r.process_frame(&frame);
                }
                let ack_num = recv.lock().expect("receiver lock").ack_num();
                let ack = SspFrame::ack_only(ack_num);
                let mut ack_data = vec![DATAGRAM_SSP_ACK];
                ack_data.extend_from_slice(&ack.encode());
                conn.send_datagram(Bytes::from(ack_data)).unwrap();
            }
        });
    });
}

/// Fills a terminal with colorful ANSI content to simulate realistic screen
/// state (colored compiler output, syntax-highlighted code, etc.).
fn fill_with_ansi(term: &mut RoseTerminal, rows: u16, cols: u16) {
    let colors = [31, 32, 33, 34, 35, 36, 91, 92, 93, 94, 95, 96];
    for r in 0..rows {
        let color = colors[r as usize % colors.len()];
        // Mix of colored and plain text, bold, reset — typical compiler/editor output
        let content: String = (0..cols)
            .map(|c| {
                if c % 20 == 0 {
                    format!("\x1b[{color};1m")
                } else if c % 20 == 10 {
                    "\x1b[0m".to_string()
                } else {
                    String::from((b'A' + (c % 26) as u8) as char)
                }
            })
            .collect();
        term.advance(format!("{content}\r\n").as_bytes());
    }
}

/// Microbenchmark: terminal advance + snapshot across terminal sizes.
///
/// Isolates the wezterm terminal emulation cost: feeding raw bytes and
/// extracting screen state with ANSI color information.
fn terminal_pipeline(c: &mut Criterion) {
    let sizes: &[(u16, u16, &str)] = &[
        (24, 80, "24x80"),
        (50, 120, "50x120"),
        (200, 200, "200x200"),
    ];

    let mut group = c.benchmark_group("terminal_advance_snapshot");
    for &(rows, cols, label) in sizes {
        let mut term = RoseTerminal::new(rows, cols);
        fill_with_ansi(&mut term, rows, cols);

        group.bench_function(label, |b| {
            b.iter(|| {
                term.advance(b"x");
                term.snapshot()
            });
        });
    }
    group.finish();
}

/// Microbenchmark: full SSP pipeline without network, across terminal sizes.
///
/// Measures: terminal advance -> snapshot -> `push_state` -> `generate_frame`
/// -> encode -> decode -> `process_frame` -> `render_diff_ansi`. This is the
/// pure computation cost per keystroke, excluding QUIC and PTY overhead.
fn ssp_pipeline(c: &mut Criterion) {
    let sizes: &[(u16, u16, &str)] = &[
        (24, 80, "24x80"),
        (50, 120, "50x120"),
        (200, 200, "200x200"),
    ];

    let mut group = c.benchmark_group("ssp_diff_render_cycle");
    for &(rows, cols, label) in sizes {
        let mut term = RoseTerminal::new(rows, cols);
        fill_with_ansi(&mut term, rows, cols);

        let mut sender = SspSender::new();
        let initial = term.snapshot();
        sender.push_state(initial);
        sender.process_ack(1);

        let mut receiver = SspReceiver::new(rows);
        let mut old_screen = ScreenState::empty(rows);

        group.bench_function(label, |b| {
            b.iter(|| {
                term.advance(b"x");
                let snap = term.snapshot();
                sender.push_state(snap);
                let frame = sender.generate_frame().unwrap();

                let encoded = frame.encode();
                let decoded = SspFrame::decode(&encoded).unwrap();
                let _ = receiver.process_frame(&decoded);
                let new_state = receiver.state().clone();
                let _ansi = render_diff_ansi(&old_screen, &new_state);

                old_screen = new_state;
                sender.process_ack(receiver.ack_num());
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    keystroke_roundtrip,
    terminal_pipeline,
    ssp_pipeline
);
criterion_main!(benches);
