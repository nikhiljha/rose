use std::io::Write;
use std::path::Path;

use bytes::Bytes;
use crossterm::terminal;

use crate::config::{self, CertKeyPair, RosePaths};
use crate::scrollback;
use crate::ssp::{MAX_STREAM_FRAME_BYTES, SspFrame};

pub(super) struct SspFrameSender {
    connection: quinn::Connection,
    pending: tokio::sync::watch::Sender<Option<EncodedFrame>>,
    worker: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
struct EncodedFrame {
    key: (u64, u64),
    data: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FrameSendResult {
    Sent,
    TooLarge,
    Disconnected,
}

impl SspFrameSender {
    pub(super) fn new(connection: quinn::Connection) -> Self {
        let (pending, receive) = tokio::sync::watch::channel(None);
        let worker = tokio::spawn(forward_screen_frames(connection.clone(), receive));
        Self {
            connection,
            pending,
            worker,
        }
    }

    pub(super) fn send(&self, frame: Option<&SspFrame>) -> FrameSendResult {
        if self.connection.close_reason().is_some() {
            return FrameSendResult::Disconnected;
        }
        let Some(frame) = frame else {
            return if self.pending.send(None).is_ok() {
                FrameSendResult::Sent
            } else {
                FrameSendResult::Disconnected
            };
        };
        let data = frame.encode();
        if data.len() > MAX_STREAM_FRAME_BYTES {
            tracing::warn!("screen exceeds reliable frame limit");
            return FrameSendResult::TooLarge;
        }
        if self
            .connection
            .max_datagram_size()
            .is_some_and(|max| data.len() <= max)
        {
            if self.pending.send(None).is_err() {
                return FrameSendResult::Disconnected;
            }
            return if self.connection.send_datagram(Bytes::from(data)).is_ok() {
                FrameSendResult::Sent
            } else {
                FrameSendResult::Disconnected
            };
        }
        if self
            .pending
            .send(Some(EncodedFrame {
                key: (frame.old_num, frame.new_num),
                data: Bytes::from(data),
            }))
            .is_ok()
        {
            FrameSendResult::Sent
        } else {
            FrameSendResult::Disconnected
        }
    }
}

impl Drop for SspFrameSender {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

struct ResetOnDrop(quinn::SendStream);

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        let _ = self.0.reset(0u32.into());
    }
}

async fn forward_screen_frames(
    connection: quinn::Connection,
    mut pending: tokio::sync::watch::Receiver<Option<EncodedFrame>>,
) {
    'updates: loop {
        let frame = pending.borrow_and_update().clone();
        let Some(frame) = frame else {
            if pending.changed().await.is_err() {
                return;
            }
            continue;
        };
        let transfer = async {
            let mut stream = ResetOnDrop(connection.open_uni().await?);
            stream
                .0
                .write_all(&[scrollback::stream_type::SSP_FRAME])
                .await?;
            stream
                .0
                .write_all(&(frame.data.len() as u32).to_be_bytes())
                .await?;
            stream.0.write_all(&frame.data).await?;
            stream.0.finish()?;
            let _ = stream.0.stopped().await?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::pin!(transfer);
        loop {
            tokio::select! {
                result = &mut transfer => {
                    if let Err(error) = result {
                        tracing::debug!(%error, "screen transfer ended");
                    }
                    break;
                }
                changed = pending.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    if pending.borrow_and_update().is_none() {
                        continue 'updates;
                    }
                }
                _ = connection.closed() => return,
            }
        }
        if pending.borrow().as_ref().map(|next| next.key) != Some(frame.key) {
            continue;
        }
        if pending.changed().await.is_err() {
            return;
        }
    }
}

/// Loads the persistent client certificate from `~/.config/rose/`, or
/// generates one if it doesn't exist yet. The same cert is used for all
/// connection modes (native, bootstrap, reattach).
///
/// Cert and key are stored as DER files alongside the PEM files that
/// `rose keygen` generates.
///
/// COVERAGE: CLI helper tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn load_or_generate_client_cert() -> anyhow::Result<CertKeyPair> {
    let paths = RosePaths::resolve();
    std::fs::create_dir_all(&paths.config_dir)?;
    let cert_der_path = paths.config_dir.join("client.crt.der");
    let key_der_path = paths.config_dir.join("client.key.der");

    if cert_der_path.exists() && key_der_path.exists() {
        let cert_der_bytes = std::fs::read(&cert_der_path)?;
        let key_der = std::fs::read(&key_der_path)?;
        Ok(CertKeyPair {
            cert_pem: String::new(),
            key_pem: String::new(),
            cert_der: rustls::pki_types::CertificateDer::from(cert_der_bytes),
            key_der,
        })
    } else {
        let cert = config::generate_self_signed_cert(&["localhost".to_string()])?;
        std::fs::write(&cert_der_path, cert.cert_der.as_ref())?;
        write_private_key(&key_der_path, &cert.key_der)?;
        std::fs::write(paths.config_dir.join("client.crt"), &cert.cert_pem)?;
        write_private_key(
            &paths.config_dir.join("client.key"),
            cert.key_pem.as_bytes(),
        )?;
        eprintln!(
            "Generated client certificate at {}",
            cert_der_path.display()
        );
        Ok(cert)
    }
}

/// Writes private key data to a file with owner-only permissions (0o600).
#[cfg(unix)]
pub(super) fn write_private_key(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

/// Writes private key data to a file (non-Unix fallback).
#[cfg(not(unix))]
pub(super) fn write_private_key(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

/// Generates a random u16 using system entropy.
///
/// COVERAGE: Thin wrapper for bootstrap port randomization.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn rand_u16() -> u16 {
    let mut buf = [0u8; 2];
    getrandom::getrandom(&mut buf).expect("OS RNG unavailable");
    u16::from_ne_bytes(buf)
}

/// Hex-encodes a byte slice.
pub(super) fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Builds a shell command that preserves connection and certificate options.
pub(super) fn connect_command(
    host: &str,
    port: u16,
    cert_path: Option<&Path>,
    client_cert_path: Option<&Path>,
) -> String {
    let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
    let mut command = format!("rose connect {} --port {port}", quote(host));
    for (flag, path) in [("cert", cert_path), ("client-cert", client_cert_path)] {
        if let Some(path) = path {
            command.push_str(&format!(" --{flag} {}", quote(&path.to_string_lossy())));
        }
    }
    command
}

/// Extracts the peer's DER-encoded TLS certificate from a QUIC connection.
///
/// On the server side this returns the client's certificate; on the client
/// side it returns the server's certificate. Returns `None` if the peer
/// did not present a certificate (e.g., no mutual TLS).
pub(super) fn extract_peer_cert(conn: &quinn::Connection) -> Option<Vec<u8>> {
    let identity = conn.peer_identity()?;
    let certs = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    certs.first().map(|c| c.as_ref().to_vec())
}

/// Parses a `ROSE_BOOTSTRAP` line from the server's stdout.
///
/// Expected format: `ROSE_BOOTSTRAP <port> <server_cert_hex>`
///
/// # Errors
///
/// Returns an error if the line is malformed.
pub(super) fn parse_bootstrap_line(line: &str) -> anyhow::Result<(u16, Vec<u8>)> {
    let line = line.trim();
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() != 3 || parts[0] != "ROSE_BOOTSTRAP" {
        anyhow::bail!("invalid bootstrap line: expected ROSE_BOOTSTRAP <port> <server_cert_hex>");
    }
    let port: u16 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid port in bootstrap line: {}", parts[1]))?;
    let server_cert_der = hex_decode(parts[2])?;
    Ok((port, server_cert_der))
}

/// Parses a `ROSE_STUN` line from the client's SSH stdin.
///
/// Expected format: `ROSE_STUN <ip> <port>`
///
/// # Errors
///
/// Returns an error if the line is malformed.
pub(super) fn parse_stun_line(line: &str) -> anyhow::Result<std::net::SocketAddr> {
    let line = line.trim();
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() != 3 || parts[0] != "ROSE_STUN" {
        anyhow::bail!("invalid STUN line: expected ROSE_STUN <ip> <port>");
    }
    let ip: std::net::IpAddr = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IP in STUN line: {}", parts[1]))?;
    let port: u16 = parts[2]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid port in STUN line: {}", parts[2]))?;
    Ok(std::net::SocketAddr::new(ip, port))
}

/// Hex-decodes a string to bytes.
pub(super) fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex string has odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| anyhow::anyhow!("invalid hex at position {i}"))
        })
        .collect()
}

/// Generates a random 16-byte session ID using system entropy.
///
/// COVERAGE: Thin wrapper around getrandom, tested via integration tests.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn rand_session_id() -> [u8; 16] {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect("OS RNG unavailable");
    buf
}

/// RAII guard to restore terminal mode on drop.
///
/// When the kitty keyboard protocol is available, it is automatically
/// enabled on creation and disabled on drop.
pub(super) struct RawModeGuard {
    /// Whether the kitty keyboard protocol was enabled and needs to be popped.
    kitty_enabled: bool,
}

impl RawModeGuard {
    /// Enters raw mode and optionally enables the kitty keyboard protocol
    /// if the terminal supports it. The protocol is automatically disabled
    /// when the guard is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if enabling raw mode fails.
    pub(super) fn enable() -> anyhow::Result<Self> {
        terminal::enable_raw_mode()?;
        let kitty_enabled = enable_kitty_keyboard();
        Ok(Self { kitty_enabled })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(b"\x1b[?25h\x1b[0 q");
        let _ = stdout.flush();
        if self.kitty_enabled {
            let _ = crossterm::execute!(
                std::io::stdout(),
                crossterm::event::PopKeyboardEnhancementFlags
            );
        }
        let _ = terminal::disable_raw_mode();
    }
}

/// Attempts to enable the kitty keyboard protocol for richer key events.
///
/// Returns `true` if enhancement was successfully pushed, `false` otherwise
/// (e.g. terminal does not support the protocol).
///
/// COVERAGE: Requires a real terminal to test keyboard enhancement detection.
#[cfg_attr(coverage_nightly, coverage(off))]
fn enable_kitty_keyboard() -> bool {
    if terminal::supports_keyboard_enhancement().unwrap_or(false) {
        crossterm::execute!(
            std::io::stdout(),
            crossterm::event::PushKeyboardEnhancementFlags(
                crossterm::event::KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
                    | crossterm::event::KeyboardEnhancementFlags::REPORT_ALL_KEYS_AS_ESCAPE_CODES
            )
        )
        .is_ok()
    } else {
        false
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::ssp::{ScreenState, SspSender};

    fn large_frame() -> SspFrame {
        let mut state = ScreenState::empty(64);
        state.rows.fill("x".repeat(60_000));
        let mut sender = SspSender::new();
        sender.push_state(state);
        sender.generate_frame().unwrap()
    }

    async fn start_transfer(
        client: &quinn::Connection,
        server: &quinn::Connection,
        frame: &SspFrame,
    ) -> (SspFrameSender, quinn::RecvStream) {
        let sender = SspFrameSender::new(server.clone());
        assert_eq!(sender.send(Some(frame)), FrameSendResult::Sent);
        let mut stream = client.accept_uni().await.unwrap();
        let mut prefix = [0];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix, [scrollback::stream_type::SSP_FRAME]);
        (sender, stream)
    }

    #[tokio::test]
    async fn newer_large_screens_replace_backlog_without_interrupting_progress() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let mut frame = large_frame();
        let (sender, mut first) = start_transfer(&client, &server, &frame).await;
        for num in [2, 3] {
            frame.new_num = num;
            assert_eq!(sender.send(Some(&frame)), FrameSendResult::Sent);
        }
        let initial = first
            .read_to_end(MAX_STREAM_FRAME_BYTES)
            .await
            .expect("continuous output starved the in-flight screen");
        assert_eq!(SspFrame::decode_from_stream(&initial).unwrap().new_num, 1);
        let mut latest =
            tokio::time::timeout(std::time::Duration::from_secs(2), client.accept_uni())
                .await
                .unwrap()
                .unwrap();
        let data = latest.read_to_end(MAX_STREAM_FRAME_BYTES).await.unwrap();
        assert_eq!(data[0], scrollback::stream_type::SSP_FRAME);
        assert_eq!(SspFrame::decode_from_stream(&data[1..]).unwrap().new_num, 3);
    }

    #[tokio::test]
    async fn datagrams_cancel_pending_streams_and_closed_connections_fail() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let (sender, mut stream) = start_transfer(&client, &server, &large_frame()).await;
        assert_eq!(
            sender.send(Some(&SspFrame::ack_only(7))),
            FrameSendResult::Sent
        );
        let data = client.read_datagram().await.unwrap();
        assert_eq!(SspFrame::decode(&data).unwrap().ack_num, 7);
        assert!(stream.read_to_end(MAX_STREAM_FRAME_BYTES).await.is_err());
        server.close(0u32.into(), b"finished");
        assert_eq!(sender.send(None), FrameSendResult::Disconnected);
    }

    #[tokio::test]
    async fn oversized_screens_are_rejected_before_queueing() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let sender = SspFrameSender::new(server);
        let mut frame = large_frame();
        frame.diff.as_mut().unwrap().changed_rows =
            (0..300).map(|row| (row, "x".repeat(60_000))).collect();
        frame.diff.as_mut().unwrap().total_rows = 300;
        assert_eq!(sender.send(Some(&frame)), FrameSendResult::TooLarge);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), client.accept_uni(),)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn completed_stream_can_retry_after_lost_application_ack() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let sender = SspFrameSender::new(server);
        let frame = large_frame();
        assert_eq!(sender.send(Some(&frame)), FrameSendResult::Sent);
        let mut first = client.accept_uni().await.unwrap();
        first.read_to_end(MAX_STREAM_FRAME_BYTES).await.unwrap();
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(20));
        let mut retry = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    stream = client.accept_uni() => break stream.unwrap(),
                    _ = interval.tick() => {
                        assert_eq!(sender.send(Some(&frame)), FrameSendResult::Sent);
                    }
                }
            }
        })
        .await
        .unwrap();
        let data = retry.read_to_end(MAX_STREAM_FRAME_BYTES).await.unwrap();
        assert_eq!(
            SspFrame::decode_from_stream(&data[1..]).unwrap().new_num,
            frame.new_num
        );
        assert_eq!(sender.send(None), FrameSendResult::Sent);
    }

    #[tokio::test]
    async fn dropping_sender_resets_inflight_screen_transfer() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let (sender, mut receive) = start_transfer(&client, &server, &large_frame()).await;
        drop(sender);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                receive.read_to_end(8 * 1024 * 1024),
            )
            .await
            .unwrap()
            .is_err()
        );
    }

    #[tokio::test]
    async fn repeated_screen_frames_share_one_pending_transfer() {
        let (client, server, _fixture, _endpoint) = crate::testutil::connected_pair().await;
        let frame = large_frame();
        let (sender, mut receive) = start_transfer(&client, &server, &frame).await;
        for _ in 0..3 {
            assert_eq!(sender.send(Some(&frame)), FrameSendResult::Sent);
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), client.accept_uni(),)
                .await
                .is_err(),
            "retransmission queued another oversized screen"
        );
        assert_eq!(sender.send(None), FrameSendResult::Sent);
        assert!(receive.read_to_end(8 * 1024 * 1024).await.is_err());
    }

    #[test]
    fn connect_command_preserves_quoted_certificate_paths() {
        assert_eq!(
            connect_command(
                "server.example",
                4433,
                Some(Path::new("server's cert.der")),
                Some(Path::new("client cert.der")),
            ),
            "rose connect 'server.example' --port 4433 --cert 'server'\\''s cert.der' --client-cert 'client cert.der'"
        );
        assert_eq!(
            connect_command("server.example", 4433, None, None),
            "rose connect 'server.example' --port 4433"
        );
    }

    #[test]
    fn hex_encode_roundtrip() {
        let data = b"hello world";
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(b""), "");
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hex_decode_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_invalid_chars() {
        assert!(hex_decode("zzzz").is_err());
    }

    #[test]
    fn parse_bootstrap_valid() {
        let server_cert = b"\x01\x02\x03";
        let line = format!("ROSE_BOOTSTRAP 60123 {}\n", hex_encode(server_cert));
        let (port, der) = parse_bootstrap_line(&line).unwrap();
        assert_eq!(port, 60123);
        assert_eq!(der, server_cert);
    }

    #[test]
    fn parse_bootstrap_missing_prefix() {
        assert!(parse_bootstrap_line("WRONG 60123 aabbcc").is_err());
    }

    #[test]
    fn parse_bootstrap_invalid_port() {
        assert!(parse_bootstrap_line("ROSE_BOOTSTRAP notaport aabbcc").is_err());
    }

    #[test]
    fn parse_bootstrap_too_few_parts() {
        assert!(parse_bootstrap_line("ROSE_BOOTSTRAP 60123").is_err());
    }

    #[test]
    fn parse_bootstrap_invalid_hex() {
        assert!(parse_bootstrap_line("ROSE_BOOTSTRAP 60123 zzzz").is_err());
    }

    #[test]
    fn parse_stun_line_valid() {
        let addr = parse_stun_line("ROSE_STUN 203.0.113.5 12345").unwrap();
        assert_eq!(
            addr,
            "203.0.113.5:12345".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_stun_line_missing_prefix() {
        assert!(parse_stun_line("WRONG 10.0.0.1 8080").is_err());
    }

    #[test]
    fn parse_stun_line_invalid_ip() {
        assert!(parse_stun_line("ROSE_STUN not_an_ip 8080").is_err());
    }

    #[test]
    fn parse_stun_line_invalid_port() {
        assert!(parse_stun_line("ROSE_STUN 10.0.0.1 notaport").is_err());
    }

    #[test]
    fn parse_stun_line_too_few_parts() {
        assert!(parse_stun_line("ROSE_STUN 10.0.0.1").is_err());
    }
}
