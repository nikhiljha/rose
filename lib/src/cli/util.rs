use std::io::Write;

use bytes::Bytes;
use crossterm::terminal;

use crate::config::{self, CertKeyPair, RosePaths};
use crate::scrollback;
use crate::ssp::SspFrame;

/// Sends an SSP frame as a QUIC datagram, falling back to a uni stream for
/// oversized frames. Returns `false` if the datagram send failed (connection
/// likely dead).
///
/// COVERAGE: CLI helper tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn send_ssp_frame(frame: &SspFrame, conn: &quinn::Connection) -> bool {
    let data = frame.encode();
    let max_dgram = conn.max_datagram_size().unwrap_or(1200);
    if data.len() <= max_dgram {
        conn.send_datagram(Bytes::from(data)).is_ok()
    } else {
        let stream_data = frame.encode_for_stream();
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Ok(mut stream) = conn.open_uni().await {
                let _ = stream
                    .write_all(&[scrollback::stream_type::SSP_FRAME])
                    .await;
                let _ = stream.write_all(&stream_data).await;
                let _ = stream.finish();
            }
        });
        true
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
pub(super) struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

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
