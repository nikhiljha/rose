//! Minimal STUN client for NAT traversal (RFC 5389).
//!
//! Implements only the STUN Binding Request/Response needed to discover the
//! public IP:port of a UDP socket behind NAT. Used as a fallback during SSH
//! bootstrap when direct UDP to the server is firewalled.

use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};

/// Errors from STUN discovery.
#[derive(Debug, thiserror::Error)]
pub enum StunError {
    /// Network I/O error.
    #[error("STUN I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// No STUN server responded within the timeout.
    #[error("no STUN server responded")]
    NoResponse,
    /// Response was malformed or missing the mapped address.
    #[error("invalid STUN response: {0}")]
    InvalidResponse(String),
}

/// STUN magic cookie (RFC 5389 Section 6).
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN Binding Request message type.
const BINDING_REQUEST: u16 = 0x0001;

/// STUN Binding Response (success) message type.
const BINDING_RESPONSE: u16 = 0x0101;

/// XOR-MAPPED-ADDRESS attribute type.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// MAPPED-ADDRESS attribute type (legacy fallback).
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// IPv4 address family in STUN attributes.
const FAMILY_IPV4: u8 = 0x01;

/// Public STUN servers to try in order.
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];

/// Builds a 20-byte STUN Binding Request.
fn build_binding_request(txn_id: &[u8; 12]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    // Message type: Binding Request
    buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Message length: 0 (no attributes)
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    // Magic cookie
    buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    // Transaction ID
    buf[8..20].copy_from_slice(txn_id);
    buf
}

/// Generates a random 12-byte STUN transaction ID using system entropy.
fn random_txn_id() -> [u8; 12] {
    let mut txn = [0u8; 12];
    getrandom::getrandom(&mut txn).expect("OS RNG unavailable");
    txn
}

/// Parses a STUN Binding Response to extract the mapped address.
///
/// Looks for `XOR-MAPPED-ADDRESS` first, then falls back to `MAPPED-ADDRESS`.
fn parse_binding_response(
    buf: &[u8],
    expected_txn_id: &[u8; 12],
) -> Result<SocketAddrV4, StunError> {
    if buf.len() < 20 {
        return Err(StunError::InvalidResponse("response too short".into()));
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_RESPONSE {
        return Err(StunError::InvalidResponse(format!(
            "expected Binding Response (0x0101), got 0x{msg_type:04x}"
        )));
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::InvalidResponse("wrong magic cookie".into()));
    }

    let txn_id = &buf[8..20];
    if txn_id != expected_txn_id {
        return Err(StunError::InvalidResponse("transaction ID mismatch".into()));
    }

    // Parse attributes
    let attrs_end = 20 + msg_len.min(buf.len() - 20);
    let mut pos = 20;
    let mut mapped_addr: Option<SocketAddrV4> = None;

    while pos + 4 <= attrs_end {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let attr_start = pos + 4;
        let attr_end = attr_start + attr_len;

        if attr_end > attrs_end {
            break;
        }

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS if attr_len >= 8 => {
                if let Some(addr) = parse_xor_mapped_address(&buf[attr_start..attr_end]) {
                    return Ok(addr);
                }
            }
            ATTR_MAPPED_ADDRESS if attr_len >= 8 && mapped_addr.is_none() => {
                mapped_addr = parse_mapped_address(&buf[attr_start..attr_end]);
            }
            _ => {}
        }

        // Attributes are padded to 4-byte boundaries
        let padded_len = (attr_len + 3) & !3;
        pos = attr_start + padded_len;
    }

    mapped_addr.ok_or_else(|| StunError::InvalidResponse("no mapped address attribute".into()))
}

/// Parses an `XOR-MAPPED-ADDRESS` attribute value (IPv4 only).
fn parse_xor_mapped_address(value: &[u8]) -> Option<SocketAddrV4> {
    // value[0] is reserved, value[1] is family
    if value[1] != FAMILY_IPV4 || value.len() < 8 {
        return None;
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    let ip_bytes = [
        value[4] ^ (MAGIC_COOKIE >> 24) as u8,
        value[5] ^ (MAGIC_COOKIE >> 16) as u8,
        value[6] ^ (MAGIC_COOKIE >> 8) as u8,
        value[7] ^ MAGIC_COOKIE as u8,
    ];
    let ip = std::net::Ipv4Addr::from(ip_bytes);
    Some(SocketAddrV4::new(ip, port))
}

/// Parses a `MAPPED-ADDRESS` attribute value (IPv4 only, legacy fallback).
fn parse_mapped_address(value: &[u8]) -> Option<SocketAddrV4> {
    if value[1] != FAMILY_IPV4 || value.len() < 8 {
        return None;
    }
    let port = u16::from_be_bytes([value[2], value[3]]);
    let ip = std::net::Ipv4Addr::new(value[4], value[5], value[6], value[7]);
    Some(SocketAddrV4::new(ip, port))
}

/// Discovers the public address of a bound UDP socket using STUN.
///
/// Sends STUN Binding Requests to public Google STUN servers and returns the
/// first successful `XOR-MAPPED-ADDRESS` (or `MAPPED-ADDRESS` as fallback).
///
/// The socket must already be bound. Its local address determines which NAT
/// mapping is discovered — reuse this socket for subsequent QUIC connections
/// to preserve the mapping.
///
/// # Errors
///
/// Returns [`StunError::NoResponse`] if no STUN server responds, or
/// [`StunError::Io`] on network errors.
///
pub fn stun_discover(socket: &UdpSocket) -> Result<SocketAddr, StunError> {
    stun_discover_from(socket, STUN_SERVERS)
}

/// Like [`stun_discover`] but accepts a custom list of STUN server addresses.
///
/// Used internally so tests can point at a local fake STUN server.
///
/// # Errors
///
/// Returns [`StunError::NoResponse`] if no server responds.
pub(crate) fn stun_discover_from(
    socket: &UdpSocket,
    servers: &[&str],
) -> Result<SocketAddr, StunError> {
    let txn_id = random_txn_id();
    let request = build_binding_request(&txn_id);

    // Set a per-attempt timeout
    socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    for server in servers {
        let Some(addr) = server.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
            continue;
        };

        if socket.send_to(&request, addr).is_err() {
            continue;
        }

        let mut buf = [0u8; 512];
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => match parse_binding_response(&buf[..n], &txn_id) {
                Ok(mapped) => return Ok(SocketAddr::V4(mapped)),
                Err(_) => continue,
            },
            Err(_) => continue,
        }
    }

    Err(StunError::NoResponse)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn build_request_structure() {
        let txn_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let req = build_binding_request(&txn_id);

        // Message type: Binding Request
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), BINDING_REQUEST);
        // Message length: 0
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        // Magic cookie
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            MAGIC_COOKIE
        );
        // Transaction ID
        assert_eq!(&req[8..20], &txn_id);
    }

    #[test]
    fn parse_xor_mapped_address_ipv4() {
        // Construct a response with XOR-MAPPED-ADDRESS
        // Public IP: 198.51.100.1, Port: 12345
        let ip = std::net::Ipv4Addr::new(198, 51, 100, 1);
        let port: u16 = 12345;

        // XOR with magic cookie
        let xor_port = port ^ (MAGIC_COOKIE >> 16) as u16;
        let ip_octets = ip.octets();
        let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
        let xor_ip = [
            ip_octets[0] ^ cookie_bytes[0],
            ip_octets[1] ^ cookie_bytes[1],
            ip_octets[2] ^ cookie_bytes[2],
            ip_octets[3] ^ cookie_bytes[3],
        ];

        let txn_id = [0u8; 12];
        let mut response = Vec::new();
        // Header
        response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&12u16.to_be_bytes()); // msg length (1 attr: 4 header + 8 value)
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&txn_id);
        // XOR-MAPPED-ADDRESS attribute
        response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes()); // attr length
        response.push(0x00); // reserved
        response.push(FAMILY_IPV4);
        response.extend_from_slice(&xor_port.to_be_bytes());
        response.extend_from_slice(&xor_ip);

        let result = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(*result.ip(), ip);
        assert_eq!(result.port(), port);
    }

    #[test]
    fn parse_mapped_address_fallback() {
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let port: u16 = 54321;
        let txn_id = [7u8; 12];

        let mut response = Vec::new();
        // Header
        response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&12u16.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&txn_id);
        // MAPPED-ADDRESS attribute (legacy)
        response.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());
        response.push(0x00); // reserved
        response.push(FAMILY_IPV4);
        response.extend_from_slice(&port.to_be_bytes());
        response.extend_from_slice(&ip.octets());

        let result = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(*result.ip(), ip);
        assert_eq!(result.port(), port);
    }

    #[test]
    fn parse_response_too_short() {
        let txn = [0u8; 12];
        let result = parse_binding_response(&[0u8; 10], &txn);
        assert!(result.is_err());
    }

    #[test]
    fn parse_response_wrong_type() {
        let txn = [0u8; 12];
        let mut buf = [0u8; 20];
        // Wrong message type (Binding Request instead of Response)
        buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
        buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&txn);
        let result = parse_binding_response(&buf, &txn);
        assert!(result.is_err());
    }

    #[test]
    fn parse_response_wrong_cookie() {
        let txn = [0u8; 12];
        let mut buf = [0u8; 20];
        buf[0..2].copy_from_slice(&BINDING_RESPONSE.to_be_bytes());
        buf[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        buf[8..20].copy_from_slice(&txn);
        let result = parse_binding_response(&buf, &txn);
        assert!(result.is_err());
    }

    #[test]
    fn parse_response_wrong_txn_id() {
        let txn = [1u8; 12];
        let wrong_txn = [2u8; 12];
        let mut buf = [0u8; 20];
        buf[0..2].copy_from_slice(&BINDING_RESPONSE.to_be_bytes());
        buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&wrong_txn);
        let result = parse_binding_response(&buf, &txn);
        assert!(result.is_err());
    }

    #[test]
    fn parse_response_no_mapped_address() {
        let txn = [0u8; 12];
        let mut response = Vec::new();
        response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes()); // no attributes
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&txn);
        let result = parse_binding_response(&response, &txn);
        assert!(result.is_err());
    }

    #[test]
    fn parse_xor_mapped_ignores_ipv6() {
        // IPv6 family (0x02) should be skipped
        let value = [
            0x00, 0x02, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(parse_xor_mapped_address(&value).is_none());
    }

    #[test]
    fn parse_mapped_ignores_ipv6() {
        let value = [
            0x00, 0x02, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(parse_mapped_address(&value).is_none());
    }

    #[test]
    fn xor_mapped_prefers_over_mapped() {
        // Response with both MAPPED-ADDRESS and XOR-MAPPED-ADDRESS
        // XOR-MAPPED-ADDRESS should be preferred
        let txn_id = [0u8; 12];
        let mapped_ip = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let mapped_port: u16 = 1111;
        let xor_ip = std::net::Ipv4Addr::new(203, 0, 113, 5);
        let xor_port: u16 = 2222;

        let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
        let xor_port_encoded = xor_port ^ (MAGIC_COOKIE >> 16) as u16;
        let xor_ip_octets = xor_ip.octets();
        let xor_ip_encoded = [
            xor_ip_octets[0] ^ cookie_bytes[0],
            xor_ip_octets[1] ^ cookie_bytes[1],
            xor_ip_octets[2] ^ cookie_bytes[2],
            xor_ip_octets[3] ^ cookie_bytes[3],
        ];

        let mut response = Vec::new();
        // Header
        response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&24u16.to_be_bytes()); // 2 attrs * 12 bytes each
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&txn_id);
        // MAPPED-ADDRESS first (should be deprioritized)
        response.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());
        response.push(0x00);
        response.push(FAMILY_IPV4);
        response.extend_from_slice(&mapped_port.to_be_bytes());
        response.extend_from_slice(&mapped_ip.octets());
        // XOR-MAPPED-ADDRESS second (should be preferred)
        response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());
        response.push(0x00);
        response.push(FAMILY_IPV4);
        response.extend_from_slice(&xor_port_encoded.to_be_bytes());
        response.extend_from_slice(&xor_ip_encoded);

        let result = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(*result.ip(), xor_ip);
        assert_eq!(result.port(), xor_port);
    }

    #[test]
    fn random_txn_id_not_all_zeros() {
        let txn = random_txn_id();
        // Extremely unlikely to be all zeros
        assert_ne!(txn, [0u8; 12]);
    }

    #[test]
    fn parse_truncated_attribute() {
        let txn = [0u8; 12];
        let mut response = Vec::new();
        response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        // Claim 100 bytes of attributes but only provide 4
        response.extend_from_slice(&100u16.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&txn);
        // Partial attribute header (only 4 bytes, says length 50)
        response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&50u16.to_be_bytes());

        let result = parse_binding_response(&response, &txn);
        assert!(result.is_err());
    }

    #[test]
    fn parse_xor_mapped_short_value() {
        // Value too short (only 4 bytes, need 8)
        let value = [0x00, FAMILY_IPV4, 0x00, 0x00];
        assert!(parse_xor_mapped_address(&value).is_none());
    }

    #[test]
    fn parse_mapped_short_value() {
        let value = [0x00, FAMILY_IPV4, 0x00, 0x00];
        assert!(parse_mapped_address(&value).is_none());
    }

    /// Spawns a local UDP server that responds with a crafted STUN Binding
    /// Response, then calls `stun_discover_from` against it.
    #[test]
    fn stun_discover_from_local_server() {
        let fake_server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = fake_server.local_addr().unwrap();
        let server_str = server_addr.to_string();

        // Spawn a thread that reads one request and sends a valid response
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (n, client_addr) = fake_server.recv_from(&mut buf).unwrap();
            assert_eq!(n, 20); // STUN Binding Request is 20 bytes

            // Extract transaction ID from request
            let txn_id: [u8; 12] = buf[8..20].try_into().unwrap();

            // Build a response with XOR-MAPPED-ADDRESS
            let mapped_ip = std::net::Ipv4Addr::new(203, 0, 113, 42);
            let mapped_port: u16 = 54321;

            let xor_port = mapped_port ^ (MAGIC_COOKIE >> 16) as u16;
            let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
            let ip_octets = mapped_ip.octets();
            let xor_ip = [
                ip_octets[0] ^ cookie_bytes[0],
                ip_octets[1] ^ cookie_bytes[1],
                ip_octets[2] ^ cookie_bytes[2],
                ip_octets[3] ^ cookie_bytes[3],
            ];

            let mut response = Vec::new();
            response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
            response.extend_from_slice(&12u16.to_be_bytes());
            response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            response.extend_from_slice(&txn_id);
            response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
            response.extend_from_slice(&8u16.to_be_bytes());
            response.push(0x00);
            response.push(FAMILY_IPV4);
            response.extend_from_slice(&xor_port.to_be_bytes());
            response.extend_from_slice(&xor_ip);

            fake_server.send_to(&response, client_addr).unwrap();
        });

        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let result = stun_discover_from(&client, &[&server_str]);
        handle.join().unwrap();

        let addr = result.unwrap();
        assert_eq!(addr, "203.0.113.42:54321".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn stun_discover_no_servers_respond() {
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // Point at a server that won't respond (bind but don't read)
        let dead_server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead_server.local_addr().unwrap().to_string();
        // Set a very short timeout so the test doesn't take 2s per server
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .unwrap();
        let result = stun_discover_from(&client, &[&dead_addr]);
        assert!(result.is_err());
    }

    #[test]
    fn stun_discover_invalid_server_name() {
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // DNS name that won't resolve
        let result = stun_discover_from(&client, &["this.host.definitely.does.not.exist:19302"]);
        assert!(result.is_err());
    }

    #[test]
    fn stun_discover_bad_response_tries_next() {
        // First server sends garbage, second sends valid response
        let bad_server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bad_addr = bad_server.local_addr().unwrap().to_string();
        let good_server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let good_addr = good_server.local_addr().unwrap().to_string();

        let handle = std::thread::spawn(move || {
            // Bad server: respond with garbage
            let mut buf = [0u8; 64];
            let (_, client_addr) = bad_server.recv_from(&mut buf).unwrap();
            bad_server
                .send_to(b"not a stun response", client_addr)
                .unwrap();

            // Good server: respond with valid STUN
            let (_, client_addr) = good_server.recv_from(&mut buf).unwrap();
            let txn_id: [u8; 12] = buf[8..20].try_into().unwrap();

            let mapped_port: u16 = 9999;
            let xor_port = mapped_port ^ (MAGIC_COOKIE >> 16) as u16;
            let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
            let xor_ip = [
                10 ^ cookie_bytes[0],
                cookie_bytes[1],
                cookie_bytes[2],
                1 ^ cookie_bytes[3],
            ];

            let mut response = Vec::new();
            response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
            response.extend_from_slice(&12u16.to_be_bytes());
            response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            response.extend_from_slice(&txn_id);
            response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
            response.extend_from_slice(&8u16.to_be_bytes());
            response.push(0x00);
            response.push(FAMILY_IPV4);
            response.extend_from_slice(&xor_port.to_be_bytes());
            response.extend_from_slice(&xor_ip);

            good_server.send_to(&response, client_addr).unwrap();
        });

        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let result = stun_discover_from(&client, &[&bad_addr, &good_addr]);
        handle.join().unwrap();

        let addr = result.unwrap();
        assert_eq!(addr, "10.0.0.1:9999".parse::<SocketAddr>().unwrap());
    }

    /// Tests the MAPPED-ADDRESS fallback when XOR-MAPPED-ADDRESS is absent.
    #[test]
    fn stun_discover_mapped_address_fallback() {
        let fake_server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = fake_server.local_addr().unwrap();
        let server_str = server_addr.to_string();

        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (_, client_addr) = fake_server.recv_from(&mut buf).unwrap();
            let txn_id: [u8; 12] = buf[8..20].try_into().unwrap();

            // Respond with MAPPED-ADDRESS only (no XOR)
            let mut response = Vec::new();
            response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
            response.extend_from_slice(&12u16.to_be_bytes());
            response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            response.extend_from_slice(&txn_id);
            response.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
            response.extend_from_slice(&8u16.to_be_bytes());
            response.push(0x00);
            response.push(FAMILY_IPV4);
            response.extend_from_slice(&8080u16.to_be_bytes());
            response.extend_from_slice(&[192, 168, 1, 100]);

            fake_server.send_to(&response, client_addr).unwrap();
        });

        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let result = stun_discover_from(&client, &[&server_str]);
        handle.join().unwrap();

        let addr = result.unwrap();
        assert_eq!(addr, "192.168.1.100:8080".parse::<SocketAddr>().unwrap());
    }
}
