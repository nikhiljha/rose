//! QUIC transport layer using quinn.
//!
//! Uses QUIC datagrams (RFC 9221) for interactive terminal data (unreliable,
//! most-recent-state-wins) and QUIC streams for reliable data (control channel,
//! scrollback sync).

use std::net::SocketAddr;

use std::path::Path;

use crate::config::{self, CertKeyPair, ConfigError};
use rustls::pki_types::CertificateDer;

/// Errors that can occur in the transport layer.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Failed to bind the QUIC endpoint.
    #[error("failed to bind endpoint: {0}")]
    Bind(#[source] std::io::Error),
    /// Failed to connect to a remote endpoint.
    #[error("connection failed: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// Connection-level error.
    #[error("connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// Certificate or TLS configuration error.
    #[error("TLS/cert error: {0}")]
    Config(#[from] ConfigError),
}

/// A QUIC server endpoint that accepts incoming connections.
pub struct QuicServer {
    pub(crate) endpoint: quinn::Endpoint,
    cert: CertKeyPair,
}

impl QuicServer {
    /// Binds a QUIC server on `addr` with an auto-generated self-signed certificate.
    ///
    /// # Errors
    ///
    /// Returns `TransportError::Config` if cert generation fails, or
    /// `TransportError::Bind` if the socket cannot be bound.
    pub fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        let san = vec!["localhost".to_string()];
        let cert = config::generate_self_signed_cert(&san)?;
        Self::bind_with_cert(addr, cert)
    }

    /// Binds a QUIC server on `addr` with a pre-existing certificate.
    ///
    /// # Errors
    ///
    /// Returns `TransportError::Config` if the TLS config is invalid, or
    /// `TransportError::Bind` if the socket cannot be bound.
    pub fn bind_with_cert(addr: SocketAddr, cert: CertKeyPair) -> Result<Self, TransportError> {
        let server_config = config::build_server_config(&cert)?;
        let endpoint =
            quinn::Endpoint::server(server_config, addr).map_err(TransportError::Bind)?;
        Ok(Self { endpoint, cert })
    }

    /// Binds a QUIC server requiring mutual TLS client authentication.
    ///
    /// # Errors
    ///
    /// Returns `TransportError::Config` if the TLS config is invalid, or
    /// `TransportError::Bind` if the socket cannot be bound.
    pub fn bind_mutual_tls(
        addr: SocketAddr,
        cert: CertKeyPair,
        authorized_certs_dir: &Path,
    ) -> Result<Self, TransportError> {
        let server_config = config::build_mutual_tls_server_config(&cert, authorized_certs_dir)?;
        let endpoint =
            quinn::Endpoint::server(server_config, addr).map_err(TransportError::Bind)?;
        Ok(Self { endpoint, cert })
    }

    /// Accepts the next incoming QUIC connection.
    ///
    /// Returns `None` if the endpoint has been closed.
    ///
    /// # Errors
    ///
    /// Returns `TransportError::Connection` if the handshake fails.
    pub async fn accept(&self) -> Result<Option<quinn::Connection>, TransportError> {
        let Some(incoming) = self.endpoint.accept().await else {
            return Ok(None);
        };
        let conn = incoming.await?;
        Ok(Some(conn))
    }

    /// Returns the local address this server is bound to.
    ///
    /// # Errors
    ///
    /// Returns `TransportError::Bind` if the address cannot be determined.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(TransportError::Bind)
    }

    /// Returns the DER-encoded server certificate for sharing with clients.
    #[must_use]
    pub const fn server_cert_der(&self) -> &CertificateDer<'static> {
        &self.cert.cert_der
    }

    /// Returns the PEM-encoded server certificate.
    #[must_use]
    pub fn server_cert_pem(&self) -> &str {
        &self.cert.cert_pem
    }

    /// Returns a lightweight handle that can only punch holes, not accept connections.
    ///
    /// Used to pass hole-punching capability into a background task without
    /// moving the entire server.
    #[must_use]
    pub fn clone_for_punch(&self) -> PunchHandle {
        PunchHandle {
            endpoint: self.endpoint.clone(),
        }
    }

    /// Sends QUIC Initial packets to `target` to open a firewall pinhole.
    ///
    /// The connection attempt is expected to fail — only the UDP packets
    /// matter. They create a stateful firewall entry that allows return
    /// traffic from `target` to reach this server's port.
    pub fn punch_hole(&self, target: SocketAddr) {
        send_punch_packets(self.endpoint.clone(), target);
    }
}

/// A lightweight handle for sending hole-punch packets from a server endpoint.
///
/// Created via [`QuicServer::clone_for_punch`]. Can be sent to background
/// tasks without moving the entire server.
pub struct PunchHandle {
    endpoint: quinn::Endpoint,
}

impl PunchHandle {
    /// Sends QUIC Initial packets to `target` to open a firewall pinhole.
    ///
    /// See [`QuicServer::punch_hole`] for details.
    pub fn punch_hole(&self, target: SocketAddr) {
        send_punch_packets(self.endpoint.clone(), target);
    }
}

/// Spawns a task that sends QUIC Initial packets to `target` from `endpoint`.
///
/// Uses a TOFU (accept-any-cert) client config since we don't care about the
/// TLS handshake completing — only the UDP packets matter for creating the
/// firewall pinhole. The connection attempt will fail, which is expected.
fn send_punch_packets(endpoint: quinn::Endpoint, target: SocketAddr) {
    tokio::spawn(async move {
        let Ok(dummy_config) = config::build_tofu_client_config() else {
            return;
        };
        if let Ok(connecting) = endpoint.connect_with(dummy_config, target, "punch") {
            // Drive the handshake briefly so Initial packets are sent.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), connecting).await;
        }
    });
}

/// A QUIC client that connects to a server.
pub struct QuicClient {
    endpoint: quinn::Endpoint,
}

impl QuicClient {
    /// Creates a new QUIC client endpoint bound to an OS-assigned port.
    ///
    /// # Errors
    ///
    /// Returns `TransportError::Bind` if the socket cannot be bound.
    pub fn new() -> Result<Self, TransportError> {
        let addr = SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0));
        let endpoint = quinn::Endpoint::client(addr).map_err(TransportError::Bind)?;
        Ok(Self { endpoint })
    }

    /// Creates a QUIC client from an existing UDP socket.
    ///
    /// Used for STUN hole-punching where the socket must preserve its NAT
    /// mapping. The socket is set to non-blocking mode automatically.
    ///
    /// # Errors
    ///
    /// Returns `TransportError::Bind` if the endpoint cannot be created.
    pub fn from_socket(socket: std::net::UdpSocket) -> Result<Self, TransportError> {
        socket.set_nonblocking(true).map_err(TransportError::Bind)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            std::sync::Arc::new(quinn::TokioRuntime),
        )
        .map_err(TransportError::Bind)?;
        Ok(Self { endpoint })
    }

    /// Connects to a QUIC server at `addr`, trusting the given server certificate.
    ///
    /// # Errors
    ///
    /// Returns `TransportError::Config` if the TLS config is invalid,
    /// `TransportError::Connect` if the connection cannot be initiated, or
    /// `TransportError::Connection` if the handshake fails.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
        server_cert_der: &CertificateDer<'static>,
    ) -> Result<quinn::Connection, TransportError> {
        let client_config = config::build_client_config(server_cert_der)?;
        let conn = self
            .endpoint
            .connect_with(client_config, addr, server_name)?
            .await?;
        Ok(conn)
    }
    /// Connects to a QUIC server presenting a client certificate for mutual TLS.
    ///
    /// # Errors
    ///
    /// Returns `TransportError::Config` if the TLS config is invalid,
    /// `TransportError::Connect` if the connection cannot be initiated, or
    /// `TransportError::Connection` if the handshake fails.
    pub async fn connect_with_cert(
        &self,
        addr: SocketAddr,
        server_name: &str,
        server_cert_der: &CertificateDer<'static>,
        client_cert: &CertKeyPair,
    ) -> Result<quinn::Connection, TransportError> {
        let client_config = config::build_client_config_with_cert(server_cert_der, client_cert)?;
        let conn = self
            .endpoint
            .connect_with(client_config, addr, server_name)?
            .await?;
        Ok(conn)
    }
}

impl Drop for QuicServer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"server shutdown");
    }
}

impl Drop for QuicClient {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"client shutdown");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use bytes::Bytes;

    /// Helper: create a server + client pair connected on localhost.
    async fn connected_pair() -> (quinn::Connection, quinn::Connection, QuicServer, QuicClient) {
        let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let cert = server.server_cert_der().clone();
        let client = QuicClient::new().unwrap();

        // Accept in a task so connect + accept run concurrently
        let accept = tokio::spawn({
            let endpoint = server.endpoint.clone();
            async move {
                let incoming = endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            }
        });

        let client_conn = client.connect(addr, "localhost", &cert).await.unwrap();
        let server_conn = accept.await.unwrap();

        (client_conn, server_conn, server, client)
    }

    #[tokio::test]
    async fn bind_and_accept() {
        let (client_conn, _server_conn, server, _client) = connected_pair().await;
        let addr = server.local_addr().unwrap();
        assert_eq!(client_conn.remote_address(), addr);
    }

    #[tokio::test]
    async fn datagram_roundtrip() {
        let (client_conn, server_conn, _server, _client) = connected_pair().await;

        client_conn
            .send_datagram(Bytes::from_static(b"hello datagram"))
            .unwrap();

        let received = server_conn.read_datagram().await.unwrap();
        assert_eq!(&received[..], b"hello datagram");

        server_conn.send_datagram(received).unwrap();
        let echoed = client_conn.read_datagram().await.unwrap();
        assert_eq!(&echoed[..], b"hello datagram");
    }

    #[tokio::test]
    async fn bidirectional_stream() {
        let (client_conn, server_conn, _server, _client) = connected_pair().await;

        // Server echoes back data it receives on a bi-stream, keeping the
        // connection alive until the client is done reading.
        let server_task = tokio::spawn(async move {
            let (mut send, mut recv) = server_conn.accept_bi().await.unwrap();
            let data = recv.read_to_end(1024).await.unwrap();
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
            // Hold the connection open until client has read the response.
            // The connection is kept alive as long as this value exists.
            server_conn
        });

        let (mut send, mut recv) = client_conn.open_bi().await.unwrap();
        send.write_all(b"stream data").await.unwrap();
        send.finish().unwrap();

        let response = recv.read_to_end(1024).await.unwrap();
        assert_eq!(&response[..], b"stream data");

        drop(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn from_socket_connects() {
        let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let cert = server.server_cert_der().clone();

        let accept = tokio::spawn({
            let endpoint = server.endpoint.clone();
            async move {
                let incoming = endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            }
        });

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = QuicClient::from_socket(socket).unwrap();
        let client_conn = client.connect(addr, "localhost", &cert).await.unwrap();
        let _server_conn = accept.await.unwrap();

        assert_eq!(client_conn.remote_address(), addr);
    }

    #[tokio::test]
    async fn punch_handle_creation() {
        let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let handle = server.clone_for_punch();
        // Just verify it can be created without panicking.
        // Actual hole-punching is tested via e2e tests.
        drop(handle);
    }
}
