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
    /// The underlying QUIC endpoint.
    pub endpoint: quinn::Endpoint,
    cert: CertKeyPair,
}

impl QuicServer {
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
    ///
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
///
fn send_punch_packets(endpoint: quinn::Endpoint, target: SocketAddr) {
    tokio::spawn(async move {
        let Ok(dummy_cert) = config::generate_self_signed_cert(&["punch".to_string()]) else {
            return;
        };
        let Ok(dummy_config) = config::build_tofu_client_config_with_cert(&dummy_cert) else {
            return;
        };
        if let Ok(connecting) = endpoint.connect_with(dummy_config, target, "punch") {
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

    /// Connects to a QUIC server using a pre-built client config.
    ///
    /// Used for TOFU first-connection where the caller builds a custom TLS
    /// config (e.g., accept-any-cert with client auth).
    ///
    /// # Errors
    ///
    /// Returns `TransportError::Connect` if the connection cannot be initiated, or
    /// `TransportError::Connection` if the handshake fails.
    pub async fn connect_with_config(
        &self,
        config: quinn::ClientConfig,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Connection, TransportError> {
        let conn = self
            .endpoint
            .connect_with(config, addr, server_name)?
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

    struct MtlsFixture {
        server: QuicServer,
        client_cert: CertKeyPair,
        _auth_dir: std::path::PathBuf,
    }

    impl MtlsFixture {
        fn new() -> Self {
            let server_cert =
                config::generate_self_signed_cert(&["localhost".to_string()]).unwrap();
            let client_cert =
                config::generate_self_signed_cert(&["localhost".to_string()]).unwrap();

            let auth_dir = std::env::temp_dir().join(format!(
                "rose-transport-test-{}",
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

        fn addr(&self) -> SocketAddr {
            self.server.local_addr().unwrap()
        }

        fn server_cert_der(&self) -> &CertificateDer<'static> {
            self.server.server_cert_der()
        }

        async fn connect(&self, client: &QuicClient) -> quinn::Connection {
            client
                .connect_with_cert(
                    self.addr(),
                    "localhost",
                    self.server_cert_der(),
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

    async fn connected_pair() -> (
        quinn::Connection,
        quinn::Connection,
        MtlsFixture,
        QuicClient,
    ) {
        let fixture = MtlsFixture::new();

        let accept = tokio::spawn({
            let endpoint = fixture.server.endpoint.clone();
            async move {
                let incoming = endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            }
        });

        let client = QuicClient::new().unwrap();
        let client_conn = fixture.connect(&client).await;
        let server_conn = accept.await.unwrap();

        (client_conn, server_conn, fixture, client)
    }

    #[tokio::test]
    async fn bind_and_accept() {
        let (client_conn, _server_conn, fixture, _client) = connected_pair().await;
        assert_eq!(client_conn.remote_address(), fixture.addr());
    }

    #[tokio::test]
    async fn datagram_roundtrip() {
        let (client_conn, server_conn, _fixture, _client) = connected_pair().await;

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
        let (client_conn, server_conn, _fixture, _client) = connected_pair().await;

        let server_task = tokio::spawn(async move {
            let (mut send, mut recv) = server_conn.accept_bi().await.unwrap();
            let data = recv.read_to_end(1024).await.unwrap();
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
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
        let fixture = MtlsFixture::new();

        let accept = tokio::spawn({
            let endpoint = fixture.server.endpoint.clone();
            async move {
                let incoming = endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            }
        });

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = QuicClient::from_socket(socket).unwrap();
        let client_conn = fixture.connect(&client).await;
        let _server_conn = accept.await.unwrap();

        assert_eq!(client_conn.remote_address(), fixture.addr());
    }

    #[tokio::test]
    async fn punch_handle_creation() {
        let fixture = MtlsFixture::new();
        let handle = fixture.server.clone_for_punch();
        drop(handle);
    }

    #[tokio::test]
    async fn server_cert_pem_is_valid() {
        let fixture = MtlsFixture::new();
        let pem = fixture.server.server_cert_pem();
        assert!(pem.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn accept_returns_none_on_close() {
        let fixture = MtlsFixture::new();
        fixture.server.endpoint.close(0u32.into(), b"done");
        let result = fixture.server.accept().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn punch_hole_sends_packets() {
        let fixture = MtlsFixture::new();
        fixture.server.punch_hole("127.0.0.1:1".parse().unwrap());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn punch_handle_sends_packets() {
        let fixture = MtlsFixture::new();
        let handle = fixture.server.clone_for_punch();
        handle.punch_hole("127.0.0.1:1".parse().unwrap());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn connect_with_cert_rejects_wrong_pinned_cert() {
        let fixture = MtlsFixture::new();
        let client = QuicClient::new().unwrap();

        let accept = tokio::spawn({
            let endpoint = fixture.server.endpoint.clone();
            async move {
                let incoming = endpoint.accept().await.unwrap();
                incoming.await
            }
        });

        let wrong_cert = config::generate_self_signed_cert(&["localhost".to_string()]).unwrap();
        let result = client
            .connect_with_cert(
                fixture.addr(),
                "localhost",
                &wrong_cert.cert_der,
                &fixture.client_cert,
            )
            .await;
        assert!(result.is_err());
        drop(accept);
    }

    #[tokio::test]
    async fn connect_with_config_succeeds() {
        let fixture = MtlsFixture::new();
        let client = QuicClient::new().unwrap();

        let accept = tokio::spawn({
            let endpoint = fixture.server.endpoint.clone();
            async move {
                let incoming = endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            }
        });

        let config =
            config::build_client_config_with_cert(fixture.server_cert_der(), &fixture.client_cert)
                .unwrap();
        let client_conn = client
            .connect_with_config(config, fixture.addr(), "localhost")
            .await
            .unwrap();
        let _server_conn = accept.await.unwrap();

        assert_eq!(client_conn.remote_address(), fixture.addr());
    }
}
