//! QUIC transport layer using quinn.
//!
//! Uses QUIC datagrams (RFC 9221) for interactive terminal data (unreliable,
//! most-recent-state-wins) and QUIC streams for reliable data (control channel,
//! scrollback sync).

use std::net::SocketAddr;

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
}
