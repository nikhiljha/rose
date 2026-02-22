//! Wire protocol for `RoSE` sessions.
//!
//! For the MVP, uses a simple length-prefixed control channel on a QUIC
//! bi-directional stream, and raw datagrams for terminal I/O.
//!
//! Control messages (Hello, Resize, Goodbye) are serialized as:
//! `[type: u8][payload...]` on the bi-stream, length-framed with a u32 prefix.
//!
//! Terminal data flows as raw QUIC datagrams — no framing beyond what QUIC provides.

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};

/// Errors that can occur in the protocol layer.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// I/O error on a QUIC stream.
    #[error("stream I/O error: {0}")]
    StreamWrite(#[from] quinn::WriteError),
    /// Error reading from a QUIC stream.
    #[error("stream read error: {0}")]
    StreamRead(#[from] quinn::ReadExactError),
    /// Connection-level error.
    #[error("connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// Invalid or unexpected message.
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    /// Datagram send error.
    #[error("datagram send error: {0}")]
    DatagramSend(#[from] quinn::SendDatagramError),
}

/// Control messages exchanged over the reliable bi-stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// Initial handshake from client to server.
    Hello {
        /// Terminal rows.
        rows: u16,
        /// Terminal columns.
        cols: u16,
    },
    /// Terminal resize notification.
    Resize {
        /// New terminal rows.
        rows: u16,
        /// New terminal columns.
        cols: u16,
    },
    /// Graceful disconnect.
    Goodbye,
}

// Wire format constants
const MSG_HELLO: u8 = 1;
const MSG_RESIZE: u8 = 2;
const MSG_GOODBYE: u8 = 3;

impl ControlMessage {
    /// Serializes this message to bytes (type byte + payload).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Hello { rows, cols } => {
                let mut buf = Vec::with_capacity(5);
                buf.push(MSG_HELLO);
                buf.extend_from_slice(&rows.to_be_bytes());
                buf.extend_from_slice(&cols.to_be_bytes());
                buf
            }
            Self::Resize { rows, cols } => {
                let mut buf = Vec::with_capacity(5);
                buf.push(MSG_RESIZE);
                buf.extend_from_slice(&rows.to_be_bytes());
                buf.extend_from_slice(&cols.to_be_bytes());
                buf
            }
            Self::Goodbye => vec![MSG_GOODBYE],
        }
    }

    /// Deserializes a message from bytes.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::InvalidMessage` if the bytes are malformed.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let (&msg_type, payload) = data
            .split_first()
            .ok_or_else(|| ProtocolError::InvalidMessage("empty message".to_string()))?;

        match msg_type {
            MSG_HELLO => {
                if payload.len() < 4 {
                    return Err(ProtocolError::InvalidMessage("Hello too short".to_string()));
                }
                let rows = u16::from_be_bytes([payload[0], payload[1]]);
                let cols = u16::from_be_bytes([payload[2], payload[3]]);
                Ok(Self::Hello { rows, cols })
            }
            MSG_RESIZE => {
                if payload.len() < 4 {
                    return Err(ProtocolError::InvalidMessage(
                        "Resize too short".to_string(),
                    ));
                }
                let rows = u16::from_be_bytes([payload[0], payload[1]]);
                let cols = u16::from_be_bytes([payload[2], payload[3]]);
                Ok(Self::Resize { rows, cols })
            }
            MSG_GOODBYE => Ok(Self::Goodbye),
            other => Err(ProtocolError::InvalidMessage(format!(
                "unknown message type: {other}"
            ))),
        }
    }
}

/// Writes a length-prefixed control message to a QUIC send stream.
///
/// Format: `[u32 big-endian length][message bytes]`
///
/// # Errors
///
/// Returns `ProtocolError::StreamWrite` if the write fails.
pub async fn write_control(
    send: &mut SendStream,
    msg: &ControlMessage,
) -> Result<(), ProtocolError> {
    let encoded = msg.encode();
    // Control messages are at most 5 bytes, always fits in u32.
    let len = encoded.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&encoded).await?;
    Ok(())
}

/// Reads a length-prefixed control message from a QUIC receive stream.
///
/// Returns `None` if the stream is finished (clean EOF).
///
/// # Errors
///
/// Returns `ProtocolError` if reading or decoding fails.
pub async fn read_control(recv: &mut RecvStream) -> Result<Option<ControlMessage>, ProtocolError> {
    let mut len_buf = [0u8; 4];
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 65536 {
        return Err(ProtocolError::InvalidMessage(format!(
            "message too large: {len}"
        )));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    ControlMessage::decode(&buf).map(Some)
}

/// Server-side protocol handler for a single client session.
pub struct ServerSession {
    conn: Connection,
    control_send: SendStream,
    control_recv: RecvStream,
}

impl ServerSession {
    /// Accepts a new client session: waits for the client to open a bi-stream
    /// and send a Hello message.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if the handshake fails.
    pub async fn accept(conn: Connection) -> Result<(Self, u16, u16), ProtocolError> {
        let (control_send, mut control_recv) = conn.accept_bi().await?;
        let hello = read_control(&mut control_recv)
            .await?
            .ok_or_else(|| ProtocolError::InvalidMessage("stream closed before Hello".into()))?;

        let ControlMessage::Hello { rows, cols } = hello else {
            return Err(ProtocolError::InvalidMessage(format!(
                "expected Hello, got {hello:?}"
            )));
        };

        Ok((
            Self {
                conn,
                control_send,
                control_recv,
            },
            rows,
            cols,
        ))
    }

    /// Sends a control message to the client (e.g., for server-initiated events).
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::StreamWrite` if the write fails.
    pub async fn send_control(&mut self, msg: &ControlMessage) -> Result<(), ProtocolError> {
        write_control(&mut self.control_send, msg).await
    }

    /// Reads the next control message from the client.
    ///
    /// Returns `None` on clean stream close.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if reading or decoding fails.
    pub async fn recv_control(&mut self) -> Result<Option<ControlMessage>, ProtocolError> {
        read_control(&mut self.control_recv).await
    }

    /// Sends terminal output to the client as a QUIC datagram.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::DatagramSend` if the send fails.
    pub fn send_output(&self, data: Bytes) -> Result<(), ProtocolError> {
        self.conn.send_datagram(data)?;
        Ok(())
    }

    /// Receives terminal input from the client as a QUIC datagram.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::Connection` if the connection is lost.
    pub async fn recv_input(&self) -> Result<Bytes, ProtocolError> {
        Ok(self.conn.read_datagram().await?)
    }

    /// Returns a reference to the underlying connection.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }
}

/// Client-side protocol handler for a session.
pub struct ClientSession {
    conn: Connection,
    control_send: SendStream,
    control_recv: RecvStream,
}

impl ClientSession {
    /// Initiates a client session: opens a bi-stream and sends a Hello.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if the handshake fails.
    pub async fn connect(conn: Connection, rows: u16, cols: u16) -> Result<Self, ProtocolError> {
        let (mut control_send, control_recv) = conn.open_bi().await?;
        write_control(&mut control_send, &ControlMessage::Hello { rows, cols }).await?;

        Ok(Self {
            conn,
            control_send,
            control_recv,
        })
    }

    /// Sends a control message (e.g., Resize, Goodbye) to the server.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::StreamWrite` if the write fails.
    pub async fn send_control(&mut self, msg: &ControlMessage) -> Result<(), ProtocolError> {
        write_control(&mut self.control_send, msg).await
    }

    /// Sends terminal input to the server as a QUIC datagram.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::DatagramSend` if the send fails.
    pub fn send_input(&self, data: Bytes) -> Result<(), ProtocolError> {
        self.conn.send_datagram(data)?;
        Ok(())
    }

    /// Receives terminal output from the server as a QUIC datagram.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::Connection` if the connection is lost.
    pub async fn recv_output(&self) -> Result<Bytes, ProtocolError> {
        Ok(self.conn.read_datagram().await?)
    }

    /// Reads the next control message from the server.
    ///
    /// Returns `None` on clean stream close.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if reading or decoding fails.
    pub async fn recv_control(&mut self) -> Result<Option<ControlMessage>, ProtocolError> {
        read_control(&mut self.control_recv).await
    }

    /// Returns a reference to the underlying connection.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::transport::{QuicClient, QuicServer};

    #[test]
    fn encode_decode_hello() {
        let msg = ControlMessage::Hello { rows: 24, cols: 80 };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn encode_decode_resize() {
        let msg = ControlMessage::Resize {
            rows: 40,
            cols: 120,
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn encode_decode_goodbye() {
        let msg = ControlMessage::Goodbye;
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_empty_is_error() {
        assert!(ControlMessage::decode(&[]).is_err());
    }

    #[test]
    fn decode_unknown_type_is_error() {
        assert!(ControlMessage::decode(&[255]).is_err());
    }

    #[test]
    fn decode_truncated_hello_is_error() {
        assert!(ControlMessage::decode(&[MSG_HELLO, 0, 24]).is_err());
    }

    /// Helper: create connected QUIC pair for protocol tests.
    async fn quic_pair() -> (Connection, Connection, QuicServer, QuicClient) {
        let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let cert = server.server_cert_der().clone();
        let client = QuicClient::new().unwrap();

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
    async fn handshake() {
        let (client_conn, server_conn, _s, _c) = quic_pair().await;

        let server_task = tokio::spawn(async move { ServerSession::accept(server_conn).await });

        let _client_session = ClientSession::connect(client_conn, 24, 80).await.unwrap();
        let (server_session, rows, cols) = server_task.await.unwrap().unwrap();
        assert_eq!(rows, 24);
        assert_eq!(cols, 80);

        // Keep sessions alive for clean shutdown
        drop(server_session);
    }

    #[tokio::test]
    async fn datagram_io() {
        let (client_conn, server_conn, _s, _c) = quic_pair().await;

        let server_task =
            tokio::spawn(async move { ServerSession::accept(server_conn).await.unwrap() });

        let client_session = ClientSession::connect(client_conn, 24, 80).await.unwrap();
        let (server_session, _, _) = server_task.await.unwrap();

        // Client sends input, server receives
        client_session
            .send_input(Bytes::from_static(b"keystrokes"))
            .unwrap();
        let received = server_session.recv_input().await.unwrap();
        assert_eq!(&received[..], b"keystrokes");

        // Server sends output, client receives
        server_session
            .send_output(Bytes::from_static(b"terminal output"))
            .unwrap();
        let received = client_session.recv_output().await.unwrap();
        assert_eq!(&received[..], b"terminal output");
    }

    #[tokio::test]
    async fn resize_control_message() {
        let (client_conn, server_conn, _s, _c) = quic_pair().await;

        let server_task =
            tokio::spawn(async move { ServerSession::accept(server_conn).await.unwrap() });

        let mut client_session = ClientSession::connect(client_conn, 24, 80).await.unwrap();
        let (mut server_session, _, _) = server_task.await.unwrap();

        // Client sends resize
        client_session
            .send_control(&ControlMessage::Resize {
                rows: 40,
                cols: 120,
            })
            .await
            .unwrap();

        let msg = server_session.recv_control().await.unwrap().unwrap();
        assert_eq!(
            msg,
            ControlMessage::Resize {
                rows: 40,
                cols: 120
            }
        );
    }
}
