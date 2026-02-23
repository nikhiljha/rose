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

/// Current protocol version. Incremented when the wire format changes
/// in an incompatible way.
pub const PROTOCOL_VERSION: u16 = 1;

/// Control messages exchanged over the reliable bi-stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// Initial handshake from client to server.
    Hello {
        /// Protocol version.
        version: u16,
        /// Terminal rows.
        rows: u16,
        /// Terminal columns.
        cols: u16,
        /// Environment variables to forward (e.g. TERM, LANG, LC_*).
        env_vars: Vec<(String, String)>,
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
    /// Reconnect to an existing session (client → server).
    Reconnect {
        /// Protocol version.
        version: u16,
        /// Terminal rows.
        rows: u16,
        /// Terminal columns.
        cols: u16,
        /// Session identifier from a previous `SessionInfo`.
        session_id: [u8; 16],
        /// Environment variables to forward (e.g. TERM, LANG, LC_*).
        env_vars: Vec<(String, String)>,
    },
    /// Session metadata sent by the server after accepting a connection.
    SessionInfo {
        /// Protocol version.
        version: u16,
        /// Unique session identifier.
        session_id: [u8; 16],
    },
}

// Wire format constants
const MSG_HELLO: u8 = 1;
const MSG_RESIZE: u8 = 2;
const MSG_GOODBYE: u8 = 3;
const MSG_RECONNECT: u8 = 4;
const MSG_SESSION_INFO: u8 = 5;

/// Encodes a list of key-value pairs as `[num: u16][key_len: u16][key][val_len: u16][val]...`.
fn encode_env_vars(vars: &[(String, String)], buf: &mut Vec<u8>) {
    buf.extend_from_slice(&(vars.len() as u16).to_be_bytes());
    for (key, val) in vars {
        buf.extend_from_slice(&(key.len() as u16).to_be_bytes());
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(&(val.len() as u16).to_be_bytes());
        buf.extend_from_slice(val.as_bytes());
    }
}

/// Decodes a list of key-value pairs from a byte slice starting at `offset`.
fn decode_env_vars(payload: &[u8], offset: usize) -> Result<Vec<(String, String)>, ProtocolError> {
    if offset + 2 > payload.len() {
        // No env section present — treat as empty (forward compatibility).
        return Ok(vec![]);
    }
    let num = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
    let mut pos = offset + 2;
    let mut vars = Vec::with_capacity(num);
    for _ in 0..num {
        if pos + 2 > payload.len() {
            return Err(ProtocolError::InvalidMessage(
                "truncated env var key length".into(),
            ));
        }
        let key_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        if pos + key_len > payload.len() {
            return Err(ProtocolError::InvalidMessage(
                "truncated env var key".into(),
            ));
        }
        let key = String::from_utf8(payload[pos..pos + key_len].to_vec())
            .map_err(|e| ProtocolError::InvalidMessage(format!("invalid UTF-8 in env key: {e}")))?;
        pos += key_len;
        if pos + 2 > payload.len() {
            return Err(ProtocolError::InvalidMessage(
                "truncated env var value length".into(),
            ));
        }
        let val_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        if pos + val_len > payload.len() {
            return Err(ProtocolError::InvalidMessage(
                "truncated env var value".into(),
            ));
        }
        let val = String::from_utf8(payload[pos..pos + val_len].to_vec())
            .map_err(|e| ProtocolError::InvalidMessage(format!("invalid UTF-8 in env val: {e}")))?;
        pos += val_len;
        vars.push((key, val));
    }
    Ok(vars)
}

impl ControlMessage {
    /// Serializes this message to bytes (type byte + payload).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Hello {
                version,
                rows,
                cols,
                env_vars,
            } => {
                let mut buf = Vec::with_capacity(9);
                buf.push(MSG_HELLO);
                buf.extend_from_slice(&version.to_be_bytes());
                buf.extend_from_slice(&rows.to_be_bytes());
                buf.extend_from_slice(&cols.to_be_bytes());
                encode_env_vars(env_vars, &mut buf);
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
            Self::Reconnect {
                version,
                rows,
                cols,
                session_id,
                env_vars,
            } => {
                let mut buf = Vec::with_capacity(25);
                buf.push(MSG_RECONNECT);
                buf.extend_from_slice(&version.to_be_bytes());
                buf.extend_from_slice(&rows.to_be_bytes());
                buf.extend_from_slice(&cols.to_be_bytes());
                buf.extend_from_slice(session_id);
                encode_env_vars(env_vars, &mut buf);
                buf
            }
            Self::SessionInfo {
                version,
                session_id,
            } => {
                let mut buf = Vec::with_capacity(19);
                buf.push(MSG_SESSION_INFO);
                buf.extend_from_slice(&version.to_be_bytes());
                buf.extend_from_slice(session_id);
                buf
            }
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
                if payload.len() < 6 {
                    return Err(ProtocolError::InvalidMessage("Hello too short".to_string()));
                }
                let version = u16::from_be_bytes([payload[0], payload[1]]);
                let rows = u16::from_be_bytes([payload[2], payload[3]]);
                let cols = u16::from_be_bytes([payload[4], payload[5]]);
                let env_vars = decode_env_vars(payload, 6)?;
                Ok(Self::Hello {
                    version,
                    rows,
                    cols,
                    env_vars,
                })
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
            MSG_RECONNECT => {
                if payload.len() < 22 {
                    return Err(ProtocolError::InvalidMessage(
                        "Reconnect too short".to_string(),
                    ));
                }
                let version = u16::from_be_bytes([payload[0], payload[1]]);
                let rows = u16::from_be_bytes([payload[2], payload[3]]);
                let cols = u16::from_be_bytes([payload[4], payload[5]]);
                let mut session_id = [0u8; 16];
                session_id.copy_from_slice(&payload[6..22]);
                let env_vars = decode_env_vars(payload, 22)?;
                Ok(Self::Reconnect {
                    version,
                    rows,
                    cols,
                    session_id,
                    env_vars,
                })
            }
            MSG_SESSION_INFO => {
                if payload.len() < 18 {
                    return Err(ProtocolError::InvalidMessage(
                        "SessionInfo too short".to_string(),
                    ));
                }
                let version = u16::from_be_bytes([payload[0], payload[1]]);
                let mut session_id = [0u8; 16];
                session_id.copy_from_slice(&payload[2..18]);
                Ok(Self::SessionInfo {
                    version,
                    session_id,
                })
            }
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
        let (session, handshake) = Self::accept_any(conn).await?;
        let ControlMessage::Hello {
            version: _,
            rows,
            cols,
            ..
        } = handshake
        else {
            return Err(ProtocolError::InvalidMessage(format!(
                "expected Hello, got {handshake:?}"
            )));
        };
        Ok((session, rows, cols))
    }

    /// Accepts a new client session and returns the raw handshake message.
    ///
    /// The caller is responsible for handling both `Hello` and `Reconnect`
    /// messages. Use this for servers that support session persistence.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if the handshake fails or the protocol version
    /// is unsupported.
    pub async fn accept_any(conn: Connection) -> Result<(Self, ControlMessage), ProtocolError> {
        let (control_send, mut control_recv) = conn.accept_bi().await?;
        let msg = read_control(&mut control_recv).await?.ok_or_else(|| {
            ProtocolError::InvalidMessage("stream closed before handshake".into())
        })?;

        let version = match &msg {
            ControlMessage::Hello { version, .. } | ControlMessage::Reconnect { version, .. } => {
                *version
            }
            other => {
                return Err(ProtocolError::InvalidMessage(format!(
                    "expected Hello or Reconnect, got {other:?}"
                )));
            }
        };

        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidMessage(format!(
                "unsupported protocol version {version} (expected {PROTOCOL_VERSION})"
            )));
        }

        Ok((
            Self {
                conn,
                control_send,
                control_recv,
            },
            msg,
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
    pub async fn connect(
        conn: Connection,
        rows: u16,
        cols: u16,
        env_vars: Vec<(String, String)>,
    ) -> Result<Self, ProtocolError> {
        let (mut control_send, control_recv) = conn.open_bi().await?;
        write_control(
            &mut control_send,
            &ControlMessage::Hello {
                version: PROTOCOL_VERSION,
                rows,
                cols,
                env_vars,
            },
        )
        .await?;

        Ok(Self {
            conn,
            control_send,
            control_recv,
        })
    }

    /// Reconnects to an existing session: opens a bi-stream and sends a Reconnect.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if the handshake fails.
    pub async fn reconnect(
        conn: Connection,
        rows: u16,
        cols: u16,
        session_id: [u8; 16],
        env_vars: Vec<(String, String)>,
    ) -> Result<Self, ProtocolError> {
        let (mut control_send, control_recv) = conn.open_bi().await?;
        write_control(
            &mut control_send,
            &ControlMessage::Reconnect {
                version: PROTOCOL_VERSION,
                rows,
                cols,
                session_id,
                env_vars,
            },
        )
        .await?;

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
        let msg = ControlMessage::Hello {
            version: PROTOCOL_VERSION,
            rows: 24,
            cols: 80,
            env_vars: vec![],
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn encode_decode_hello_with_env() {
        let msg = ControlMessage::Hello {
            version: PROTOCOL_VERSION,
            rows: 24,
            cols: 80,
            env_vars: vec![
                ("TERM".into(), "xterm-256color".into()),
                ("LANG".into(), "en_US.UTF-8".into()),
            ],
        };
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
    fn encode_decode_reconnect() {
        let session_id = [42u8; 16];
        let msg = ControlMessage::Reconnect {
            version: PROTOCOL_VERSION,
            rows: 30,
            cols: 100,
            session_id,
            env_vars: vec![],
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn encode_decode_reconnect_with_env() {
        let session_id = [42u8; 16];
        let msg = ControlMessage::Reconnect {
            version: PROTOCOL_VERSION,
            rows: 30,
            cols: 100,
            session_id,
            env_vars: vec![("TERM".into(), "screen-256color".into())],
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn encode_decode_session_info() {
        let session_id = [7u8; 16];
        let msg = ControlMessage::SessionInfo {
            version: PROTOCOL_VERSION,
            session_id,
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_truncated_reconnect_is_error() {
        // MSG_RECONNECT needs 22 bytes payload (2 + 4 + 16)
        assert!(ControlMessage::decode(&[MSG_RECONNECT, 0, 1, 0, 24, 0]).is_err());
    }

    #[test]
    fn decode_truncated_session_info_is_error() {
        // MSG_SESSION_INFO needs 18 bytes payload (2 + 16)
        assert!(ControlMessage::decode(&[MSG_SESSION_INFO, 0, 0, 0]).is_err());
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
        // MSG_HELLO needs 6 bytes payload (2 + 4)
        assert!(ControlMessage::decode(&[MSG_HELLO, 0, 1, 0, 24]).is_err());
    }

    #[test]
    fn decode_env_vars_truncated_key_length() {
        // Valid Hello header (7 bytes) + num_vars=1 but no key data
        let mut data = vec![MSG_HELLO, 0, 1, 0, 24, 0, 80];
        data.extend_from_slice(&1u16.to_be_bytes()); // num_vars = 1
        // No key length/data follows → truncated
        assert!(ControlMessage::decode(&data).is_err());
    }

    #[test]
    fn decode_env_vars_truncated_key_data() {
        let mut data = vec![MSG_HELLO, 0, 1, 0, 24, 0, 80];
        data.extend_from_slice(&1u16.to_be_bytes()); // num_vars = 1
        data.extend_from_slice(&10u16.to_be_bytes()); // key_len = 10
        data.extend_from_slice(b"AB"); // only 2 bytes of key (need 10)
        assert!(ControlMessage::decode(&data).is_err());
    }

    #[test]
    fn decode_env_vars_truncated_val_length() {
        let mut data = vec![MSG_HELLO, 0, 1, 0, 24, 0, 80];
        data.extend_from_slice(&1u16.to_be_bytes()); // num_vars = 1
        data.extend_from_slice(&4u16.to_be_bytes()); // key_len = 4
        data.extend_from_slice(b"TERM"); // key
        // No val length follows
        assert!(ControlMessage::decode(&data).is_err());
    }

    #[test]
    fn decode_env_vars_truncated_val_data() {
        let mut data = vec![MSG_HELLO, 0, 1, 0, 24, 0, 80];
        data.extend_from_slice(&1u16.to_be_bytes()); // num_vars = 1
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(b"TERM");
        data.extend_from_slice(&20u16.to_be_bytes()); // val_len = 20
        data.extend_from_slice(b"xt"); // only 2 bytes (need 20)
        assert!(ControlMessage::decode(&data).is_err());
    }

    #[test]
    fn decode_env_vars_invalid_utf8_key() {
        let mut data = vec![MSG_HELLO, 0, 1, 0, 24, 0, 80];
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes()); // key_len = 2
        data.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        data.extend_from_slice(&1u16.to_be_bytes()); // val_len = 1
        data.push(b'x');
        assert!(ControlMessage::decode(&data).is_err());
    }

    #[test]
    fn decode_env_vars_invalid_utf8_val() {
        let mut data = vec![MSG_HELLO, 0, 1, 0, 24, 0, 80];
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.push(b'K');
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8 value
        assert!(ControlMessage::decode(&data).is_err());
    }

    #[test]
    fn decode_hello_without_env_section() {
        // A Hello with exactly 6 bytes payload (no env section) should
        // decode with empty env_vars for forward compatibility.
        let data = [MSG_HELLO, 0, 1, 0, 24, 0, 80];
        let msg = ControlMessage::decode(&data).unwrap();
        let ControlMessage::Hello { env_vars, .. } = msg else {
            panic!("expected Hello");
        };
        assert!(env_vars.is_empty());
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

        let _client_session = ClientSession::connect(client_conn, 24, 80, vec![])
            .await
            .unwrap();
        let (server_session, rows, cols) = server_task.await.unwrap().unwrap();
        assert_eq!(rows, 24);
        assert_eq!(cols, 80);

        // Keep sessions alive for clean shutdown
        drop(server_session);
    }

    #[tokio::test]
    async fn version_mismatch_hello_rejected() {
        let (client_conn, server_conn, _s, _c) = quic_pair().await;

        let server_task = tokio::spawn(async move { ServerSession::accept_any(server_conn).await });

        // Manually send a Hello with a bogus version instead of using ClientSession::connect
        let (mut send, _recv) = client_conn.open_bi().await.unwrap();
        let bad_hello = ControlMessage::Hello {
            version: 999,
            rows: 24,
            cols: 80,
            env_vars: vec![],
        };
        write_control(&mut send, &bad_hello).await.unwrap();

        match server_task.await.unwrap() {
            Err(e) => {
                let err = e.to_string();
                assert!(
                    err.contains("unsupported protocol version 999"),
                    "error should mention version: {err}"
                );
            }
            Ok(_) => panic!("server should reject unknown version"),
        }
    }

    #[tokio::test]
    async fn version_mismatch_reconnect_rejected() {
        let (client_conn, server_conn, _s, _c) = quic_pair().await;

        let server_task = tokio::spawn(async move { ServerSession::accept_any(server_conn).await });

        let (mut send, _recv) = client_conn.open_bi().await.unwrap();
        let bad_reconnect = ControlMessage::Reconnect {
            version: 0,
            rows: 24,
            cols: 80,
            session_id: [1u8; 16],
            env_vars: vec![],
        };
        write_control(&mut send, &bad_reconnect).await.unwrap();

        match server_task.await.unwrap() {
            Err(e) => {
                let err = e.to_string();
                assert!(
                    err.contains("unsupported protocol version 0"),
                    "error should mention version: {err}"
                );
            }
            Ok(_) => panic!("server should reject version 0"),
        }
    }

    #[tokio::test]
    async fn datagram_io() {
        let (client_conn, server_conn, _s, _c) = quic_pair().await;

        let server_task =
            tokio::spawn(async move { ServerSession::accept(server_conn).await.unwrap() });

        let client_session = ClientSession::connect(client_conn, 24, 80, vec![])
            .await
            .unwrap();
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

        let mut client_session = ClientSession::connect(client_conn, 24, 80, vec![])
            .await
            .unwrap();
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

    #[test]
    fn decode_resize_too_short() {
        // MSG_RESIZE with only 2 bytes instead of 4
        let data = [MSG_RESIZE, 0x00, 0x18];
        assert!(ControlMessage::decode(&data).is_err());
    }

    #[test]
    fn decode_resize_valid() {
        let data = [MSG_RESIZE, 0x00, 0x18, 0x00, 0x50];
        let msg = ControlMessage::decode(&data).unwrap();
        assert_eq!(msg, ControlMessage::Resize { rows: 24, cols: 80 });
    }

    #[tokio::test]
    async fn read_control_oversized_message() {
        // Set up a QUIC connection to test read_control with oversized length
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

        // Client sends an oversized length prefix (> 65536)
        let (mut send, _recv) = client_conn.open_bi().await.unwrap();
        let bad_len: u32 = 100_000;
        send.write_all(&bad_len.to_be_bytes()).await.unwrap();
        send.finish().unwrap();

        let (_server_send, mut server_recv) = server_conn.accept_bi().await.unwrap();
        let result = read_control(&mut server_recv).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn read_control_stream_closed_early() {
        // Test that read_control returns None when stream closes before any data
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

        // Client opens bi-stream and immediately finishes (no data)
        let (mut send, _recv) = client_conn.open_bi().await.unwrap();
        send.finish().unwrap();

        let (_server_send, mut server_recv) = server_conn.accept_bi().await.unwrap();
        let result = read_control(&mut server_recv).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn accept_non_hello_rejected() {
        // ServerSession::accept should reject non-Hello messages
        let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let cert = server.server_cert_der().clone();
        let client = QuicClient::new().unwrap();

        let accept = tokio::spawn({
            let endpoint = server.endpoint.clone();
            async move {
                let incoming = endpoint.accept().await.unwrap();
                let conn = incoming.await.unwrap();
                ServerSession::accept(conn).await
            }
        });
        let client_conn = client.connect(addr, "localhost", &cert).await.unwrap();

        // Send a Resize instead of Hello (invalid for handshake)
        let (mut send, _recv) = client_conn.open_bi().await.unwrap();
        let resize = ControlMessage::Resize { rows: 24, cols: 80 };
        write_control(&mut send, &resize).await.unwrap();

        let result = accept.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn accept_any_non_hello_non_reconnect_rejected() {
        // ServerSession::accept_any should reject non-Hello/Reconnect messages
        let server = QuicServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let cert = server.server_cert_der().clone();
        let client = QuicClient::new().unwrap();

        let accept = tokio::spawn({
            let endpoint = server.endpoint.clone();
            async move {
                let incoming = endpoint.accept().await.unwrap();
                let conn = incoming.await.unwrap();
                ServerSession::accept_any(conn).await
            }
        });
        let client_conn = client.connect(addr, "localhost", &cert).await.unwrap();

        // Send Goodbye (not Hello or Reconnect)
        let (mut send, _recv) = client_conn.open_bi().await.unwrap();
        write_control(&mut send, &ControlMessage::Goodbye)
            .await
            .unwrap();

        let result = accept.await.unwrap();
        assert!(result.is_err());
    }
}
