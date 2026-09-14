//! Bounded, ordered terminal input with session-level replay suppression.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use tokio::sync::{mpsc, oneshot, watch};

/// Maximum unacknowledged input retained by a client.
pub const MAX_PENDING_INPUT: usize = 64 * 1024;
const MAX_FRAME_INPUT: usize = 4096;
const STREAM_TYPE: u8 = 3;

/// Failures in input retention, framing, or transport.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("terminal input buffer is full")]
    Full,
    #[error("input offset {received} is outside the retained range {start}..={end}")]
    Offset { received: u64, start: u64, end: u64 },
    #[error("invalid terminal input frame length")]
    Length,
    #[error("terminal input writer stopped")]
    Closed,
    #[error("terminal input handshake timed out")]
    Timeout,
    #[error("terminal input I/O: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    #[error(transparent)]
    Read(#[from] quinn::ReadExactError),
    #[error(transparent)]
    Write(#[from] quinn::WriteError),
}

#[derive(Default)]
struct PendingInput {
    offset: u64,
    sent: u64,
    bytes: BytesMut,
    initialized: bool,
}

impl PendingInput {
    fn acknowledge(&mut self, offset: u64) -> Result<(), InputError> {
        let end = self.sent;
        if offset < self.offset || offset > end {
            return Err(InputError::Offset {
                received: offset,
                start: self.offset,
                end,
            });
        }
        self.bytes.advance((offset - self.offset) as usize);
        self.offset = offset;
        Ok(())
    }
}

/// Input retained across transport connections, until the PTY acknowledges it.
#[derive(Clone)]
pub struct InputBuffer {
    pending: Arc<Mutex<PendingInput>>,
    changed: watch::Sender<()>,
}

impl Default for InputBuffer {
    fn default() -> Self {
        Self {
            pending: Arc::new(Mutex::new(PendingInput::default())),
            changed: watch::channel(()).0,
        }
    }
}

impl InputBuffer {
    /// Retain bytes for transmission without blocking on network I/O.
    pub(crate) fn push(&self, bytes: &[u8]) -> Result<(), InputError> {
        let mut pending = self.pending.lock().expect("input buffer lock poisoned");
        if bytes.len() > MAX_PENDING_INPUT - pending.bytes.len() {
            return Err(InputError::Full);
        }
        pending
            .offset
            .checked_add((pending.bytes.len() + bytes.len()) as u64)
            .ok_or(InputError::Length)?;
        pending.bytes.extend_from_slice(bytes);
        self.changed.send_replace(());
        Ok(())
    }

    /// Wait before consuming another keyboard event when input is backed up.
    pub(crate) async fn wait_for_capacity(&self, length: usize) {
        let mut changed = self.changed.subscribe();
        loop {
            if self
                .pending
                .lock()
                .expect("input buffer lock poisoned")
                .bytes
                .len()
                <= MAX_PENDING_INPUT.saturating_sub(length)
            {
                return;
            }
            let _ = changed.changed().await;
        }
    }

    fn resume(&self, offset: u64) -> Result<(), InputError> {
        let mut pending = self.pending.lock().expect("input buffer lock poisoned");
        if pending.initialized {
            pending.acknowledge(offset)?;
        } else {
            offset
                .checked_add(pending.bytes.len() as u64)
                .ok_or(InputError::Length)?;
            pending.offset = offset;
            pending.sent = offset;
            pending.initialized = true;
        }
        self.changed.send_replace(());
        Ok(())
    }

    fn acknowledge(&self, offset: u64) -> Result<(), InputError> {
        self.pending
            .lock()
            .expect("input buffer lock poisoned")
            .acknowledge(offset)?;
        self.changed.send_replace(());
        Ok(())
    }

    async fn send_pending(
        &self,
        mut send: quinn::SendStream,
        mut offset: u64,
    ) -> Result<(), InputError> {
        let mut changed = self.changed.subscribe();
        loop {
            let bytes = {
                let mut pending = self.pending.lock().expect("input buffer lock poisoned");
                offset = offset.max(pending.offset);
                let start = (offset - pending.offset) as usize;
                let end = (start + MAX_FRAME_INPUT).min(pending.bytes.len());
                let bytes = Bytes::copy_from_slice(&pending.bytes[start..end]);
                pending.sent = pending.sent.max(offset + bytes.len() as u64);
                bytes
            };
            if bytes.is_empty() {
                let _ = changed.changed().await;
                continue;
            }
            send.write_all(&offset.to_be_bytes()).await?;
            send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
            send.write_all(&bytes).await?;
            offset += bytes.len() as u64;
        }
    }

    async fn receive_acks(&self, mut recv: quinn::RecvStream) -> Result<(), InputError> {
        loop {
            let mut offset = [0; 8];
            recv.read_exact(&mut offset).await?;
            self.acknowledge(u64::from_be_bytes(offset))?;
        }
    }

    /// Run one connection, replaying only bytes the persistent writer lacks.
    pub(crate) async fn connect(&self, conn: &quinn::Connection) -> Result<(), InputError> {
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&[STREAM_TYPE]).await?;
        let mut offset = [0; 8];
        tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut offset))
            .await
            .map_err(|_| InputError::Timeout)??;
        let offset = u64::from_be_bytes(offset);
        self.resume(offset)?;
        tokio::select! {
            result = self.send_pending(send, offset) => result,
            result = self.receive_acks(recv) => result,
        }
    }
}

enum WriteRequest {
    Position(oneshot::Sender<u64>),
    Write {
        offset: u64,
        bytes: Bytes,
        result: oneshot::Sender<Result<u64, InputError>>,
    },
}

#[derive(Default)]
struct InputReceiver {
    offset: u64,
}

impl InputReceiver {
    fn write(
        &mut self,
        offset: u64,
        bytes: &[u8],
        writer: &mut dyn Write,
    ) -> Result<u64, InputError> {
        if offset > self.offset {
            return Err(InputError::Offset {
                received: offset,
                start: 0,
                end: self.offset,
            });
        }
        offset
            .checked_add(bytes.len() as u64)
            .ok_or(InputError::Length)?;
        let skipped = (self.offset - offset).min(bytes.len() as u64) as usize;
        let mut remaining = &bytes[skipped..];
        while !remaining.is_empty() {
            match writer.write(remaining) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(length) => {
                    self.offset += length as u64;
                    remaining = &remaining[length..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(self.offset)
    }
}

/// Session-owned writer: cancellation of a connection cannot cancel a PTY write.
#[derive(Clone)]
pub struct ServerInput {
    requests: mpsc::Sender<WriteRequest>,
}

impl ServerInput {
    /// Start a bounded worker for the PTY's blocking writer.
    pub(crate) fn new(writer: Arc<Mutex<Box<dyn Write + Send>>>) -> Self {
        let (requests, mut receive) = mpsc::channel(16);
        std::thread::spawn(move || {
            let mut input = InputReceiver::default();
            while let Some(request) = receive.blocking_recv() {
                match request {
                    WriteRequest::Position(result) => {
                        let _ = result.send(input.offset);
                    }
                    WriteRequest::Write {
                        offset,
                        bytes,
                        result,
                    } => {
                        let mut writer = writer.lock().expect("PTY writer lock poisoned");
                        let _ = result.send(input.write(offset, &bytes, writer.as_mut()));
                    }
                }
            }
        });
        Self { requests }
    }

    async fn position(&self) -> Result<u64, InputError> {
        let (send, recv) = oneshot::channel();
        self.requests
            .send(WriteRequest::Position(send))
            .await
            .map_err(|_| InputError::Closed)?;
        recv.await.map_err(|_| InputError::Closed)
    }

    async fn write(&self, offset: u64, bytes: Bytes) -> Result<u64, InputError> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_INPUT {
            return Err(InputError::Length);
        }
        let (send, recv) = oneshot::channel();
        self.requests
            .send(WriteRequest::Write {
                offset,
                bytes,
                result: send,
            })
            .await
            .map_err(|_| InputError::Closed)?;
        recv.await.map_err(|_| InputError::Closed)?
    }

    /// Receive a connection's input stream and acknowledge completed PTY writes.
    pub(crate) async fn serve(&self, conn: &quinn::Connection) -> Result<(), InputError> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let mut kind = [0];
        recv.read_exact(&mut kind).await?;
        if kind[0] != STREAM_TYPE {
            return Err(InputError::Length);
        }
        send.write_all(&self.position().await?.to_be_bytes())
            .await?;
        loop {
            let mut offset = [0; 8];
            let mut length = [0; 4];
            recv.read_exact(&mut offset).await?;
            recv.read_exact(&mut length).await?;
            let length = u32::from_be_bytes(length) as usize;
            if length == 0 || length > MAX_FRAME_INPUT {
                return Err(InputError::Length);
            }
            let mut bytes = vec![0; length];
            recv.read_exact(&mut bytes).await?;
            let accepted = self.write(u64::from_be_bytes(offset), bytes.into()).await?;
            send.write_all(&accepted.to_be_bytes()).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::task::{Context, Waker};

    use super::*;

    #[test]
    fn partial_writes_and_overlapping_replays_preserve_each_byte_once() {
        let mut receiver = InputReceiver::default();
        let mut prefix = [0; 2];
        assert!(
            receiver
                .write(0, b"abcd", &mut prefix.as_mut_slice())
                .is_err()
        );
        assert_eq!(receiver.offset, 2);
        let mut rest = Vec::new();
        assert_eq!(receiver.write(0, b"abcd", &mut rest).unwrap(), 4);
        assert_eq!(receiver.write(2, b"cdEF", &mut rest).unwrap(), 6);
        assert_eq!(receiver.write(0, b"abcd", &mut rest).unwrap(), 6);
        assert_eq!([prefix.as_slice(), &rest].concat(), b"abcdEF");
        assert!(matches!(
            receiver.write(7, b"x", &mut rest),
            Err(InputError::Offset { .. })
        ));
        receiver.offset = u64::MAX;
        assert!(matches!(
            receiver.write(u64::MAX, b"x", &mut rest),
            Err(InputError::Length)
        ));
    }

    #[test]
    fn acknowledgments_cannot_discard_unsent_bytes_or_rewind_input() {
        let input = InputBuffer::default();
        input.resume(5).unwrap();
        input.push(b"x").unwrap();
        assert!(matches!(
            input.acknowledge(6),
            Err(InputError::Offset { .. })
        ));
        assert!(matches!(input.resume(4), Err(InputError::Offset { .. })));
        assert_eq!(&input.pending.lock().unwrap().bytes[..], b"x");
        let overflow = InputBuffer::default();
        overflow.push(b"x").unwrap();
        assert!(matches!(overflow.resume(u64::MAX), Err(InputError::Length)));
        let overflow = InputBuffer::default();
        overflow.resume(u64::MAX).unwrap();
        assert!(matches!(overflow.push(b"x"), Err(InputError::Length)));
    }

    #[tokio::test]
    async fn canceled_write_requests_finish_before_the_next_connection_position() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let writer = Arc::new(Mutex::new(
            Box::new(file.reopen().unwrap()) as Box<dyn Write + Send>
        ));
        let input = ServerInput::new(Arc::clone(&writer));
        {
            let _guard = writer.lock().unwrap();
            let mut write = std::pin::pin!(input.write(0, Bytes::from_static(b"once")));
            assert!(
                write
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        let offset = tokio::time::timeout(Duration::from_secs(2), input.position())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(offset, 4);
        assert_eq!(
            input.write(0, Bytes::from_static(b"once")).await.unwrap(),
            4
        );
        assert_eq!(std::fs::read(file.path()).unwrap(), b"once");
        assert!(matches!(
            input.write(4, Bytes::new()).await,
            Err(InputError::Length)
        ));
        assert!(matches!(
            input
                .write(4, Bytes::from(vec![0; MAX_FRAME_INPUT + 1]))
                .await,
            Err(InputError::Length)
        ));
    }

    async fn run_input(server: ServerInput, client: InputBuffer) {
        let connection = crate::testutil::InputConnection::new(server, client.clone()).await;
        tokio::time::timeout(
            Duration::from_secs(5),
            client.wait_for_capacity(MAX_PENDING_INPUT),
        )
        .await
        .unwrap();
        connection.close().await;
    }

    #[tokio::test]
    async fn bounded_input_streams_in_order_and_a_new_client_adopts_the_session_offset() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let server = ServerInput::new(Arc::new(Mutex::new(Box::new(file.reopen().unwrap()))));
        let input = InputBuffer::default();
        let bytes: Vec<u8> = (0..MAX_PENDING_INPUT).map(|i| (i % 251) as u8).collect();
        input.push(&bytes).unwrap();
        assert!(matches!(input.push(b"x"), Err(InputError::Full)));
        run_input(server.clone(), input.clone()).await;
        assert_eq!(std::fs::read(file.path()).unwrap(), bytes);
        input.push(b"same client").unwrap();
        run_input(server.clone(), input).await;
        let next = InputBuffer::default();
        next.push(b"new client").unwrap();
        run_input(server, next).await;
        assert_eq!(
            std::fs::read(file.path()).unwrap(),
            [bytes.as_slice(), b"same client", b"new client"].concat()
        );
    }

    #[tokio::test]
    async fn invalid_input_streams_are_rejected_without_writing() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let server = ServerInput::new(Arc::new(Mutex::new(Box::new(file.reopen().unwrap()))));
        for bytes in [
            vec![255],
            [
                &[STREAM_TYPE][..],
                &0u64.to_be_bytes(),
                &u32::MAX.to_be_bytes(),
            ]
            .concat(),
        ] {
            let (client_conn, server_conn, _fixture, _client) =
                crate::testutil::connected_pair().await;
            let worker = server.clone();
            let task = tokio::spawn(async move { worker.serve(&server_conn).await });
            let (mut send, _recv) = client_conn.open_bi().await.unwrap();
            send.write_all(&bytes).await.unwrap();
            assert!(matches!(task.await.unwrap(), Err(InputError::Length)));
        }
        assert_eq!(server.position().await.unwrap(), 0);
        assert!(std::fs::read(file.path()).unwrap().is_empty());
    }
}
