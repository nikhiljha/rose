//! Cancellable readiness waits for nonblocking Unix PTY descriptors.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use filedescriptor::{AsRawFileDescriptor, FileDescriptor, POLLIN, POLLOUT, poll, pollfd};
use portable_pty::MasterPty;

/// Shared PTY readiness and session-lifetime notification.
pub struct PtyIo {
    descriptor: FileDescriptor,
    cancelled: FileDescriptor,
}

impl PtyIo {
    /// Return readiness state and an endpoint whose closure cancels all waits.
    pub(crate) fn new(master: &dyn MasterPty) -> io::Result<(Arc<Self>, FileDescriptor)> {
        let fd = master
            .as_raw_fd()
            .ok_or_else(|| io::Error::other("PTY has no Unix descriptor"))?;
        let mut descriptor = FileDescriptor::dup(&fd).map_err(io::Error::other)?;
        descriptor
            .set_non_blocking(true)
            .map_err(io::Error::other)?;
        let (cancelled, cancel) = filedescriptor::socketpair().map_err(io::Error::other)?;
        let ready = Arc::new(Self {
            descriptor,
            cancelled,
        });
        ready.wait(POLLIN, Some(Duration::ZERO)).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("PTY readiness is unsupported: {error}"),
            )
        })?;
        Ok((ready, cancel))
    }

    /// Wrap an existing PTY reader or writer with cancellable readiness waits.
    pub(crate) fn wrap<T>(self: &Arc<Self>, inner: T) -> PtyStream<T> {
        PtyStream {
            inner,
            ready: Arc::clone(self),
        }
    }

    fn wait(&self, events: i16, timeout: Option<Duration>) -> io::Result<()> {
        loop {
            let mut descriptors = [
                pollfd {
                    fd: self.descriptor.as_raw_file_descriptor(),
                    events,
                    revents: 0,
                },
                pollfd {
                    fd: self.cancelled.as_raw_file_descriptor(),
                    events: POLLIN,
                    revents: 0,
                },
            ];
            match poll(&mut descriptors, timeout) {
                Err(filedescriptor::Error::Poll(error))
                    if error.kind() == io::ErrorKind::Interrupted =>
                {
                    continue;
                }
                Err(error) => return Err(io::Error::other(error)),
                Ok(_) => {}
            }
            if descriptors[1].revents != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "PTY session closed",
                ));
            }
            return Ok(());
        }
    }

    fn perform<T>(
        &self,
        events: i16,
        mut operation: impl FnMut() -> io::Result<T>,
    ) -> io::Result<T> {
        loop {
            self.wait(events, None)?;
            match operation() {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => return result,
            }
        }
    }
}

/// A PTY stream that wakes on readiness or session destruction.
pub struct PtyStream<T> {
    inner: T,
    ready: Arc<PtyIo>,
}

impl<T: Read> Read for PtyStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.ready.perform(POLLIN, || self.inner.read(buf))
    }
}

impl<T: Write> Write for PtyStream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.ready.perform(POLLOUT, || self.inner.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portable_pty::{PtySize, native_pty_system};
    use std::sync::mpsc;

    #[test]
    fn cancellation_wakes_idle_reader_and_preserves_empty_io() {
        let pair = native_pty_system().openpty(PtySize::default()).unwrap();
        let (ready, cancel) = PtyIo::new(pair.master.as_ref()).unwrap();
        let mut reader = ready.wrap(pair.master.try_clone_reader().unwrap());
        let mut writer = ready.wrap(pair.master.take_writer().unwrap());
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(reader.read(&mut [])).unwrap();
            send.send(reader.read(&mut [0])).unwrap();
        });
        assert_eq!(
            receive
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            0
        );
        assert!(matches!(
            receive.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(cancel);
        assert_eq!(
            receive
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(writer.write(&[]).unwrap(), 0);
        assert_eq!(
            writer.write(b"cancelled").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        worker.join().unwrap();
    }

    #[test]
    fn read_retries_when_another_consumer_drains_readiness() {
        let (mut reader, mut sender) = filedescriptor::socketpair().unwrap();
        reader.set_non_blocking(true).unwrap();
        let mut other_reader = reader.try_clone().unwrap();
        let (cancelled, _cancel) = filedescriptor::socketpair().unwrap();
        let ready = PtyIo {
            descriptor: reader.try_clone().unwrap(),
            cancelled,
        };
        sender.write_all(b"x").unwrap();
        let mut attempts = 0;
        let mut byte = [0];
        let count = ready
            .perform(POLLIN, || {
                attempts += 1;
                if attempts == 1 {
                    let mut consumed = [0];
                    other_reader.read_exact(&mut consumed)?;
                    assert_eq!(&consumed, b"x");
                    let result = reader.read(&mut byte);
                    assert_eq!(
                        result.as_ref().unwrap_err().kind(),
                        io::ErrorKind::WouldBlock
                    );
                    sender.write_all(b"y")?;
                    return result;
                }
                reader.read(&mut byte)
            })
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(&byte, b"y");
        assert_eq!(attempts, 2);
    }

    #[test]
    fn peer_closure_preserves_eof_and_write_errors() {
        let (mut descriptor, peer) = filedescriptor::socketpair().unwrap();
        descriptor.set_non_blocking(true).unwrap();
        let (cancelled, _cancel) = filedescriptor::socketpair().unwrap();
        let ready = Arc::new(PtyIo {
            descriptor: descriptor.try_clone().unwrap(),
            cancelled,
        });
        let mut stream = ready.wrap(descriptor);
        drop(peer);
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(stream.read(&mut [0])).unwrap();
            send.send(stream.write(b"closed")).unwrap();
        });
        assert_eq!(
            receive
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(
            receive
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        worker.join().unwrap();
    }
}
