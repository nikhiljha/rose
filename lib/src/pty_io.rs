//! Cancellable readiness waits for nonblocking Unix PTY descriptors.

use std::io::{self, Read, Write};
use std::sync::Arc;

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
        Ok((
            Arc::new(Self {
                descriptor,
                cancelled,
            }),
            cancel,
        ))
    }

    /// Wrap an existing PTY reader or writer with cancellable readiness waits.
    pub(crate) fn wrap<T>(self: &Arc<Self>, inner: T) -> PtyStream<T> {
        PtyStream {
            inner,
            ready: Arc::clone(self),
        }
    }

    fn perform<T>(
        &self,
        events: i16,
        mut operation: impl FnMut() -> io::Result<T>,
    ) -> io::Result<T> {
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
            match poll(&mut descriptors, None) {
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
