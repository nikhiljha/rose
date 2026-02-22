//! PTY management using portable-pty.
//!
//! The server spawns a shell (or command) in a PTY and reads/writes to it.
//! By default, spawns the user's login shell.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use portable_pty::{Child, ChildKiller, CommandBuilder, ExitStatus, MasterPty, PtySize};
use tokio::sync::broadcast;

/// Errors that can occur during PTY operations.
#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    /// Failed to open a PTY pair.
    #[error("failed to open PTY: {0}")]
    Open(String),
    /// Failed to spawn a command in the PTY.
    #[error("failed to spawn command: {0}")]
    Spawn(String),
    /// I/O error during PTY read/write.
    #[error("PTY I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Manages a PTY lifecycle: spawning a child process, reading output,
/// writing input, and handling resize events.
pub struct PtySession {
    writer: Arc<Mutex<Box<dyn std::io::Write + Send>>>,
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    output_tx: broadcast::Sender<Bytes>,
    _reader_handle: std::thread::JoinHandle<()>,
}

impl PtySession {
    /// Opens a PTY with the user's default login shell.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Open` if the PTY cannot be created, or
    /// `PtyError::Spawn` if the shell cannot be started.
    pub fn open(rows: u16, cols: u16) -> Result<Self, PtyError> {
        Self::open_internal(rows, cols, CommandBuilder::new_default_prog())
    }

    /// Opens a PTY running a specific command with arguments.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Open` if the PTY cannot be created, or
    /// `PtyError::Spawn` if the command cannot be started.
    pub fn open_command(rows: u16, cols: u16, cmd: &str, args: &[&str]) -> Result<Self, PtyError> {
        let mut builder = CommandBuilder::new(cmd);
        builder.args(args);
        Self::open_internal(rows, cols, builder)
    }

    fn open_internal(rows: u16, cols: u16, cmd: CommandBuilder) -> Result<Self, PtyError> {
        let pty_system = portable_pty::native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| PtyError::Open(e.to_string()))?;

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| PtyError::Spawn(e.to_string()))?;
        let killer = child.clone_killer();
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| PtyError::Io(std::io::Error::other(e.to_string())))?;
        let writer = Arc::new(Mutex::new(writer));

        let (output_tx, _) = broadcast::channel(256);
        let tx = output_tx.clone();

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| PtyError::Io(std::io::Error::other(e.to_string())))?;

        // Spawn a dedicated OS thread for blocking PTY reads.
        // tokio::task::spawn_blocking is not suitable because the tokio
        // blocking thread pool has a limited number of threads and this
        // read blocks indefinitely until the PTY closes.
        let reader_handle = std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = Bytes::copy_from_slice(&buf[..n]);
                        // Ignore send errors — means no subscribers
                        let _ = tx.send(chunk);
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            writer,
            master: pair.master,
            child,
            killer,
            output_tx,
            _reader_handle: reader_handle,
        })
    }

    /// Subscribes to PTY output. Each subscriber receives all output
    /// produced after subscribing.
    #[must_use]
    pub fn subscribe_output(&self) -> broadcast::Receiver<Bytes> {
        self.output_tx.subscribe()
    }

    /// Returns a clone of the writer handle for use from another task/thread.
    #[must_use]
    pub fn clone_writer(&self) -> Arc<Mutex<Box<dyn std::io::Write + Send>>> {
        Arc::clone(&self.writer)
    }

    /// Writes input bytes to the PTY (i.e., sends keystrokes to the child).
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Io` if the write fails.
    ///
    /// # Panics
    ///
    /// Panics if the writer mutex is poisoned (a thread panicked while holding it).
    pub fn write(&self, data: &[u8]) -> Result<(), PtyError> {
        let mut w = self.writer.lock().expect("writer lock poisoned");
        std::io::Write::write_all(&mut *w, data)?;
        std::io::Write::flush(&mut *w)?;
        Ok(())
    }

    /// Resizes the PTY to the given dimensions.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Io` if the resize fails.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), PtyError> {
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| PtyError::Io(std::io::Error::other(e.to_string())))
    }

    /// Polls the child process for completion without blocking.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Io` if the wait fails.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, PtyError> {
        self.child.try_wait().map_err(PtyError::Io)
    }

    /// Blocks until the child process exits.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Io` if the wait fails.
    pub fn wait(&mut self) -> Result<ExitStatus, PtyError> {
        self.child.wait().map_err(PtyError::Io)
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        let _ = self.killer.kill();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn spawn_echo_and_read_output() {
        let mut session = PtySession::open_command(24, 80, "echo", &["hello_pty"]).unwrap();
        let mut rx = session.subscribe_output();

        // Collect output until we see our marker or timeout
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut collected = String::new();
        while std::time::Instant::now() < deadline {
            match rx.try_recv() {
                Ok(chunk) => {
                    collected.push_str(&String::from_utf8_lossy(&chunk));
                    if collected.contains("hello_pty") {
                        break;
                    }
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        assert!(
            collected.contains("hello_pty"),
            "expected 'hello_pty' in output, got: {collected:?}"
        );

        let status = session.wait().unwrap();
        assert!(status.success());
    }

    #[test]
    fn write_to_cat_and_read_echo() {
        let session = PtySession::open_command(24, 80, "cat", &[]).unwrap();
        let mut rx = session.subscribe_output();

        // Give the child a moment to start
        std::thread::sleep(Duration::from_millis(100));

        session.write(b"test_input\n").unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut collected = String::new();
        while std::time::Instant::now() < deadline {
            match rx.try_recv() {
                Ok(chunk) => {
                    collected.push_str(&String::from_utf8_lossy(&chunk));
                    if collected.contains("test_input") {
                        break;
                    }
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        assert!(
            collected.contains("test_input"),
            "expected 'test_input' in output, got: {collected:?}"
        );
    }

    #[test]
    fn resize_does_not_error() {
        let session = PtySession::open_command(24, 80, "cat", &[]).unwrap();
        session.resize(40, 120).unwrap();
    }

    #[test]
    fn child_exit_code() {
        let mut session = PtySession::open_command(24, 80, "sh", &["-c", "exit 42"]).unwrap();
        let status = session.wait().unwrap();
        assert!(!status.success());
        assert_eq!(status.exit_code(), 42);
    }

    #[test]
    fn multiple_subscribers() {
        let mut session = PtySession::open_command(24, 80, "echo", &["multi_sub"]).unwrap();
        let mut rx1 = session.subscribe_output();
        let mut rx2 = session.subscribe_output();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut c1 = String::new();
        let mut c2 = String::new();
        while std::time::Instant::now() < deadline {
            if let Ok(chunk) = rx1.try_recv() {
                c1.push_str(&String::from_utf8_lossy(&chunk));
            }
            if let Ok(chunk) = rx2.try_recv() {
                c2.push_str(&String::from_utf8_lossy(&chunk));
            }
            if c1.contains("multi_sub") && c2.contains("multi_sub") {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            c1.contains("multi_sub"),
            "subscriber 1 should see output: {c1:?}"
        );
        assert!(
            c2.contains("multi_sub"),
            "subscriber 2 should see output: {c2:?}"
        );

        session.wait().unwrap();
    }

    #[test]
    fn try_wait_before_exit() {
        let mut session = PtySession::open_command(24, 80, "sleep", &["10"]).unwrap();
        // Child should not have exited yet
        let result = session.try_wait().unwrap();
        assert!(result.is_none(), "child should still be running");
        // Drop will kill it
    }

    #[test]
    fn open_default_shell() {
        // Just verify that opening a default shell doesn't error
        let _session = PtySession::open(24, 80).unwrap();
        // Drop immediately kills it
    }
}
