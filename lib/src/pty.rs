//! PTY management using portable-pty.
//!
//! The server spawns a shell (or command) in a PTY and reads/writes to it.
//! By default, spawns the user's login shell.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use portable_pty::{Child, ChildKiller, CommandBuilder, ExitStatus, MasterPty, PtySize};
use tokio::sync::{Notify, broadcast};

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
    /// The initial broadcast receiver, created before the reader thread
    /// starts.  Handed to the first caller of [`subscribe_output`] so it
    /// receives all output from the very start of the PTY — avoiding a
    /// race where a fast command (e.g. `echo`) completes before the
    /// caller has a chance to subscribe.
    initial_rx: Mutex<Option<broadcast::Receiver<Bytes>>>,
    /// Notified when the PTY reader thread exits (shell closed).
    pty_closed: Arc<Notify>,
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

    /// Opens a PTY with the user's default login shell and additional
    /// environment variables (e.g. `TERM`, locale settings forwarded from
    /// the client).
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Open` if the PTY cannot be created, or
    /// `PtyError::Spawn` if the shell cannot be started.
    pub fn open_with_env(
        rows: u16,
        cols: u16,
        env_vars: &[(String, String)],
    ) -> Result<Self, PtyError> {
        let mut builder = CommandBuilder::new_default_prog();
        for (key, val) in env_vars {
            builder.env(key, val);
        }
        Self::open_internal(rows, cols, builder)
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

    /// Opens a PTY running a specific command with arguments and extra
    /// environment variables.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Open` if the PTY cannot be created, or
    /// `PtyError::Spawn` if the command cannot be started.
    pub fn open_command_with_env(
        rows: u16,
        cols: u16,
        cmd: &str,
        args: &[&str],
        env_vars: &[(String, String)],
    ) -> Result<Self, PtyError> {
        let mut builder = CommandBuilder::new(cmd);
        builder.args(args);
        for (key, val) in env_vars {
            builder.env(key, val);
        }
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

        let (output_tx, initial_rx) = broadcast::channel(256);
        let tx = output_tx.clone();

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| PtyError::Io(std::io::Error::other(e.to_string())))?;

        // Notified when the reader thread exits (shell closed / PTY EOF).
        let pty_closed = Arc::new(Notify::new());
        let closed = Arc::clone(&pty_closed);

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
            // notify_one() stores a permit when no task is currently
            // waiting, so the output_task sees the close even if it's
            // busy doing work outside its select! loop.
            closed.notify_one();
        });

        Ok(Self {
            writer,
            master: pair.master,
            child,
            killer,
            output_tx,
            initial_rx: Mutex::new(Some(initial_rx)),
            pty_closed,
            _reader_handle: reader_handle,
        })
    }

    /// Subscribes to PTY output.
    ///
    /// The **first** call returns a receiver created before the reader
    /// thread started, so it is guaranteed to contain every byte the
    /// child has produced.  Subsequent calls create a new receiver that
    /// only sees output produced after the call.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (a thread panicked while
    /// holding it).
    #[must_use]
    pub fn subscribe_output(&self) -> broadcast::Receiver<Bytes> {
        self.initial_rx
            .lock()
            .expect("initial_rx lock poisoned")
            .take()
            .unwrap_or_else(|| self.output_tx.subscribe())
    }

    /// Returns a handle that is notified when the PTY reader exits
    /// (shell closed / EOF). Used by the server to detect shell exit
    /// even though the broadcast channel stays open (`PtySession` holds
    /// a sender).
    #[must_use]
    pub fn closed(&self) -> Arc<Notify> {
        Arc::clone(&self.pty_closed)
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

    fn poll_output_until(rx: &mut broadcast::Receiver<Bytes>, marker: &str) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut collected = String::new();
        while std::time::Instant::now() < deadline {
            match rx.try_recv() {
                Ok(chunk) => {
                    collected.push_str(&String::from_utf8_lossy(&chunk));
                    if collected.contains(marker) {
                        break;
                    }
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        collected
    }

    #[test]
    fn spawn_echo_and_read_output() {
        let mut session = PtySession::open_command(24, 80, "echo", &["hello_pty"]).unwrap();
        let mut rx = session.subscribe_output();
        let collected = poll_output_until(&mut rx, "hello_pty");
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

        let collected = poll_output_until(&mut rx, "test_input");
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

        let c1 = poll_output_until(&mut rx1, "multi_sub");
        let c2 = poll_output_until(&mut rx2, "multi_sub");
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

    #[test]
    fn open_with_env_spawns_shell() {
        let env = vec![("TERM".into(), "xterm-256color".into())];
        let _session = PtySession::open_with_env(24, 80, &env).unwrap();
        // Drop immediately kills it — just verify it doesn't error
    }

    #[test]
    fn open_with_env_sets_term() {
        let env = vec![("TERM".into(), "xterm-256color".into())];
        let mut session = PtySession::open_command_with_env(24, 80, "env", &[], &env).unwrap();
        let mut rx = session.subscribe_output();

        let collected = poll_output_until(&mut rx, "TERM=xterm-256color");
        assert!(
            collected.contains("TERM=xterm-256color"),
            "env command should show TERM=xterm-256color, got: {collected:?}"
        );
        session.wait().unwrap();
    }

    #[test]
    fn closed_returns_notify_handle() {
        let session = PtySession::open(4, 20).unwrap();
        let closed = session.closed();
        // PtySession holds one clone, the reader thread holds another, we hold a third
        assert!(std::sync::Arc::strong_count(&closed) >= 2);
    }
}
