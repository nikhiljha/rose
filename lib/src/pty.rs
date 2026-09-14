//! PTY management using portable-pty.
//!
//! The server spawns a shell (or command) in a PTY and reads/writes to it.
//! By default, spawns the user's login shell.

use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use portable_pty::{Child, CommandBuilder, ExitStatus, MasterPty, PtySize};
use tokio::sync::{Notify, broadcast};

use crate::input::ServerInput;
use crate::terminal::RoseTerminal;

struct PtyWriter(Arc<Mutex<Box<dyn std::io::Write + Send>>>);

impl std::io::Write for PtyWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("writer lock poisoned")
            .write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().expect("writer lock poisoned").flush()
    }
}

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
    input: OnceLock<ServerInput>,
    master: Box<dyn MasterPty + Send>,
    child: Option<Box<dyn Child + Send + Sync>>,
    output_tx: broadcast::Sender<Bytes>,
    /// The initial broadcast receiver, created before the reader thread
    /// starts.  Handed to the first caller of [`subscribe_output`] so it
    /// receives all output from the very start of the PTY — avoiding a
    /// race where a fast command (e.g. `echo`) completes before the
    /// caller has a chance to subscribe.
    initial_rx: Mutex<Option<broadcast::Receiver<Bytes>>>,
    /// Notified when the PTY reader thread exits (shell closed).
    pty_closed: Arc<Notify>,
    terminal: Option<Arc<Mutex<RoseTerminal>>>,
    _reader_handle: std::thread::JoinHandle<()>,
}

impl PtySession {
    /// Returns the persistent, ordered input writer for this PTY.
    pub(crate) fn input(&self) -> ServerInput {
        self.input
            .get_or_init(|| ServerInput::new(Arc::clone(&self.writer)))
            .clone()
    }

    /// Opens a PTY with the user's default login shell.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Open` if the PTY cannot be created, or
    /// `PtyError::Spawn` if the shell cannot be started.
    pub fn open(rows: u16, cols: u16) -> Result<Self, PtyError> {
        Self::open_internal(rows, cols, CommandBuilder::new_default_prog(), false)
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
        Self::open_internal(rows, cols, builder, false)
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
        Self::open_internal(rows, cols, builder, false)
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
        Self::open_internal(rows, cols, builder, false)
    }

    /// Opens a command with an authoritative terminal that consumes every PTY
    /// byte before broadcasting output, independently of network subscribers.
    /// Emulator responses are written back to the PTY.
    ///
    /// # Errors
    ///
    /// Returns an error if opening the PTY or spawning the command fails.
    pub fn open_terminal(rows: u16, cols: u16, cmd: CommandBuilder) -> Result<Self, PtyError> {
        Self::open_internal(rows, cols, cmd, true)
    }

    /// Returns the authoritative emulator created by [`Self::open_terminal`].
    #[must_use]
    pub const fn terminal(&self) -> Option<&Arc<Mutex<RoseTerminal>>> {
        self.terminal.as_ref()
    }

    fn open_internal(
        rows: u16,
        cols: u16,
        cmd: CommandBuilder,
        emulate: bool,
    ) -> Result<Self, PtyError> {
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
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| PtyError::Io(std::io::Error::other(e.to_string())))?;
        let writer = Arc::new(Mutex::new(writer));
        let terminal = emulate.then(|| {
            Arc::new(Mutex::new(RoseTerminal::with_writer(
                rows,
                cols,
                Box::new(PtyWriter(Arc::clone(&writer))),
            )))
        });
        let terminal_output = terminal.clone();

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
                        if let Some(terminal) = &terminal_output {
                            terminal
                                .lock()
                                .expect("terminal lock poisoned")
                                .advance(&buf[..n]);
                        }
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
            input: OnceLock::new(),
            master: pair.master,
            child: Some(child),
            output_tx,
            initial_rx: Mutex::new(Some(initial_rx)),
            pty_closed,
            terminal,
            _reader_handle: reader_handle,
        })
    }

    /// Subscribes to PTY output.
    ///
    /// The **first** call returns a receiver created before the reader
    /// thread started. Subsequent calls only see output produced after
    /// the call. All receivers can lag and lose bytes; when opened with
    /// [`Self::open_terminal`], the authoritative emulator always consumes
    /// output before it reaches this lossy observer channel.
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
    ///
    /// # Panics
    ///
    /// Panics if child ownership was already transferred during destruction.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, PtyError> {
        self.child
            .as_mut()
            .expect("child present until drop")
            .try_wait()
            .map_err(PtyError::Io)
    }

    /// Blocks until the child process exits.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Io` if the wait fails.
    ///
    /// # Panics
    ///
    /// Panics if child ownership was already transferred during destruction.
    pub fn wait(&mut self) -> Result<ExitStatus, PtyError> {
        self.child
            .as_mut()
            .expect("child present until drop")
            .wait()
            .map_err(PtyError::Io)
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take()
            && !matches!(child.try_wait(), Ok(Some(_)))
        {
            std::thread::spawn(move || {
                let _ = child.kill();
                let _ = child.wait();
            });
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::time::Duration;

    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dropping_a_session_reaps_its_exited_child() {
        let pty = PtySession::open_command(5, 20, "sh", &["-c", "exit"]).unwrap();
        let pid = pty.child.as_ref().unwrap().process_id().unwrap();
        let process = std::path::PathBuf::from(format!("/proc/{pid}"));
        tokio::time::timeout(Duration::from_secs(5), pty.closed().notified())
            .await
            .unwrap();
        drop(pty);
        tokio::time::timeout(Duration::from_secs(2), async {
            while process.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("exited PTY child was not reaped");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dropping_a_session_reaps_a_child_that_ignores_hangup() {
        let pty = PtySession::open_command(
            5,
            20,
            "sh",
            &["-c", "trap '' HUP; printf READY; while :; do sleep 1; done"],
        )
        .unwrap();
        let process = std::path::PathBuf::from(format!(
            "/proc/{}",
            pty.child.as_ref().unwrap().process_id().unwrap()
        ));
        assert!(poll_output_until(&mut pty.subscribe_output(), "READY").contains("READY"));
        drop(pty);
        tokio::time::timeout(Duration::from_secs(2), async {
            while process.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("running PTY child was not killed and reaped");
    }

    #[tokio::test]
    async fn unread_terminal_replies_do_not_block_output_or_resize() {
        let mut command = CommandBuilder::new("sh");
        command.args([
            "-c",
            "stty raw -echo; i=0; while [ \"$i\" -lt 20000 ]; do \
             printf '\\033[6n'; i=$((i+1)); done; printf OUTPUT_COMPLETE; \
             while :; do sleep 1; done",
        ]);
        let pty = PtySession::open_terminal(5, 20, command).unwrap();
        let mut observer = pty.subscribe_output();
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut output = String::new();
            while !output.contains("OUTPUT_COMPLETE") {
                match observer.recv().await {
                    Ok(chunk) => output.push_str(&String::from_utf8_lossy(&chunk)),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => panic!("PTY closed"),
                }
            }
        })
        .await
        .expect("PTY output stopped while the child was not reading replies");
        let mut terminal = pty.terminal().unwrap().try_lock().unwrap();
        assert_eq!(terminal.snapshot().rows[0], "OUTPUT_COMPLETE");
        pty.resize(8, 40).unwrap();
        terminal.resize(8, 40);
        assert_eq!(terminal.snapshot().rows.len(), 8);
    }

    #[tokio::test]
    async fn terminal_state_survives_a_lagging_output_observer() {
        let mut command = CommandBuilder::new("sh");
        command.args([
            "-c",
            "printf '\\033[31m'; head -c 20000000 /dev/zero; printf RED",
        ]);
        let pty = PtySession::open_terminal(5, 20, command).unwrap();
        let mut observer = pty.subscribe_output();
        tokio::time::timeout(Duration::from_secs(20), pty.closed().notified())
            .await
            .expect("PTY did not drain");
        assert!(matches!(
            observer.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(_))
        ));
        let mut expected = RoseTerminal::new(5, 20);
        expected.advance(b"\x1b[31mRED");
        assert_eq!(
            pty.terminal().unwrap().lock().unwrap().snapshot(),
            expected.snapshot()
        );
    }

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
