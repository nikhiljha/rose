use std::io::Write;
use std::sync::{Arc, Mutex};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use crate::input::{InputBuffer, InputError};

const MAX_KEY_LOOKAHEAD: usize = 128;
const MAX_KEY_BYTES: usize = 32;

pub(super) fn read_keyboard_events(sender: tokio::sync::mpsc::Sender<Event>) {
    while let Ok(event) = crossterm::event::read() {
        if sender.blocking_send(event).is_err() {
            break;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InputAction {
    Disconnect,
    Detach,
}

#[derive(Clone)]
pub(super) struct KeyboardInput {
    pub(super) buffer: InputBuffer,
    events: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Event>>>,
    state: Arc<Mutex<KeyboardState>>,
}

struct KeyboardState {
    escape: EscapeState,
    action: Option<InputAction>,
    pending: Vec<u8>,
}

impl KeyboardInput {
    pub(super) fn new(events: tokio::sync::mpsc::Receiver<Event>) -> Self {
        Self {
            buffer: InputBuffer::default(),
            events: Arc::new(tokio::sync::Mutex::new(events)),
            state: Arc::new(Mutex::new(KeyboardState {
                escape: EscapeState::Normal,
                action: None,
                pending: Vec::new(),
            })),
        }
    }

    pub(super) async fn next(&self) -> Result<Option<InputAction>, InputError> {
        let mut events = self.events.lock().await;
        let mut consumed = false;
        loop {
            let (pending, action) = {
                let mut state = self.state.lock().expect("keyboard lock poisoned");
                if !state.pending.is_empty() {
                    match self.buffer.push(&state.pending) {
                        Ok(()) => state.pending.clear(),
                        Err(InputError::Full) => {}
                        Err(error) => return Err(error),
                    }
                }
                (state.pending.len(), state.action)
            };
            if let Some(action) = action {
                if action == InputAction::Detach {
                    if pending > 0 {
                        self.buffer.wait_for_capacity(pending).await;
                        continue;
                    }
                    self.buffer
                        .wait_for_capacity(crate::input::MAX_PENDING_INPUT)
                        .await;
                }
                return Ok(Some(action));
            }
            if consumed {
                return Ok(None);
            }
            if pending > MAX_KEY_LOOKAHEAD - MAX_KEY_BYTES {
                self.buffer.wait_for_capacity(pending).await;
                continue;
            }
            let event = tokio::select! {
                event = events.recv() => event,
                () = self.buffer.wait_for_capacity(pending), if pending > 0 => continue,
            };
            let mut state = self.state.lock().expect("keyboard lock poisoned");
            state.action = match event {
                Some(Event::Key(key)) => process_key(&key, &mut state),
                None => Some(InputAction::Disconnect),
                Some(_) => None,
            };
            consumed = true;
        }
    }
}

fn process_key(key: &KeyEvent, state: &mut KeyboardState) -> Option<InputAction> {
    let bytes = key_event_to_bytes(key);
    if bytes.is_empty() {
        return None;
    }
    let escape = &mut state.escape;
    let pending = &mut state.pending;
    match escape {
        EscapeState::Normal => {
            pending.extend_from_slice(&bytes);
            if key.code == KeyCode::Enter {
                *escape = EscapeState::AfterEnter;
            }
        }
        EscapeState::AfterEnter => {
            if key.code == KeyCode::Char('~') {
                *escape = EscapeState::AfterTilde;
            } else {
                pending.extend_from_slice(&bytes);
                if key.code != KeyCode::Enter {
                    *escape = EscapeState::Normal;
                }
            }
        }
        EscapeState::AfterTilde => {
            *escape = EscapeState::Normal;
            match key.code {
                KeyCode::Char('.') => return Some(InputAction::Disconnect),
                KeyCode::Char('d') => return Some(InputAction::Detach),
                KeyCode::Char('~') => pending.push(b'~'),
                KeyCode::Char('?') => {
                    let mut stdout = std::io::stdout();
                    let _ = stdout.write_all(
                        b"\r\nSupported escape sequences:\r\n\
                          \x20 ~.  - disconnect\r\n\
                          \x20 ~d  - detach (session stays alive)\r\n\
                          \x20 ~~  - send literal ~\r\n\
                          \x20 ~?  - this help\r\n",
                    );
                    let _ = stdout.flush();
                }
                _ => {
                    pending.push(b'~');
                    pending.extend_from_slice(&bytes);
                }
            }
        }
    }
    None
}

/// SSH-style escape sequence state machine.
///
/// Detects `Enter ~ .` to disconnect, `Enter ~ ~` to send literal `~`,
/// and `Enter ~ ?` for help.
pub(super) enum EscapeState {
    /// No escape sequence in progress.
    Normal,
    /// Enter was just pressed — `~` would start an escape.
    AfterEnter,
    /// Enter + `~` were pressed — waiting for `.`, `~`, or `?`.
    AfterTilde,
}

/// Computes the xterm-style modifier parameter from crossterm key modifiers.
///
/// The encoding is `1 + sum` where Shift=1, Alt=2, Ctrl=4. Returns `0` when
/// no modifiers are active (caller should omit the parameter in that case).
const fn modifier_param(mods: KeyModifiers) -> u8 {
    let mut param: u8 = 0;
    if mods.contains(KeyModifiers::SHIFT) {
        param += 1;
    }
    if mods.contains(KeyModifiers::ALT) {
        param += 2;
    }
    if mods.contains(KeyModifiers::CONTROL) {
        param += 4;
    }
    if param > 0 { param + 1 } else { 0 }
}

/// Builds a CSI final-byte sequence with an optional modifier parameter.
///
/// Without modifiers: `ESC [ final_byte`
/// With modifiers:    `ESC [ 1 ; mod final_byte`
fn csi_key(final_byte: u8, mods: KeyModifiers) -> Vec<u8> {
    let m = modifier_param(mods);
    if m == 0 {
        vec![0x1b, b'[', final_byte]
    } else {
        format!("\x1b[1;{m}{}", final_byte as char).into_bytes()
    }
}

/// Builds a CSI tilde-style sequence with an optional modifier parameter.
///
/// Without modifiers: `ESC [ code ~`
/// With modifiers:    `ESC [ code ; mod ~`
fn csi_tilde(code: &str, mods: KeyModifiers) -> Vec<u8> {
    let m = modifier_param(mods);
    if m == 0 {
        format!("\x1b[{code}~").into_bytes()
    } else {
        format!("\x1b[{code};{m}~").into_bytes()
    }
}

/// Converts a crossterm key event to bytes to send to the PTY.
///
/// Encodes modifier keys (Shift, Alt, Ctrl) on special keys using the standard
/// xterm modifier parameter encoding. This is compatible with the kitty
/// keyboard protocol and allows applications to distinguish modified keys.
pub(super) fn key_event_to_bytes(key: &crossterm::event::KeyEvent) -> Vec<u8> {
    // Ctrl+letter maps to ASCII control codes (0x01-0x1a).
    // With the kitty keyboard protocol enabled, crossterm may report uppercase
    // characters for Ctrl+Shift+letter, so we normalize to lowercase first.
    // Alt+Ctrl+letter prepends ESC before the control byte.
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && let KeyCode::Char(c) = key.code
        && c.is_ascii_alphabetic()
    {
        let ctrl_byte = (c.to_ascii_lowercase() as u8)
            .wrapping_sub(b'a')
            .wrapping_add(1);
        if key.modifiers.contains(KeyModifiers::ALT) {
            return vec![0x1b, ctrl_byte];
        }
        return vec![ctrl_byte];
    }

    // Ctrl+punctuation in the 0x40-0x5F range maps to control codes via (c & 0x1F).
    // With the kitty keyboard protocol enabled, crossterm reports these as explicit
    // Char events (e.g. Ctrl+[ becomes Char('[') + CONTROL instead of KeyCode::Esc).
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && let KeyCode::Char(c) = key.code
    {
        let b = c as u32;
        if (0x40..=0x5f).contains(&b) {
            let ctrl_byte = (b as u8) & 0x1f;
            if key.modifiers.contains(KeyModifiers::ALT) {
                return vec![0x1b, ctrl_byte];
            }
            return vec![ctrl_byte];
        }
    }

    match key.code {
        KeyCode::Char(c) => {
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            let char_bytes = s.as_bytes();
            // Alt+char: prefix ESC before the character bytes.
            // With kitty keyboard protocol, Alt+char arrives as a structured
            // KeyEvent with ALT modifier instead of terminal-emitted ESC prefix.
            if key.modifiers.contains(KeyModifiers::ALT) {
                let mut result = Vec::with_capacity(1 + char_bytes.len());
                result.push(0x1b);
                result.extend_from_slice(char_bytes);
                return result;
            }
            char_bytes.to_vec()
        }
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Backspace => vec![127],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => csi_key(b'A', key.modifiers),
        KeyCode::Down => csi_key(b'B', key.modifiers),
        KeyCode::Right => csi_key(b'C', key.modifiers),
        KeyCode::Left => csi_key(b'D', key.modifiers),
        KeyCode::Home => csi_key(b'H', key.modifiers),
        KeyCode::End => csi_key(b'F', key.modifiers),
        KeyCode::PageUp => csi_tilde("5", key.modifiers),
        KeyCode::PageDown => csi_tilde("6", key.modifiers),
        KeyCode::Delete => csi_tilde("3", key.modifiers),
        KeyCode::Insert => csi_tilde("2", key.modifiers),
        KeyCode::F(n) => f_key_escape(n, key.modifiers),
        _ => vec![],
    }
}

/// Returns the escape sequence for a function key with optional modifiers.
///
/// F1-F4 use SS3 encoding without modifiers (`ESC O P`..`ESC O S`) but switch
/// to CSI encoding with a modifier parameter when modified (`ESC [ 1 ; mod P`).
/// F5-F12 always use CSI tilde-style encoding.
pub(super) fn f_key_escape(n: u8, mods: KeyModifiers) -> Vec<u8> {
    let m = modifier_param(mods);
    // F1-F4: SS3 without modifiers, CSI with modifiers
    match n {
        1..=4 => {
            let final_byte = b'P' + n - 1;
            if m == 0 {
                vec![0x1b, b'O', final_byte]
            } else {
                format!("\x1b[1;{m}{}", final_byte as char).into_bytes()
            }
        }
        5 => csi_tilde("15", mods),
        6 => csi_tilde("17", mods),
        7 => csi_tilde("18", mods),
        8 => csi_tilde("19", mods),
        9 => csi_tilde("20", mods),
        10 => csi_tilde("21", mods),
        11 => csi_tilde("23", mods),
        12 => csi_tilde("24", mods),
        _ => vec![],
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::io::Read;
    use std::time::{Duration, Instant};

    use super::*;

    #[tokio::test]
    async fn detach_survives_cancellation_and_waits_for_prior_keys() {
        let (send, receive) = tokio::sync::mpsc::channel(16);
        let keyboard = KeyboardInput::new(receive);
        for code in [
            KeyCode::Enter,
            KeyCode::Char('~'),
            KeyCode::Char('?'),
            KeyCode::Enter,
            KeyCode::Char('~'),
            KeyCode::Char('~'),
            KeyCode::Enter,
            KeyCode::Char('~'),
            KeyCode::Char('x'),
            KeyCode::Enter,
            KeyCode::Char('~'),
            KeyCode::Char('d'),
        ] {
            send.send(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)))
                .await
                .unwrap();
        }
        for _ in 0..11 {
            assert_eq!(keyboard.next().await.unwrap(), None);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), keyboard.next())
                .await
                .is_err()
        );
        let file = tempfile::NamedTempFile::new().unwrap();
        let input =
            crate::input::ServerInput::new(Arc::new(Mutex::new(Box::new(file.reopen().unwrap()))));
        let connection =
            crate::testutil::InputConnection::new(input, keyboard.buffer.clone()).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), keyboard.next())
                .await
                .unwrap()
                .unwrap(),
            Some(InputAction::Detach)
        );
        assert_eq!(std::fs::read(file.path()).unwrap(), b"\r\r~\r~x\r");
        connection.close().await;
    }

    #[tokio::test]
    async fn explicit_disconnect_does_not_wait_for_input_acknowledgments() {
        let (send, receive) = tokio::sync::mpsc::channel(8);
        let keyboard = KeyboardInput::new(receive);
        for code in [KeyCode::Enter, KeyCode::Char('~'), KeyCode::Char('.')] {
            send.send(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)))
                .await
                .unwrap();
        }
        assert_eq!(keyboard.next().await.unwrap(), None);
        assert_eq!(keyboard.next().await.unwrap(), None);
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), keyboard.next())
                .await
                .unwrap()
                .unwrap(),
            Some(InputAction::Disconnect)
        );
    }

    #[test]
    fn terminal_reader_drains_large_pastes_without_another_key() {
        const CAPTURE: &str = "ROSE_TEST_INPUT_CAPTURE";
        const LENGTH: usize = 80 * 1024;
        if let Some(path) = std::env::var_os(CAPTURE) {
            crossterm::terminal::enable_raw_mode().unwrap();
            let (send, mut receive) = tokio::sync::mpsc::channel(128);
            std::thread::spawn(move || read_keyboard_events(send));
            println!("INPUT_READER_READY");
            std::io::stdout().flush().unwrap();
            let mut bytes = Vec::new();
            while bytes.len() < LENGTH {
                if let Event::Key(key) = receive.blocking_recv().unwrap() {
                    bytes.extend(key_event_to_bytes(&key));
                }
            }
            std::fs::write(path, bytes).unwrap();
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let capture = directory.path().join("input");
        let pair = portable_pty::native_pty_system()
            .openpty(portable_pty::PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let mut command = portable_pty::CommandBuilder::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "cli::input::tests::terminal_reader_drains_large_pastes_without_another_key",
            "--nocapture",
        ]);
        command.env(CAPTURE, &capture);
        let mut child = pair.slave.spawn_command(command).unwrap();
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().unwrap();
        let (output, receive) = std::sync::mpsc::channel();
        let reading = std::thread::spawn(move || {
            let mut bytes = [0; 4096];
            while let Ok(length) = reader.read(&mut bytes) {
                if length == 0 || output.send(bytes[..length].to_vec()).is_err() {
                    break;
                }
            }
        });
        let mut writer = pair.master.take_writer().unwrap();
        let payload: Vec<u8> = (0..LENGTH).map(|i| b'a' + (i % 26) as u8).collect();
        let expected = payload.clone();
        let mut writing = None;
        let mut output = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(bytes) = receive.recv_timeout(Duration::from_millis(50)) {
                output.extend(bytes);
            }
            if writing.is_none() && output.windows(18).any(|s| s == b"INPUT_READER_READY") {
                writing = Some(std::thread::spawn(move || writer.write_all(&payload)));
                break;
            }
        }
        while Instant::now() < deadline && child.try_wait().unwrap().is_none() {
            let _ = receive.recv_timeout(Duration::from_millis(50));
        }
        let exited = child.try_wait().unwrap().is_some();
        if !exited {
            child.kill().unwrap();
        }
        let status = child.wait().unwrap();
        reading.join().unwrap();
        assert!(exited, "terminal reader stalled without another key");
        if let Some(writing) = writing {
            let _ = writing.join().unwrap();
        }
        assert!(status.success());
        assert_eq!(std::fs::read(capture).unwrap(), expected);
    }

    #[tokio::test]
    async fn full_input_still_accepts_local_disconnect() {
        for free in [31, 0] {
            let (send, receive) = tokio::sync::mpsc::channel(8);
            let keyboard = KeyboardInput::new(receive);
            keyboard
                .buffer
                .push(&vec![b'a'; crate::input::MAX_PENDING_INPUT - free])
                .unwrap();
            for code in [
                KeyCode::Char('x'),
                KeyCode::Enter,
                KeyCode::Char('~'),
                KeyCode::Char('.'),
            ] {
                send.send(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)))
                    .await
                    .unwrap();
            }
            assert_eq!(
                tokio::time::timeout(Duration::from_millis(100), async {
                    loop {
                        if let Some(action) = keyboard.next().await.unwrap() {
                            break action;
                        }
                    }
                })
                .await
                .expect("retained input blocked the local disconnect"),
                InputAction::Disconnect
            );
        }
    }

    #[tokio::test]
    async fn backpressured_keys_survive_cancellation_and_flush_before_detach() {
        let (send, receive) = tokio::sync::mpsc::channel(256);
        let keyboard = KeyboardInput::new(receive);
        let prefix = vec![b'a'; crate::input::MAX_PENDING_INPUT];
        keyboard.buffer.push(&prefix).unwrap();
        for code in std::iter::repeat_n(KeyCode::Char('x'), 128).chain([
            KeyCode::Enter,
            KeyCode::Char('~'),
            KeyCode::Char('~'),
            KeyCode::Enter,
            KeyCode::Char('~'),
            KeyCode::Char('d'),
        ]) {
            send.send(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)))
                .await
                .unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), async {
                loop {
                    assert_eq!(keyboard.next().await.unwrap(), None);
                }
            })
            .await
            .is_err()
        );
        let queued = keyboard.events.lock().await.len();
        assert!(queued > 0 && queued < 134, "lookahead must be bounded");

        let file = tempfile::NamedTempFile::new().unwrap();
        let input =
            crate::input::ServerInput::new(Arc::new(Mutex::new(Box::new(file.reopen().unwrap()))));
        let connection =
            crate::testutil::InputConnection::new(input, keyboard.buffer.clone()).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(action) = keyboard.next().await.unwrap() {
                        break action;
                    }
                }
            })
            .await
            .unwrap(),
            InputAction::Detach
        );
        assert_eq!(
            std::fs::read(file.path()).unwrap(),
            [prefix.as_slice(), &[b'x'; 128], b"\r~\r"].concat()
        );
        connection.close().await;
    }

    #[test]
    fn key_event_ctrl_c() {
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&key), vec![3]); // Ctrl+C = 0x03
    }

    #[test]
    fn key_event_ctrl_a() {
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&key), vec![1]); // Ctrl+A = 0x01
    }

    #[test]
    fn key_event_char_encoding() {
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE);
        assert_eq!(key_event_to_bytes(&key), b"x");
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('\u{1f600}'), KeyModifiers::NONE);
        let bytes = key_event_to_bytes(&key);
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "\u{1f600}");
    }

    #[test]
    fn key_event_special_keys() {
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE
            )),
            vec![b'\r']
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Backspace,
                KeyModifiers::NONE
            )),
            vec![127]
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Tab,
                KeyModifiers::NONE
            )),
            vec![b'\t']
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Esc,
                KeyModifiers::NONE
            )),
            vec![0x1b]
        );
    }

    #[test]
    fn key_event_arrow_keys() {
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Up,
                KeyModifiers::NONE
            )),
            b"\x1b[A"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Down,
                KeyModifiers::NONE
            )),
            b"\x1b[B"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Right,
                KeyModifiers::NONE
            )),
            b"\x1b[C"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Left,
                KeyModifiers::NONE
            )),
            b"\x1b[D"
        );
    }

    #[test]
    fn key_event_navigation_keys() {
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Home,
                KeyModifiers::NONE
            )),
            b"\x1b[H"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::End,
                KeyModifiers::NONE
            )),
            b"\x1b[F"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::PageUp,
                KeyModifiers::NONE
            )),
            b"\x1b[5~"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::PageDown,
                KeyModifiers::NONE
            )),
            b"\x1b[6~"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Delete,
                KeyModifiers::NONE
            )),
            b"\x1b[3~"
        );
        assert_eq!(
            key_event_to_bytes(&crossterm::event::KeyEvent::new(
                KeyCode::Insert,
                KeyModifiers::NONE
            )),
            b"\x1b[2~"
        );
    }

    #[test]
    fn key_event_function_keys() {
        assert_eq!(f_key_escape(1, KeyModifiers::NONE), b"\x1bOP");
        assert_eq!(f_key_escape(2, KeyModifiers::NONE), b"\x1bOQ");
        assert_eq!(f_key_escape(3, KeyModifiers::NONE), b"\x1bOR");
        assert_eq!(f_key_escape(4, KeyModifiers::NONE), b"\x1bOS");
        assert_eq!(f_key_escape(5, KeyModifiers::NONE), b"\x1b[15~");
        assert_eq!(f_key_escape(6, KeyModifiers::NONE), b"\x1b[17~");
        assert_eq!(f_key_escape(7, KeyModifiers::NONE), b"\x1b[18~");
        assert_eq!(f_key_escape(8, KeyModifiers::NONE), b"\x1b[19~");
        assert_eq!(f_key_escape(9, KeyModifiers::NONE), b"\x1b[20~");
        assert_eq!(f_key_escape(10, KeyModifiers::NONE), b"\x1b[21~");
        assert_eq!(f_key_escape(11, KeyModifiers::NONE), b"\x1b[23~");
        assert_eq!(f_key_escape(12, KeyModifiers::NONE), b"\x1b[24~");
        assert_eq!(f_key_escape(13, KeyModifiers::NONE), Vec::<u8>::new());
    }

    #[test]
    fn key_event_unknown_returns_empty() {
        let key = crossterm::event::KeyEvent::new(KeyCode::Null, KeyModifiers::NONE);
        assert!(key_event_to_bytes(&key).is_empty());
    }

    #[test]
    fn key_event_f_key_via_key_event() {
        let key = crossterm::event::KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE);
        assert_eq!(key_event_to_bytes(&key), b"\x1bOP");
    }

    #[test]
    fn key_event_backtab() {
        // Shift+Tab should send CSI Z (backtab escape sequence)
        let key = crossterm::event::KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT);
        assert_eq!(key_event_to_bytes(&key), b"\x1b[Z");
    }

    #[test]
    fn key_event_shift_up() {
        // Shift+Up should encode modifier parameter: \x1b[1;2A
        let key = crossterm::event::KeyEvent::new(KeyCode::Up, KeyModifiers::SHIFT);
        assert_eq!(key_event_to_bytes(&key), b"\x1b[1;2A");
    }

    #[test]
    fn key_event_alt_right() {
        // Alt+Right should encode modifier parameter: \x1b[1;3C
        let key = crossterm::event::KeyEvent::new(KeyCode::Right, KeyModifiers::ALT);
        assert_eq!(key_event_to_bytes(&key), b"\x1b[1;3C");
    }

    #[test]
    fn key_event_ctrl_left() {
        // Ctrl+Left should encode modifier parameter: \x1b[1;5D
        let key = crossterm::event::KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&key), b"\x1b[1;5D");
    }

    #[test]
    fn key_event_shift_ctrl_end() {
        // Shift+Ctrl+End should encode modifier parameter: \x1b[1;6F
        let key = crossterm::event::KeyEvent::new(
            KeyCode::End,
            KeyModifiers::SHIFT | KeyModifiers::CONTROL,
        );
        assert_eq!(key_event_to_bytes(&key), b"\x1b[1;6F");
    }

    #[test]
    fn key_event_shift_delete() {
        // Shift+Delete should encode modifier in tilde-style: \x1b[3;2~
        let key = crossterm::event::KeyEvent::new(KeyCode::Delete, KeyModifiers::SHIFT);
        assert_eq!(key_event_to_bytes(&key), b"\x1b[3;2~");
    }

    #[test]
    fn key_event_ctrl_pageup() {
        // Ctrl+PageUp should encode modifier in tilde-style: \x1b[5;5~
        let key = crossterm::event::KeyEvent::new(KeyCode::PageUp, KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&key), b"\x1b[5;5~");
    }

    #[test]
    fn key_event_shift_f1() {
        // Shift+F1 should convert SS3 to CSI with modifier: \x1b[1;2P
        let key = crossterm::event::KeyEvent::new(KeyCode::F(1), KeyModifiers::SHIFT);
        assert_eq!(key_event_to_bytes(&key), b"\x1b[1;2P");
    }

    #[test]
    fn key_event_ctrl_f5() {
        // Ctrl+F5 should encode modifier in tilde-style: \x1b[15;5~
        let key = crossterm::event::KeyEvent::new(KeyCode::F(5), KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&key), b"\x1b[15;5~");
    }

    #[test]
    fn key_event_shift_insert() {
        // Shift+Insert should encode modifier in tilde-style: \x1b[2;2~
        let key = crossterm::event::KeyEvent::new(KeyCode::Insert, KeyModifiers::SHIFT);
        assert_eq!(key_event_to_bytes(&key), b"\x1b[2;2~");
    }

    #[test]
    fn key_event_ctrl_shift_letter_normalizes_case() {
        // Kitty keyboard protocol reports Ctrl+Shift+C as uppercase 'C' with
        // CONTROL|SHIFT modifiers. Must normalize to lowercase before computing
        // the control byte, otherwise we get garbage (0xE3 instead of 0x03).
        let key = crossterm::event::KeyEvent::new(
            KeyCode::Char('C'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        );
        assert_eq!(key_event_to_bytes(&key), vec![3]); // Ctrl+C = 0x03
    }

    #[test]
    fn key_event_ctrl_bracket_sends_esc() {
        // With the kitty keyboard protocol, Ctrl+[ is reported as Char('[') with
        // CONTROL modifier. It should still produce ESC (0x1b).
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('['), KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&key), vec![0x1b]);
    }

    #[test]
    fn key_event_ctrl_backslash_sends_fs() {
        // Ctrl+\\ -> FS (0x1c)
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('\\'), KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&key), vec![0x1c]);
    }

    #[test]
    fn key_event_ctrl_close_bracket_sends_gs() {
        // Ctrl+] -> GS (0x1d)
        let key = crossterm::event::KeyEvent::new(KeyCode::Char(']'), KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&key), vec![0x1d]);
    }

    #[test]
    fn key_event_alt_char() {
        // Alt+x should send ESC followed by 'x' (0x1b 0x78)
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT);
        assert_eq!(key_event_to_bytes(&key), b"\x1bx");
    }

    #[test]
    fn key_event_alt_uppercase_char() {
        // Alt+Shift+A (reported as Alt + 'A') should send ESC followed by 'A'
        let key = crossterm::event::KeyEvent::new(
            KeyCode::Char('A'),
            KeyModifiers::ALT | KeyModifiers::SHIFT,
        );
        assert_eq!(key_event_to_bytes(&key), b"\x1bA");
    }

    #[test]
    fn key_event_alt_ctrl_letter() {
        // Alt+Ctrl+c should send ESC followed by Ctrl+C (0x1b 0x03)
        let key = crossterm::event::KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::ALT | KeyModifiers::CONTROL,
        );
        assert_eq!(key_event_to_bytes(&key), vec![0x1b, 0x03]);
    }

    #[test]
    fn key_event_alt_ctrl_bracket_sends_esc_esc() {
        // Alt+Ctrl+[ should send ESC ESC (0x1b 0x1b)
        let key = crossterm::event::KeyEvent::new(
            KeyCode::Char('['),
            KeyModifiers::ALT | KeyModifiers::CONTROL,
        );
        assert_eq!(key_event_to_bytes(&key), vec![0x1b, 0x1b]);
    }

    #[test]
    fn key_event_alt_ctrl_backslash() {
        // Alt+Ctrl+\ should send ESC FS (0x1b 0x1c)
        let key = crossterm::event::KeyEvent::new(
            KeyCode::Char('\\'),
            KeyModifiers::ALT | KeyModifiers::CONTROL,
        );
        assert_eq!(key_event_to_bytes(&key), vec![0x1b, 0x1c]);
    }

    #[test]
    fn key_event_alt_ctrl_close_bracket() {
        // Alt+Ctrl+] should send ESC GS (0x1b 0x1d)
        let key = crossterm::event::KeyEvent::new(
            KeyCode::Char(']'),
            KeyModifiers::ALT | KeyModifiers::CONTROL,
        );
        assert_eq!(key_event_to_bytes(&key), vec![0x1b, 0x1d]);
    }

    #[test]
    fn key_event_alt_shift_ctrl_up() {
        // Alt+Shift+Ctrl+Up: modifier = 1 + 1 + 2 + 4 = 8 → \x1b[1;8A
        let key = crossterm::event::KeyEvent::new(
            KeyCode::Up,
            KeyModifiers::SHIFT | KeyModifiers::ALT | KeyModifiers::CONTROL,
        );
        assert_eq!(key_event_to_bytes(&key), b"\x1b[1;8A");
    }
}
