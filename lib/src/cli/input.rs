use crossterm::event::{KeyCode, KeyModifiers};

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

/// Converts a crossterm key event to bytes to send to the PTY.
pub(super) fn key_event_to_bytes(key: &crossterm::event::KeyEvent) -> Vec<u8> {
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && let KeyCode::Char(c) = key.code
    {
        let ctrl_byte = (c as u8).wrapping_sub(b'a').wrapping_add(1);
        return vec![ctrl_byte];
    }

    match key.code {
        KeyCode::Char(c) => {
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            s.as_bytes().to_vec()
        }
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Backspace => vec![127],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => b"\x1b[A".to_vec(),
        KeyCode::Down => b"\x1b[B".to_vec(),
        KeyCode::Right => b"\x1b[C".to_vec(),
        KeyCode::Left => b"\x1b[D".to_vec(),
        KeyCode::Home => b"\x1b[H".to_vec(),
        KeyCode::End => b"\x1b[F".to_vec(),
        KeyCode::PageUp => b"\x1b[5~".to_vec(),
        KeyCode::PageDown => b"\x1b[6~".to_vec(),
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::Insert => b"\x1b[2~".to_vec(),
        KeyCode::F(n) => f_key_escape(n),
        _ => vec![],
    }
}

/// Returns the escape sequence for a function key.
pub(super) fn f_key_escape(n: u8) -> Vec<u8> {
    match n {
        1 => b"\x1bOP".to_vec(),
        2 => b"\x1bOQ".to_vec(),
        3 => b"\x1bOR".to_vec(),
        4 => b"\x1bOS".to_vec(),
        5 => b"\x1b[15~".to_vec(),
        6 => b"\x1b[17~".to_vec(),
        7 => b"\x1b[18~".to_vec(),
        8 => b"\x1b[19~".to_vec(),
        9 => b"\x1b[20~".to_vec(),
        10 => b"\x1b[21~".to_vec(),
        11 => b"\x1b[23~".to_vec(),
        12 => b"\x1b[24~".to_vec(),
        _ => vec![],
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    macro_rules! assert_key {
        ($code:expr, $expected:expr) => {
            assert_eq!(
                key_event_to_bytes(&crossterm::event::KeyEvent::new($code, KeyModifiers::NONE,)),
                $expected,
            );
        };
    }

    #[test]
    fn key_event_ctrl_modifier() {
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(key_event_to_bytes(&key), vec![3]);
    }

    #[test]
    fn key_event_char_encoding() {
        assert_key!(KeyCode::Char('x'), b"x");
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('\u{1f600}'), KeyModifiers::NONE);
        let bytes = key_event_to_bytes(&key);
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "\u{1f600}");
    }

    #[test]
    fn key_event_special_keys() {
        assert_key!(KeyCode::Enter, vec![b'\r']);
        assert_key!(KeyCode::Backspace, vec![127]);
        assert_key!(KeyCode::Tab, vec![b'\t']);
        assert_key!(KeyCode::Esc, vec![0x1b]);
    }

    #[test]
    fn key_event_arrow_keys() {
        assert_key!(KeyCode::Up, b"\x1b[A");
        assert_key!(KeyCode::Down, b"\x1b[B");
        assert_key!(KeyCode::Right, b"\x1b[C");
        assert_key!(KeyCode::Left, b"\x1b[D");
    }

    #[test]
    fn key_event_navigation_keys() {
        assert_key!(KeyCode::Home, b"\x1b[H");
        assert_key!(KeyCode::End, b"\x1b[F");
        assert_key!(KeyCode::PageUp, b"\x1b[5~");
        assert_key!(KeyCode::PageDown, b"\x1b[6~");
        assert_key!(KeyCode::Delete, b"\x1b[3~");
        assert_key!(KeyCode::Insert, b"\x1b[2~");
    }

    #[test]
    fn key_event_function_keys() {
        assert_key!(KeyCode::F(1), b"\x1bOP");
        assert_eq!(f_key_escape(2), b"\x1bOQ");
        assert_eq!(f_key_escape(3), b"\x1bOR");
        assert_eq!(f_key_escape(4), b"\x1bOS");
        assert_eq!(f_key_escape(5), b"\x1b[15~");
        assert_eq!(f_key_escape(6), b"\x1b[17~");
        assert_eq!(f_key_escape(7), b"\x1b[18~");
        assert_eq!(f_key_escape(8), b"\x1b[19~");
        assert_eq!(f_key_escape(9), b"\x1b[20~");
        assert_eq!(f_key_escape(10), b"\x1b[21~");
        assert_eq!(f_key_escape(11), b"\x1b[23~");
        assert_eq!(f_key_escape(12), b"\x1b[24~");
        assert_eq!(f_key_escape(13), Vec::<u8>::new());
    }

    #[test]
    fn key_event_unknown_returns_empty() {
        assert_key!(KeyCode::Null, Vec::<u8>::new());
    }
}
