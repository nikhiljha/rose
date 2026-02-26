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
    use super::*;

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
