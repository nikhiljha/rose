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

/// Action determined by the escape state machine for a single key event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum KeyAction {
    /// Send the byte sequence to the server and feed it to the predictor.
    SendAndPredict(Vec<u8>),
    /// Send multiple byte sequences (e.g., deferred `~` plus the current key).
    SendMultipleAndPredict(Vec<Vec<u8>>),
    /// User requested disconnect (`Enter ~ .`).
    Disconnect,
    /// User requested detach (`Enter ~ d`).
    Detach,
    /// User requested escape help (`Enter ~ ?`).
    ShowHelp,
    /// Key was consumed by the escape state machine (no action needed).
    Consumed,
}

/// Processes a key event through the escape state machine.
///
/// Returns the action to take. The caller is responsible for sending bytes,
/// predicting, disconnecting, etc. based on the returned action.
///
/// The escape detection uses the actual bytes produced by [`key_event_to_bytes`]
/// rather than raw key codes, so it works correctly regardless of whether the
/// kitty keyboard protocol is active.
pub(super) fn process_key_event(
    escape: &mut EscapeState,
    key: &crossterm::event::KeyEvent,
) -> KeyAction {
    let key_bytes = key_event_to_bytes(key);
    if key_bytes.is_empty() {
        return KeyAction::Consumed;
    }

    match *escape {
        EscapeState::Normal => {
            if key_bytes == [b'\r'] {
                *escape = EscapeState::AfterEnter;
            }
            KeyAction::SendAndPredict(key_bytes)
        }
        EscapeState::AfterEnter => {
            if key_bytes == [b'~'] {
                *escape = EscapeState::AfterTilde;
                KeyAction::Consumed
            } else if key_bytes == [b'\r'] {
                // Another Enter — stay in AfterEnter, send this one.
                KeyAction::SendAndPredict(key_bytes)
            } else {
                *escape = EscapeState::Normal;
                KeyAction::SendAndPredict(key_bytes)
            }
        }
        EscapeState::AfterTilde => {
            *escape = EscapeState::Normal;
            if key_bytes == [b'.'] {
                KeyAction::Disconnect
            } else if key_bytes == [b'd'] {
                KeyAction::Detach
            } else if key_bytes == [b'~'] {
                // `~~` sends a literal tilde.
                KeyAction::SendAndPredict(b"~".to_vec())
            } else if key_bytes == [b'?'] {
                KeyAction::ShowHelp
            } else {
                // Escape abandoned — flush the deferred `~` and the current key.
                KeyAction::SendMultipleAndPredict(vec![b"~".to_vec(), key_bytes])
            }
        }
    }
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
            // With the kitty keyboard protocol, Shift+<key> may be reported as
            // the base (unshifted) character with SHIFT modifier, instead of the
            // actual produced character.  Resolve the shifted character before
            // encoding so both the server and the escape state machine see the
            // correct bytes.
            let resolved = if key.modifiers.contains(KeyModifiers::SHIFT)
                && !key.modifiers.contains(KeyModifiers::CONTROL)
            {
                resolve_shifted_char(c)
            } else {
                c
            };
            let mut buf = [0u8; 4];
            let s = resolved.encode_utf8(&mut buf);
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

/// Resolves the shifted character for a base key on a US keyboard layout.
///
/// With the kitty keyboard protocol, Shift+key may be reported as the
/// unshifted base character plus a SHIFT modifier. This function maps
/// those base characters to their shifted counterparts so that byte
/// encoding and escape-sequence detection work correctly.
const fn resolve_shifted_char(base: char) -> char {
    match base {
        // Letters: lowercase -> uppercase
        c if c.is_ascii_lowercase() => c.to_ascii_uppercase(),
        // Number row
        '`' => '~',
        '1' => '!',
        '2' => '@',
        '3' => '#',
        '4' => '$',
        '5' => '%',
        '6' => '^',
        '7' => '&',
        '8' => '*',
        '9' => '(',
        '0' => ')',
        '-' => '_',
        '=' => '+',
        // Brackets and punctuation
        '[' => '{',
        ']' => '}',
        '\\' => '|',
        ';' => ':',
        '\'' => '"',
        ',' => '<',
        '.' => '>',
        '/' => '?',
        // Already the shifted variant, or not a standard US key
        other => other,
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

    // -----------------------------------------------------------------------
    // resolve_shifted_char / kitty keyboard protocol SHIFT handling
    // -----------------------------------------------------------------------

    #[test]
    fn shift_backtick_produces_tilde() {
        // Kitty protocol: Shift+` reported as Char('`') + SHIFT → should produce ~
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('`'), KeyModifiers::SHIFT);
        assert_eq!(key_event_to_bytes(&key), b"~");
    }

    #[test]
    fn shift_letter_produces_uppercase() {
        // Kitty protocol: Shift+a reported as Char('a') + SHIFT → should produce A
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('a'), KeyModifiers::SHIFT);
        assert_eq!(key_event_to_bytes(&key), b"A");
    }

    #[test]
    fn shift_number_row_produces_symbols() {
        let cases = [
            ('1', b"!" as &[u8]),
            ('2', b"@"),
            ('3', b"#"),
            ('4', b"$"),
            ('5', b"%"),
            ('6', b"^"),
            ('7', b"&"),
            ('8', b"*"),
            ('9', b"("),
            ('0', b")"),
            ('-', b"_"),
            ('=', b"+"),
        ];
        for (base, expected) in cases {
            let key = crossterm::event::KeyEvent::new(KeyCode::Char(base), KeyModifiers::SHIFT);
            assert_eq!(
                key_event_to_bytes(&key),
                expected,
                "Shift+{base} should produce {:?}",
                std::str::from_utf8(expected).unwrap()
            );
        }
    }

    #[test]
    fn shift_punctuation_produces_shifted() {
        let cases = [
            ('[', b"{" as &[u8]),
            (']', b"}"),
            ('\\', b"|"),
            (';', b":"),
            ('\'', b"\""),
            (',', b"<"),
            ('.', b">"),
            ('/', b"?"),
        ];
        for (base, expected) in cases {
            let key = crossterm::event::KeyEvent::new(KeyCode::Char(base), KeyModifiers::SHIFT);
            assert_eq!(
                key_event_to_bytes(&key),
                expected,
                "Shift+{base} should produce {:?}",
                std::str::from_utf8(expected).unwrap()
            );
        }
    }

    #[test]
    fn already_shifted_char_passes_through() {
        // If crossterm reports the shifted char directly (no SHIFT), pass through.
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('~'), KeyModifiers::NONE);
        assert_eq!(key_event_to_bytes(&key), b"~");
    }

    #[test]
    fn shift_does_not_apply_when_ctrl_is_held() {
        // Ctrl+Shift+a should still produce Ctrl+A (0x01), not uppercase 'A'.
        // The Ctrl path takes precedence over shift resolution.
        let key = crossterm::event::KeyEvent::new(
            KeyCode::Char('a'),
            KeyModifiers::SHIFT | KeyModifiers::CONTROL,
        );
        assert_eq!(key_event_to_bytes(&key), vec![1]); // Ctrl+A
    }

    // -----------------------------------------------------------------------
    // process_key_event: escape state machine
    // -----------------------------------------------------------------------

    /// Helper to create a key event with no modifiers.
    fn char_key(c: char) -> crossterm::event::KeyEvent {
        crossterm::event::KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    /// Helper to create a key event with SHIFT modifier (kitty protocol style).
    fn shift_char_key(c: char) -> crossterm::event::KeyEvent {
        crossterm::event::KeyEvent::new(KeyCode::Char(c), KeyModifiers::SHIFT)
    }

    fn enter_key() -> crossterm::event::KeyEvent {
        crossterm::event::KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)
    }

    #[test]
    fn process_normal_char_sends_and_predicts() {
        let mut escape = EscapeState::Normal;
        let action = process_key_event(&mut escape, &char_key('a'));
        assert_eq!(action, KeyAction::SendAndPredict(b"a".to_vec()));
        assert!(matches!(escape, EscapeState::Normal));
    }

    #[test]
    fn process_enter_transitions_to_after_enter() {
        let mut escape = EscapeState::Normal;
        let action = process_key_event(&mut escape, &enter_key());
        assert_eq!(action, KeyAction::SendAndPredict(b"\r".to_vec()));
        assert!(matches!(escape, EscapeState::AfterEnter));
    }

    #[test]
    fn process_enter_tilde_period_disconnects() {
        let mut escape = EscapeState::Normal;
        // Enter
        let _ = process_key_event(&mut escape, &enter_key());
        assert!(matches!(escape, EscapeState::AfterEnter));
        // ~
        let action = process_key_event(&mut escape, &char_key('~'));
        assert_eq!(action, KeyAction::Consumed);
        assert!(matches!(escape, EscapeState::AfterTilde));
        // .
        let action = process_key_event(&mut escape, &char_key('.'));
        assert_eq!(action, KeyAction::Disconnect);
    }

    #[test]
    fn process_enter_tilde_d_detaches() {
        let mut escape = EscapeState::Normal;
        let _ = process_key_event(&mut escape, &enter_key());
        let _ = process_key_event(&mut escape, &char_key('~'));
        let action = process_key_event(&mut escape, &char_key('d'));
        assert_eq!(action, KeyAction::Detach);
    }

    #[test]
    fn process_enter_tilde_tilde_sends_literal_tilde() {
        let mut escape = EscapeState::Normal;
        let _ = process_key_event(&mut escape, &enter_key());
        let _ = process_key_event(&mut escape, &char_key('~'));
        let action = process_key_event(&mut escape, &char_key('~'));
        assert_eq!(action, KeyAction::SendAndPredict(b"~".to_vec()));
        assert!(matches!(escape, EscapeState::Normal));
    }

    #[test]
    fn process_enter_tilde_question_shows_help() {
        let mut escape = EscapeState::Normal;
        let _ = process_key_event(&mut escape, &enter_key());
        let _ = process_key_event(&mut escape, &char_key('~'));
        let action = process_key_event(&mut escape, &char_key('?'));
        assert_eq!(action, KeyAction::ShowHelp);
        assert!(matches!(escape, EscapeState::Normal));
    }

    #[test]
    fn process_enter_tilde_other_flushes_deferred() {
        let mut escape = EscapeState::Normal;
        let _ = process_key_event(&mut escape, &enter_key());
        let _ = process_key_event(&mut escape, &char_key('~'));
        let action = process_key_event(&mut escape, &char_key('x'));
        assert_eq!(
            action,
            KeyAction::SendMultipleAndPredict(vec![b"~".to_vec(), b"x".to_vec()])
        );
        assert!(matches!(escape, EscapeState::Normal));
    }

    #[test]
    fn process_enter_enter_stays_in_after_enter() {
        let mut escape = EscapeState::Normal;
        let _ = process_key_event(&mut escape, &enter_key());
        let action = process_key_event(&mut escape, &enter_key());
        // Second Enter is sent and we stay in AfterEnter.
        assert_eq!(action, KeyAction::SendAndPredict(b"\r".to_vec()));
        assert!(matches!(escape, EscapeState::AfterEnter));
    }

    #[test]
    fn process_after_enter_normal_key_resets() {
        let mut escape = EscapeState::Normal;
        let _ = process_key_event(&mut escape, &enter_key());
        let action = process_key_event(&mut escape, &char_key('x'));
        assert_eq!(action, KeyAction::SendAndPredict(b"x".to_vec()));
        assert!(matches!(escape, EscapeState::Normal));
    }

    #[test]
    fn process_unknown_key_consumed() {
        let mut escape = EscapeState::Normal;
        let key = crossterm::event::KeyEvent::new(KeyCode::Null, KeyModifiers::NONE);
        let action = process_key_event(&mut escape, &key);
        assert_eq!(action, KeyAction::Consumed);
    }

    // -----------------------------------------------------------------------
    // Kitty protocol: escape sequence with SHIFT+base key
    // -----------------------------------------------------------------------

    #[test]
    fn kitty_escape_shift_backtick_is_tilde() {
        // With kitty protocol, ~ may arrive as Char('`') + SHIFT.
        // The escape FSM should still recognize it as tilde.
        let mut escape = EscapeState::Normal;
        let _ = process_key_event(&mut escape, &enter_key());
        assert!(matches!(escape, EscapeState::AfterEnter));

        // Shift+backtick (kitty protocol for ~)
        let action = process_key_event(&mut escape, &shift_char_key('`'));
        assert_eq!(action, KeyAction::Consumed);
        assert!(matches!(escape, EscapeState::AfterTilde));

        // . to disconnect
        let action = process_key_event(&mut escape, &char_key('.'));
        assert_eq!(action, KeyAction::Disconnect);
    }

    #[test]
    fn kitty_escape_shift_backtick_shift_backtick_sends_tilde() {
        // Enter, ~(shift+`), ~(shift+`) → literal tilde
        let mut escape = EscapeState::Normal;
        let _ = process_key_event(&mut escape, &enter_key());
        let _ = process_key_event(&mut escape, &shift_char_key('`'));
        let action = process_key_event(&mut escape, &shift_char_key('`'));
        assert_eq!(action, KeyAction::SendAndPredict(b"~".to_vec()));
    }

    #[test]
    fn kitty_shift_period_produces_greater_than() {
        // Shift+. → > (not a disconnect trigger)
        let mut escape = EscapeState::Normal;
        let _ = process_key_event(&mut escape, &enter_key());
        let _ = process_key_event(&mut escape, &char_key('~'));
        // Shift+. produces '>' which is NOT '.'
        let action = process_key_event(&mut escape, &shift_char_key('.'));
        // '>' is not a recognized escape character, so it flushes ~ and >
        assert_eq!(
            action,
            KeyAction::SendMultipleAndPredict(vec![b"~".to_vec(), b">".to_vec()])
        );
    }
}
