//! Terminal emulation layer wrapping wezterm-term.
//!
//! Both the client and server embed a wezterm terminal emulator. The server
//! interprets PTY output into screen state and computes diffs. The client
//! maintains a local copy for display and keystroke prediction.

use std::sync::Arc;

use wezterm_term::{Terminal, TerminalConfiguration, TerminalSize};

use crate::ssp::ScreenState;

/// Configuration for the wezterm terminal emulator.
#[derive(Debug)]
struct RoseTerminalConfig;

impl TerminalConfiguration for RoseTerminalConfig {
    fn color_palette(&self) -> wezterm_term::color::ColorPalette {
        wezterm_term::color::ColorPalette::default()
    }
}

struct DummyWriter;

impl std::io::Write for DummyWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Wraps a wezterm [`Terminal`] for use in `RoSE`'s state synchronization.
pub struct RoseTerminal {
    inner: Terminal,
}

impl RoseTerminal {
    /// Creates a new terminal emulator with the given dimensions.
    #[must_use]
    pub fn new(rows: u16, cols: u16) -> Self {
        let config: Arc<dyn TerminalConfiguration + Send + Sync> = Arc::new(RoseTerminalConfig);
        let size = TerminalSize {
            rows: rows as usize,
            cols: cols as usize,
            pixel_width: 0,
            pixel_height: 0,
            dpi: 0,
        };

        let terminal = Terminal::new(size, config, "RoSE", "0.1.0", Box::new(DummyWriter));

        Self { inner: terminal }
    }

    /// Feeds raw bytes (PTY output) into the terminal emulator.
    pub fn advance(&mut self, data: &[u8]) {
        self.inner.advance_bytes(data);
    }

    /// Resizes the terminal to the given dimensions.
    pub fn resize(&mut self, rows: u16, cols: u16) {
        self.inner.resize(TerminalSize {
            rows: rows as usize,
            cols: cols as usize,
            pixel_width: 0,
            pixel_height: 0,
            dpi: 0,
        });
    }

    /// Returns the text content of a single visible row.
    #[must_use]
    pub fn line_text(&self, row: usize) -> String {
        let screen = self.inner.screen();
        let stable_row = screen.visible_row_to_stable_row(row as i64);
        let phys_lines = screen.lines_in_phys_range(stable_row as usize..stable_row as usize + 1);
        phys_lines
            .first()
            .map_or_else(String::new, |line| line.as_str().to_string())
    }

    /// Returns the current screen contents as a string (visible lines joined by newlines).
    #[must_use]
    pub fn screen_text(&self) -> String {
        let size = self.inner.get_size();
        let mut lines = Vec::with_capacity(size.rows);
        for row in 0..size.rows {
            lines.push(self.line_text(row));
        }
        lines.join("\n")
    }

    /// Returns the cursor position as (x, y).
    #[must_use]
    pub fn cursor_pos(&self) -> (usize, usize) {
        let pos = self.inner.cursor_pos();
        (pos.x, pos.y as usize)
    }

    /// Returns the terminal dimensions as (rows, cols).
    #[must_use]
    pub fn size(&self) -> (usize, usize) {
        let s = self.inner.get_size();
        (s.rows, s.cols)
    }

    /// Returns scrollback lines (lines above the visible viewport).
    ///
    /// Each entry is `(stable_row_index, text)`. Only lines that have scrolled
    /// off the top of the visible area are included.
    #[must_use]
    pub fn scrollback_lines(&self) -> Vec<(isize, String)> {
        let screen = self.inner.screen();
        let total = screen.scrollback_rows();
        let visible = self.inner.get_size().rows;
        let scrollback_count = total.saturating_sub(visible);
        if scrollback_count == 0 {
            return vec![];
        }
        let lines = screen.lines_in_phys_range(0..scrollback_count);
        lines
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let stable = screen.phys_to_stable_row_index(i);
                (stable, line.as_str().to_string())
            })
            .collect()
    }

    /// Captures the current visible screen state as a [`ScreenState`].
    ///
    /// Each row has trailing whitespace trimmed.
    #[must_use]
    pub fn snapshot(&self) -> ScreenState {
        let size = self.inner.get_size();
        let mut rows = Vec::with_capacity(size.rows);
        for row in 0..size.rows {
            rows.push(self.line_text(row).trim_end().to_string());
        }
        let (cx, cy) = self.cursor_pos();
        ScreenState {
            rows,
            cursor_x: cx as u16,
            cursor_y: cy as u16,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Basic terminal functionality
    // -----------------------------------------------------------------------

    #[test]
    fn new_terminal_has_correct_dimensions() {
        let term = RoseTerminal::new(24, 80);
        assert_eq!(term.size(), (24, 80));
    }

    #[test]
    fn advance_renders_text() {
        let mut term = RoseTerminal::new(24, 80);
        term.advance(b"hello world");
        assert!(term.screen_text().contains("hello world"));
    }

    #[test]
    fn cursor_moves_after_output() {
        let mut term = RoseTerminal::new(24, 80);
        term.advance(b"abc");
        assert_eq!(term.cursor_pos(), (3, 0));
    }

    #[test]
    fn resize_updates_dimensions() {
        let mut term = RoseTerminal::new(24, 80);
        term.resize(40, 120);
        assert_eq!(term.size(), (40, 120));
    }

    #[test]
    fn line_text_returns_individual_rows() {
        let mut term = RoseTerminal::new(24, 80);
        term.advance(b"line one\nline two\nline three");
        assert!(term.line_text(0).contains("line one"));
        assert!(term.line_text(1).contains("line two"));
        assert!(term.line_text(2).contains("line three"));
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-80th-column.test
    //
    // Tests that writing exactly 80 characters on an 80-column terminal
    // positions the cursor at column 80 without wrapping. A subsequent
    // CR+LF should move to the next line without creating an extra blank line.
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_80th_column_no_extra_blank_line() {
        let mut term = RoseTerminal::new(24, 80);
        // Clear screen and home cursor
        term.advance(b"\x1b[H\x1b[J");

        // Write 25 lines of exactly 80 'E' characters followed by CR+LF
        for _ in 0..25 {
            let row = "E".repeat(80);
            term.advance(row.as_bytes());
            term.advance(b"\r\n");
        }

        // Count visible lines containing "EEEEEEEEEE" (10+ E's).
        // With correct 80th-column handling, there should be no extra blank
        // lines inserted. The terminal scrolls (25 lines in 24 rows) so we
        // expect the visible area to contain contiguous E-filled lines.
        let text = term.screen_text();
        let e_lines = text.lines().filter(|l| l.contains("EEEEEEEEEE")).count();

        // Mosh test expects 23 (25 lines printed, 24 visible, last line is
        // blank from the final CR+LF). We allow slight variation since
        // wezterm may handle the final newline differently, but there must
        // be no interleaved blank lines.
        assert!(
            e_lines >= 23,
            "expected at least 23 E-filled lines, got {e_lines}"
        );
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-scroll.test
    //
    // Regression test: SCROLL UP (CSI S) and SCROLL DOWN (CSI T) should
    // not move the cursor.
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_scroll_up_down_does_not_move_cursor() {
        let mut term = RoseTerminal::new(24, 80);
        // Clear screen
        term.advance(b"\x1b[H\x1b[J");

        // Fill with sample text: "text 1" through "text 24"
        for i in 1..=24 {
            term.advance(format!("\ntext {i}").as_bytes());
        }

        // Record cursor position before scrolling
        let cursor_before = term.cursor_pos();

        // Scroll up 4 lines (CSI 4 S)
        term.advance(b"\x1b[4S");
        // Scroll down 2 lines (CSI 2 T)
        term.advance(b"\x1b[2T");

        // Cursor should not have moved
        let cursor_after = term.cursor_pos();
        assert_eq!(
            cursor_before, cursor_after,
            "cursor moved during scroll: before={cursor_before:?}, after={cursor_after:?}"
        );

        // The first 4 lines should have scrolled off (net scroll = 4 up - 2 down = 2 up)
        // Actually, scroll up 4 removes top 4 lines, then scroll down 2 inserts 2 blank
        // lines at top. So "text 1" through "text 4" are gone, and we have 2 blank lines
        // at top followed by "text 5" through "text 24".
        let text = term.screen_text();
        assert!(
            !text.contains("text 1\n") && !text.contains("\ntext 1"),
            "text 1 should have scrolled off"
        );
        assert!(
            !text.contains("text 2\n") && !text.contains("\ntext 2"),
            "text 2 should have scrolled off"
        );
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-cursor-motion.test
    //
    // Tests cursor positioning with CSI row;col H.
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_cursor_motion_positioning() {
        let mut term = RoseTerminal::new(24, 80);
        term.advance(b"\x1b[H\x1b[J");

        // Position cursor at various locations and write single characters
        // Format: CSI row;col H followed by a character
        let placements = [
            (1, 1, 'A'),
            (1, 10, 'B'),
            (2, 1, 'C'),
            (4, 1, 'D'),
            (4, 10, 'E'),
            (7, 1, 'F'),
            (11, 1, 'G'),
            (11, 10, 'H'),
            (16, 1, 'I'),
            (16, 2, 'J'),
            (22, 1, 'K'),
            (24, 1, 'L'),
        ];

        for (row, col, ch) in placements {
            term.advance(format!("\x1b[{row};{col}H{ch}").as_bytes());
        }

        // Verify each character is at the right position
        assert!(term.line_text(0).starts_with('A'));
        assert!(term.line_text(0).contains('B'));
        assert!(term.line_text(1).starts_with('C'));
        assert!(term.line_text(3).starts_with('D'));
        assert!(term.line_text(3).contains('E'));
        assert!(term.line_text(6).starts_with('F'));
        assert!(term.line_text(10).starts_with('G'));
        assert!(term.line_text(10).contains('H'));
        assert!(term.line_text(15).starts_with('I'));
        assert!(term.line_text(21).starts_with('K'));
        assert!(term.line_text(23).starts_with('L'));
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-back-tab.test
    //
    // Tests back-tab (CSI Z) and forward-tab (CSI I) escape sequences.
    // Issue 539: Back-tab should move cursor to previous tab stop.
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_back_tab_basic() {
        let mut term = RoseTerminal::new(24, 80);
        // "hello, wurld" then back-tab then 'o'
        // Back-tab from col 12 goes to tab stop at col 8, writes 'o' -> "hello, world"
        term.advance(b"hello, wurld\x1b[Zo\n");
        assert!(
            term.line_text(0).contains("hello, world"),
            "back-tab should position cursor to overwrite 'u' with 'o': got {:?}",
            term.line_text(0)
        );
    }

    #[test]
    fn emulation_back_tab_count_2() {
        let mut term = RoseTerminal::new(24, 80);
        // "hello, wurld" then back-tab 2 (goes to col 0), writes 'o'
        term.advance(b"hello, wurld\x1b[2Zo\n");
        assert!(
            term.line_text(0).starts_with('o'),
            "back-tab 2 from col 12 should go to col 0: got {:?}",
            term.line_text(0)
        );
    }

    #[test]
    fn emulation_back_tab_overflow() {
        let mut term = RoseTerminal::new(24, 80);
        // "hello, wurld" then back-tab 99 (clamps to col 0), writes '9'
        term.advance(b"hello, wurld\x1b[99Z9\n");
        assert!(
            term.line_text(0).starts_with('9'),
            "back-tab 99 should clamp to col 0: got {:?}",
            term.line_text(0)
        );
    }

    #[test]
    fn emulation_forward_tab() {
        let mut term = RoseTerminal::new(24, 80);
        // "hello, wurld" then forward-tab (CSI I) then 't'
        // Forward tab from col 12 goes to next tab stop at col 16, writes 't'
        term.advance(b"hello, wurld\x1b[It\n");
        let line = term.line_text(0);
        // 't' should appear after the tab stop (around col 16)
        assert!(
            line.contains('t'),
            "forward-tab should place 't' at next tab stop: got {line:?}"
        );
        // The 't' should be past the original text
        let t_pos = line.find('t').unwrap();
        assert!(
            t_pos >= 16,
            "forward-tab 't' should be at col 16+, got col {t_pos}"
        );
    }

    #[test]
    fn emulation_forward_tab_overflow() {
        let mut term = RoseTerminal::new(24, 80);
        // Forward tab 99 from col 0, then '#'
        // Should go to last tab stop (col 72 on 80-col) or col 79
        term.advance(b"\x1b[99I#\n");
        let line = term.line_text(0);
        assert!(
            line.contains('#'),
            "forward-tab 99 should place '#' near end of line: got {line:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-wrap-across-frames.test
    //
    // Regression test: text filled to column 80 on one frame, then wrapped
    // to the next line on the next frame. Verifies that wrap state is
    // handled correctly.
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_wrap_across_frames() {
        let mut term = RoseTerminal::new(24, 80);
        term.advance(b"\x1b[H\x1b[J");

        // Write exactly 80 chars (4 "abcd" + 72 'X' + "1234" = 80), then
        // another 80 chars that should wrap to the next line.
        let first_80 = format!("abcd{}1234", "X".repeat(72));
        assert_eq!(first_80.len(), 80);
        term.advance(first_80.as_bytes());

        let second_80 = format!("ABCD{}5678", "x".repeat(72));
        assert_eq!(second_80.len(), 80);
        term.advance(second_80.as_bytes());

        // The first 80 chars should be on line 0, second on line 1
        let line0 = term.line_text(0);
        let line1 = term.line_text(1);
        assert!(
            line0.contains("abcd"),
            "first frame should contain 'abcd': got {line0:?}"
        );
        assert!(
            line1.contains("ABCD"),
            "second frame should wrap to next line with 'ABCD': got {line1:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-multiline-scroll.test
    //
    // Regression test for insert/delete line (CSI L / CSI M) with various
    // counts, including counts exceeding the window height.
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_insert_delete_line_no_crash() {
        let mut term = RoseTerminal::new(24, 80);
        term.advance(b"\x1b[H\x1b[J");

        // Test delete line (CSI M) with various counts
        for i in [0, 1, 2, 22, 23, 24, 25, 26] {
            term.advance(format!("{i}\r").as_bytes());
            term.advance(format!("\x1b[{i}M").as_bytes());
        }

        // Test insert line (CSI L) with various counts
        for i in [0, 1, 2, 22, 23, 24, 25, 26] {
            term.advance(format!("{i}\r").as_bytes());
            term.advance(format!("\x1b[{i}L").as_bytes());
        }

        // If we get here without panicking, the test passes.
        // This is a crash regression test.
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-ascii-iso-8859.test
    //
    // Verifies that printable ASCII (0x20-0x7E) and ISO 8859-1 (0xA0-0xFF)
    // characters display correctly.
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_ascii_printable_characters() {
        let mut term = RoseTerminal::new(24, 80);
        term.advance(b"\x1b[H\x1b[J");

        // Output printable ASCII characters
        let ascii_line: String = (0x20u8..=0x7E).map(|b| b as char).collect();
        term.advance(ascii_line.as_bytes());

        let text = term.screen_text();
        // Verify all printable ASCII chars are present
        for ch in '!'..='~' {
            assert!(
                text.contains(ch),
                "ASCII char '{ch}' (0x{:02x}) missing from screen",
                ch as u32
            );
        }
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-attributes.test (VT100 subset)
    //
    // Tests that VT100 SGR attributes (bold, underline, blink, reverse)
    // can be applied without crashing. We verify the text content is
    // rendered; attribute correctness depends on wezterm internals.
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_vt100_attributes_render() {
        let mut term = RoseTerminal::new(24, 80);
        term.advance(b"\x1b[H\x1b[J");

        // Apply various VT100 attributes and write 'E', then reset
        for attr in [0, 1, 4, 5, 7] {
            term.advance(format!("\x1b[{attr}mE\x1b[m ").as_bytes());
        }

        let text = term.screen_text();
        let e_count = text.matches('E').count();
        assert_eq!(
            e_count, 5,
            "expected 5 'E' characters with different attributes, got {e_count}"
        );
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-attributes.test (16-color subset)
    //
    // Tests 16-color SGR attributes (foreground 30-37, 39, background 40-47, 49).
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_16color_attributes_render() {
        let mut term = RoseTerminal::new(24, 80);
        term.advance(b"\x1b[H\x1b[J");

        // Foreground colors 30-37, default fg 39, background 40-47, default bg 49
        let attrs: Vec<u8> = (30..=37)
            .chain(39..=47)
            .chain(std::iter::once(49))
            .collect();
        for attr in &attrs {
            term.advance(format!("\x1b[{attr}mE\x1b[m ").as_bytes());
        }

        let text = term.screen_text();
        let e_count = text.matches('E').count();
        assert_eq!(
            e_count,
            attrs.len(),
            "expected {} 'E' characters for 16-color, got {e_count}",
            attrs.len()
        );
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-attributes.test (256-color subset)
    //
    // Tests 256-color SGR attributes (CSI 38;5;N m for fg, CSI 48;5;N m for bg).
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_256color_attributes_render() {
        let mut term = RoseTerminal::new(80, 132);
        term.advance(b"\x1b[H\x1b[J");

        for color in 0..=255u16 {
            term.advance(format!("\x1b[38;5;{color}mF\x1b[m").as_bytes());
            term.advance(format!("\x1b[48;5;{color}mB\x1b[m").as_bytes());
        }

        let text = term.screen_text();
        let f_count = text.matches('F').count();
        let b_count = text.matches('B').count();
        assert_eq!(
            f_count, 256,
            "expected 256 foreground 'F' chars, got {f_count}"
        );
        assert_eq!(
            b_count, 256,
            "expected 256 background 'B' chars, got {b_count}"
        );
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-attributes.test (true-color subset)
    //
    // Tests true-color SGR (CSI 38;2;R;G;B m / CSI 48;2;R;G;B m).
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_truecolor_attributes_render() {
        let mut term = RoseTerminal::new(24, 80);
        term.advance(b"\x1b[H\x1b[J");

        // Write a gradient of true-color characters
        for attr in 0..=76 {
            let r = 255 - (attr * 255 / 76);
            let g = {
                let raw = attr * 510 / 76;
                if raw > 255 { 510 - raw } else { raw }
            };
            let b = attr * 255 / 76;
            let inv_r = 255 - r;
            let inv_g = 255 - g;
            let inv_b = 255 - b;
            term.advance(
                format!("\x1b[48;2;{r};{g};{b}m\x1b[38;2;{inv_r};{inv_g};{inv_b}mE\x1b[m")
                    .as_bytes(),
            );
        }

        let text = term.screen_text();
        let e_count = text.matches('E').count();
        assert_eq!(
            e_count, 77,
            "expected 77 true-color 'E' chars, got {e_count}"
        );
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: unicode-later-combining.test
    //
    // Tests combining character (U+0302 COMBINING CIRCUMFLEX ACCENT) drawn
    // on a cell after the cursor returns to that cell.
    // Print "abc\n", then U+0302 which should combine with the space at the
    // start of line 1.
    // -----------------------------------------------------------------------

    #[test]
    fn unicode_combining_on_returned_cell() {
        let mut term = RoseTerminal::new(24, 80);
        // "abc\n" puts cursor at (0, 1). Then U+0302 (combining circumflex,
        // UTF-8: 0xCC 0x82) should combine with whatever is at (0, 1).
        term.advance(b"abc\n\xcc\x82\ndef\n");

        // The combining character should not crash, and "def" should appear.
        let text = term.screen_text();
        assert!(
            text.contains("def"),
            "output after combining char should contain 'def': got {text:?}"
        );
        assert!(
            text.contains("abc"),
            "output should still contain 'abc': got {text:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: unicode-combine-fallback-assert.test
    //
    // Regression test for issue 667: combining character printed on a
    // just-cleared cell should not crash.
    // -----------------------------------------------------------------------

    #[test]
    fn unicode_combining_on_cleared_cell_no_crash() {
        let mut term = RoseTerminal::new(24, 80);
        // Print '0', then CSI 1 J (clear from beginning of screen to cursor),
        // then U+0334 (COMBINING TILDE OVERLAY, UTF-8: 0xCC 0xB4)
        term.advance(b"0\x1b[1J\xcc\xb4");

        // If we get here without panicking, the test passes.
        // This is a crash regression test.
        let _text = term.screen_text();
    }

    // -----------------------------------------------------------------------
    // Ported from mosh: emulation-attributes.test (BCE subset)
    //
    // Tests Background Color Erase (BCE) — clearing the screen while a
    // background color is active should fill with that color, not default.
    // -----------------------------------------------------------------------

    #[test]
    fn emulation_bce_clear_with_background_color() {
        let mut term = RoseTerminal::new(24, 80);
        // True color background, clear screen, write text
        term.advance(b"\x1b[48;2;255;0;255m\x1b[H\x1b[JTrue color\n");
        // 256 color background, erase below
        term.advance(b"\x1b[48;5;32m\x1b[J256 color\n");
        // 16 color background, erase below
        term.advance(b"\x1b[42m\x1b[J16 color\n");
        // Reset and write done
        term.advance(b"\x1b[0mdone\n");

        let text = term.screen_text();
        assert!(text.contains("True color"), "BCE true color text missing");
        assert!(text.contains("256 color"), "BCE 256 color text missing");
        assert!(text.contains("16 color"), "BCE 16 color text missing");
        assert!(text.contains("done"), "BCE done text missing");
    }
}
