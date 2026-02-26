//! Scrollback synchronization for `RoSE`.
//!
//! Transfers scrollback history from server to client over a dedicated
//! QUIC uni stream. The server tracks which lines have been sent and
//! incrementally sends new ones as they appear.

use crate::ssp::SspError;

/// A single scrollback line with its stable row index and text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrollbackLine {
    /// Stable row index from the wezterm terminal emulator.
    pub stable_row: isize,
    /// Text content of the line.
    pub text: String,
}

impl ScrollbackLine {
    /// Encodes this line to bytes.
    ///
    /// Format: `[stable_row: i64 BE][text_len: u32 BE][text bytes]`
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let text_bytes = self.text.as_bytes();
        let mut buf = Vec::with_capacity(12 + text_bytes.len());
        buf.extend_from_slice(&(self.stable_row as i64).to_be_bytes());
        buf.extend_from_slice(&(text_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(text_bytes);
        buf
    }

    /// Decodes a scrollback line from a byte slice, returning the line
    /// and the number of bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `SspError::MalformedFrame` if the data is truncated or invalid.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), SspError> {
        if data.len() < 12 {
            return Err(SspError::MalformedFrame(
                "scrollback line too short".to_string(),
            ));
        }
        let stable_row = i64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]) as isize;
        let text_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let total = 12 + text_len;
        if data.len() < total {
            return Err(SspError::MalformedFrame(
                "scrollback line text truncated".to_string(),
            ));
        }
        let text = String::from_utf8(data[12..total].to_vec())
            .map_err(|e| SspError::MalformedFrame(format!("invalid UTF-8 in scrollback: {e}")))?;
        Ok((Self { stable_row, text }, total))
    }
}

/// Uni stream type prefix bytes for distinguishing stream contents.
pub mod stream_type {
    /// Oversized SSP frame sent via a one-shot uni stream.
    pub const SSP_FRAME: u8 = 0x01;
    /// Scrollback data sent via a long-lived uni stream.
    pub const SCROLLBACK: u8 = 0x02;
}

/// Server-side scrollback tracker.
///
/// Tracks which scrollback lines have been sent to the client and
/// collects new ones for transmission.
pub struct ScrollbackSender {
    last_sent_stable_row: isize,
}

impl ScrollbackSender {
    /// Creates a new sender that hasn't sent any lines yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_sent_stable_row: -1,
        }
    }

    /// Returns new scrollback lines from the terminal that haven't been sent yet.
    pub fn collect_new_lines(
        &mut self,
        terminal: &crate::terminal::RoseTerminal,
    ) -> Vec<ScrollbackLine> {
        let lines = terminal.scrollback_lines();
        let new_lines: Vec<ScrollbackLine> = lines
            .into_iter()
            .filter(|(stable, _)| *stable > self.last_sent_stable_row)
            .map(|(stable, text)| ScrollbackLine {
                stable_row: stable,
                text,
            })
            .collect();
        if let Some(last) = new_lines.last() {
            self.last_sent_stable_row = last.stable_row;
        }
        new_lines
    }
}

impl Default for ScrollbackSender {
    fn default() -> Self {
        Self::new()
    }
}

/// Client-side scrollback storage.
///
/// Accumulates scrollback lines received from the server.
pub struct ScrollbackReceiver {
    lines: Vec<ScrollbackLine>,
}

impl ScrollbackReceiver {
    /// Creates an empty receiver.
    #[must_use]
    pub const fn new() -> Self {
        Self { lines: Vec::new() }
    }

    /// Adds a scrollback line.
    pub fn add_line(&mut self, line: ScrollbackLine) {
        self.lines.push(line);
    }

    /// Returns all received scrollback lines.
    #[must_use]
    pub fn lines(&self) -> &[ScrollbackLine] {
        &self.lines
    }

    /// Returns the number of received scrollback lines.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.lines.len()
    }

    /// Returns `true` if no scrollback lines have been received.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

impl Default for ScrollbackReceiver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn scrollback_line_encode_decode() {
        for line in [
            ScrollbackLine {
                stable_row: 42,
                text: "hello scrollback".to_string(),
            },
            ScrollbackLine {
                stable_row: -5,
                text: "negative".to_string(),
            },
            ScrollbackLine {
                stable_row: 0,
                text: String::new(),
            },
        ] {
            let encoded = line.encode();
            let (decoded, consumed) = ScrollbackLine::decode(&encoded).unwrap();
            assert_eq!(decoded, line);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn scrollback_line_decode_truncated_header() {
        assert!(ScrollbackLine::decode(&[0; 8]).is_err());
    }

    #[test]
    fn scrollback_line_decode_truncated_text() {
        let mut data = vec![0u8; 12];
        // Set text_len to 10
        data[8..12].copy_from_slice(&10u32.to_be_bytes());
        // Only 3 bytes of text
        data.extend_from_slice(&[b'a'; 3]);
        assert!(ScrollbackLine::decode(&data).is_err());
    }

    #[test]
    fn scrollback_line_decode_invalid_utf8() {
        let mut data = vec![0u8; 12];
        // Set text_len to 2
        data[8..12].copy_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&[0xFF, 0xFE]);
        assert!(ScrollbackLine::decode(&data).is_err());
    }

    #[test]
    fn scrollback_line_decode_multiple_consecutive() {
        let line1 = ScrollbackLine {
            stable_row: 1,
            text: "first".to_string(),
        };
        let line2 = ScrollbackLine {
            stable_row: 2,
            text: "second".to_string(),
        };
        let mut data = line1.encode();
        data.extend_from_slice(&line2.encode());

        let (decoded1, consumed1) = ScrollbackLine::decode(&data).unwrap();
        assert_eq!(decoded1, line1);
        let (decoded2, consumed2) = ScrollbackLine::decode(&data[consumed1..]).unwrap();
        assert_eq!(decoded2, line2);
        assert_eq!(consumed1 + consumed2, data.len());
    }

    #[test]
    fn sender_collects_new_lines() {
        use crate::terminal::RoseTerminal;

        let mut term = RoseTerminal::new(4, 80);
        let mut sender = ScrollbackSender::default();

        // Generate scrollback by writing more lines than the terminal height
        for i in 0..10 {
            term.advance(format!("line {i}\r\n").as_bytes());
        }

        let lines = sender.collect_new_lines(&term);
        assert!(
            !lines.is_empty(),
            "should collect scrollback lines after overflow"
        );

        // Calling again should return no new lines
        let lines2 = sender.collect_new_lines(&term);
        assert!(lines2.is_empty(), "should not re-send already sent lines");
    }

    #[test]
    fn sender_incremental_collection() {
        use crate::terminal::RoseTerminal;

        let mut term = RoseTerminal::new(4, 80);
        let mut sender = ScrollbackSender::new();

        // Generate some scrollback
        for i in 0..8 {
            term.advance(format!("line {i}\r\n").as_bytes());
        }
        let first = sender.collect_new_lines(&term);
        let first_count = first.len();

        // Generate more scrollback
        for i in 8..12 {
            term.advance(format!("line {i}\r\n").as_bytes());
        }
        let second = sender.collect_new_lines(&term);
        assert!(
            !second.is_empty(),
            "should collect new scrollback after more output"
        );
        assert!(
            second.len() < first_count + 5,
            "should only collect new lines, not all lines"
        );
    }

    #[test]
    fn sender_no_scrollback_returns_empty() {
        use crate::terminal::RoseTerminal;

        let term = RoseTerminal::new(24, 80);
        let mut sender = ScrollbackSender::new();
        let lines = sender.collect_new_lines(&term);
        assert!(lines.is_empty());
    }

    #[test]
    fn receiver_add_and_query() {
        let mut receiver = ScrollbackReceiver::default();
        assert!(receiver.is_empty());
        assert_eq!(receiver.len(), 0);

        receiver.add_line(ScrollbackLine {
            stable_row: 0,
            text: "line 0".to_string(),
        });
        receiver.add_line(ScrollbackLine {
            stable_row: 1,
            text: "line 1".to_string(),
        });

        assert_eq!(receiver.len(), 2);
        assert!(!receiver.is_empty());
        assert_eq!(receiver.lines()[0].text, "line 0");
        assert_eq!(receiver.lines()[1].text, "line 1");
    }

    #[test]
    fn scrollback_via_terminal() {
        use crate::terminal::RoseTerminal;

        let mut term = RoseTerminal::new(4, 80);
        // No scrollback yet
        assert!(term.scrollback_lines().is_empty());

        // Write enough lines to cause scrollback
        for i in 0..10 {
            term.advance(format!("line {i}\r\n").as_bytes());
        }

        let scrollback = term.scrollback_lines();
        assert!(
            !scrollback.is_empty(),
            "should have scrollback lines after overflow"
        );
        // The first scrollback line should contain "line 0"
        assert!(
            scrollback[0].1.contains("line 0"),
            "first scrollback line should be 'line 0', got: {:?}",
            scrollback[0].1
        );
    }
}
