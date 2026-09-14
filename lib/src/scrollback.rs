//! Scrollback synchronization for `RoSE`.
//!
//! Transfers scrollback history from server to client over a dedicated
//! QUIC uni stream. The server tracks which lines have been sent and
//! incrementally sends new ones as they appear.

use crate::ssp::{SspError, Viewport, scrollback_before_viewport};

/// Maximum retained history rows on either endpoint.
pub const MAX_SCROLLBACK_LINES: usize = 3500;
/// Maximum retained client history text bytes, and maximum encoded line text.
pub const MAX_SCROLLBACK_BYTES: usize = 8 * 1024 * 1024;

const MAX_BATCH_BYTES: usize = 256 * 1024;

pub(crate) type ScrollbackRange = Option<(isize, isize)>;

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

    /// Collects unsent history, targeting at most 256 KiB of text per batch.
    ///
    /// A larger single row may fill a batch, up to [`MAX_SCROLLBACK_BYTES`].
    /// Rows exceeding that limit are skipped.
    pub fn collect_new_lines(
        &mut self,
        terminal: &crate::terminal::RoseTerminal,
    ) -> Vec<ScrollbackLine> {
        let (last, lines) = terminal.scrollback_batch_since(
            self.last_sent_stable_row,
            MAX_BATCH_BYTES,
            MAX_SCROLLBACK_BYTES,
        );
        self.last_sent_stable_row = last;
        lines
            .into_iter()
            .map(|(stable, text)| ScrollbackLine {
                stable_row: stable,
                text,
            })
            .collect()
    }
}

impl Default for ScrollbackSender {
    fn default() -> Self {
        Self::new()
    }
}

/// Client-side scrollback storage.
///
/// Retains the newest history within row and text-byte limits.
pub struct ScrollbackReceiver {
    lines: Vec<ScrollbackLine>,
    start: usize,
    bytes: usize,
}

impl ScrollbackReceiver {
    /// Creates an empty receiver.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lines: Vec::new(),
            start: 0,
            bytes: 0,
        }
    }

    /// Adds a new row, evicting older rows to stay within retention limits.
    ///
    /// Duplicate, out-of-order, and individually oversized rows are ignored.
    pub fn add_line(&mut self, line: ScrollbackLine) {
        if line.text.len() > MAX_SCROLLBACK_BYTES
            || self
                .lines()
                .last()
                .is_some_and(|last| line.stable_row <= last.stable_row)
        {
            return;
        }
        while self.len() >= MAX_SCROLLBACK_LINES
            || self.bytes + line.text.len() > MAX_SCROLLBACK_BYTES
        {
            self.bytes -= self.lines[self.start].text.len();
            self.lines[self.start].text = String::new();
            self.start += 1;
        }
        if self.start > 0 && self.lines.len() == self.lines.capacity() {
            self.lines.drain(..self.start);
            self.start = 0;
        }
        self.bytes += line.text.len();
        self.lines.push(line);
    }

    /// Returns retained scrollback lines in ascending stable-row order.
    #[must_use]
    pub fn lines(&self) -> &[ScrollbackLine] {
        &self.lines[self.start..]
    }

    pub(crate) fn range_before_viewport(&self, viewport: Option<Viewport>) -> ScrollbackRange {
        let lines = scrollback_before_viewport(self.lines(), viewport);
        Some((lines.first()?.stable_row, lines.last()?.stable_row))
    }

    /// Returns the number of received scrollback lines.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.lines.len() - self.start
    }

    /// Returns `true` if no scrollback lines have been received.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
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
    fn sender_batches_history_without_losing_rows() {
        let mut terminal = crate::terminal::RoseTerminal::new(24, 100);
        terminal.advance(format!("{}\r\n", "x".repeat(99)).repeat(4000).as_bytes());
        let mut sender = ScrollbackSender::new();
        let mut collected = sender.collect_new_lines(&terminal);
        assert!(collected.iter().map(|line| line.text.len()).sum::<usize>() <= 256 * 1024);
        let remaining = sender.collect_new_lines(&terminal);
        assert!(!remaining.is_empty());
        collected.extend(remaining);
        assert_eq!(
            collected
                .into_iter()
                .map(|line| (line.stable_row, line.text))
                .collect::<Vec<_>>(),
            terminal.scrollback_lines(),
        );
        assert!(sender.collect_new_lines(&terminal).is_empty());
    }

    #[test]
    fn rendered_history_range_tracks_eviction_and_viewport_overlap() {
        let mut receiver = ScrollbackReceiver::new();
        assert_eq!(receiver.range_before_viewport(None), None);
        for stable_row in 0..3500 {
            receiver.add_line(ScrollbackLine {
                stable_row,
                text: "row".to_owned(),
            });
        }
        let viewport = Some(Viewport {
            first_row: 3499,
            alternate_screen: false,
        });
        assert_eq!(receiver.range_before_viewport(viewport), Some((0, 3498)));
        receiver.add_line(ScrollbackLine {
            stable_row: 3500,
            text: "new".to_owned(),
        });
        assert_eq!(receiver.len(), 3500);
        assert_eq!(receiver.range_before_viewport(viewport), Some((1, 3498)));
        assert_eq!(receiver.range_before_viewport(None), Some((1, 3500)));
        assert_eq!(
            receiver.range_before_viewport(Some(Viewport {
                first_row: 1,
                alternate_screen: false
            })),
            None
        );
        assert_eq!(
            receiver
                .lines
                .iter()
                .map(|line| line.text.len())
                .sum::<usize>(),
            receiver.bytes
        );
    }

    #[test]
    fn history_batches_advance_past_oversized_rows_and_allow_one_large_row() {
        let mut terminal = crate::terminal::RoseTerminal::new(2, 240);
        terminal.advance(format!("{}\r\nsmall\r\nvisible\r\nend", "x".repeat(200)).as_bytes());
        let expected = terminal.scrollback_lines();
        assert_eq!(expected.len(), 2);
        let (last, batch) = terminal.scrollback_batch_since(-1, 64, 256);
        assert_eq!(batch, expected[..1]);
        assert_eq!(last, expected[0].0);
        let (last, batch) = terminal.scrollback_batch_since(-1, 64, 128);
        assert_eq!(batch, expected[1..]);
        assert_eq!(last, expected[1].0);
        let (last, batch) = terminal.scrollback_batch_since(-1, 64, 0);
        assert!(batch.is_empty());
        assert_eq!(last, expected[1].0);
    }

    #[test]
    fn receiver_evicts_oldest_rows_after_retention_limit() {
        let mut receiver = ScrollbackReceiver::new();
        for stable_row in 0..8000 {
            receiver.add_line(ScrollbackLine {
                stable_row,
                text: format!("line {stable_row}"),
            });
        }
        assert_eq!(receiver.len(), 3500);
        assert_eq!(receiver.lines().first().unwrap().stable_row, 4500);
        assert_eq!(receiver.lines().last().unwrap().stable_row, 7999);
    }

    #[test]
    fn receiver_bounds_text_bytes_independently_of_row_count() {
        let mut receiver = ScrollbackReceiver::new();
        for stable_row in 0..3 {
            receiver.add_line(ScrollbackLine {
                stable_row,
                text: "x".repeat(3 * 1024 * 1024),
            });
        }
        assert_eq!(receiver.len(), 2);
        assert_eq!(receiver.lines()[0].stable_row, 1);
        receiver.add_line(ScrollbackLine {
            stable_row: 3,
            text: "x".repeat(8 * 1024 * 1024 + 1),
        });
        assert_eq!(receiver.len(), 2);
    }

    #[test]
    fn receiver_ignores_duplicate_and_out_of_order_history() {
        let mut receiver = ScrollbackReceiver::new();
        for stable_row in [2, 1, 2] {
            receiver.add_line(ScrollbackLine {
                stable_row,
                text: "retained".to_owned(),
            });
        }
        assert_eq!(receiver.len(), 1);
        assert_eq!(receiver.lines()[0].stable_row, 2);
    }

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
    fn sender_handles_pruning_clear_resize_and_alternate_screen() {
        let mut term = crate::terminal::RoseTerminal::new(5, 40);
        let mut sender = ScrollbackSender::new();
        let mut last = -1;
        for phase in 0..4 {
            for i in 0..3800 {
                term.advance(format!("\x1b[31m{phase}:{i}\x1b[0m\r\n").as_bytes());
            }
            let all = term.scrollback_lines();
            let expected: Vec<_> = all.into_iter().filter(|(row, _)| *row > last).collect();
            let collected = sender.collect_new_lines(&term);
            assert!(!collected.is_empty());
            assert_eq!(
                collected
                    .iter()
                    .map(|line| (line.stable_row, line.text.clone()))
                    .collect::<Vec<_>>(),
                expected
            );
            last = collected.last().unwrap().stable_row;
            assert!(sender.collect_new_lines(&term).is_empty());
            assert!(term.scrollback_lines_since(isize::MAX).is_empty());
            assert_eq!(
                term.scrollback_lines_since(isize::MIN),
                term.scrollback_lines()
            );

            let mut reattached = ScrollbackSender::new();
            assert_eq!(
                reattached.collect_new_lines(&term).len(),
                term.scrollback_lines().len()
            );
            match phase {
                0 => term.advance(b"\x1b[3J"),
                1 => term.resize(10, 80),
                2 => {
                    term.advance(
                        b"\x1b[?1049h1\r\n2\r\n3\r\n4\r\n5\r\n6\r\n7\r\n8\r\n9\r\n10\r\n11",
                    );
                    assert!(sender.collect_new_lines(&term).is_empty());
                    term.advance(b"\x1b[?1049l");
                }
                _ => {}
            }
        }
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
