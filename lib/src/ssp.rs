//! State Synchronization Protocol (SSP) for `RoSE`.
//!
//! Implements screen-state diffing: the server maintains terminal state,
//! computes diffs from the last acknowledged state, and sends those diffs.
//! The client applies diffs and renders. Lost packets are automatically
//! superseded by the next diff, so the screen self-heals.

use std::collections::VecDeque;

use crate::scrollback::ScrollbackLine;

/// Errors in the SSP layer.
#[derive(Debug, thiserror::Error)]
pub enum SspError {
    /// Frame data could not be decoded.
    #[error("malformed frame: {0}")]
    MalformedFrame(String),
    /// Diff could not be applied to the current state.
    #[error("invalid diff: {0}")]
    InvalidDiff(String),
}

/// Snapshot of visible terminal screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenState {
    /// Content per visible row, may include ANSI SGR escape sequences.
    pub rows: Vec<String>,
    /// Cursor column.
    pub cursor_x: u16,
    /// Cursor row.
    pub cursor_y: u16,
}

impl ScreenState {
    /// Creates an empty screen state with the given number of rows.
    #[must_use]
    pub fn empty(rows: u16) -> Self {
        Self {
            rows: vec![String::new(); rows as usize],
            cursor_x: 0,
            cursor_y: 0,
        }
    }

    /// Computes a diff from `old` to `self`.
    #[must_use]
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn diff_from(&self, old: &Self) -> ScreenDiff {
        let mut changed_rows = Vec::new();
        let max_rows = self.rows.len().max(old.rows.len());
        for i in 0..max_rows {
            let old_row = old.rows.get(i).map_or("", String::as_str);
            let new_row = self.rows.get(i).map_or("", String::as_str);
            if old_row != new_row {
                changed_rows.push((i as u16, new_row.to_string()));
            }
        }
        ScreenDiff {
            changed_rows,
            cursor_x: self.cursor_x,
            cursor_y: self.cursor_y,
            total_rows: self.rows.len() as u16,
        }
    }

    /// Computes a diff from an empty state (init diff). Only includes non-empty rows.
    #[must_use]
    pub fn diff_from_empty(&self) -> ScreenDiff {
        let changed_rows = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| !row.is_empty())
            .map(|(i, row)| (i as u16, row.clone()))
            .collect();
        ScreenDiff {
            changed_rows,
            cursor_x: self.cursor_x,
            cursor_y: self.cursor_y,
            total_rows: self.rows.len() as u16,
        }
    }

    /// Applies a diff to this state, mutating it in place.
    ///
    /// # Errors
    ///
    /// Returns `SspError::InvalidDiff` if a row index is out of bounds.
    pub fn apply_diff(&mut self, diff: &ScreenDiff) -> Result<(), SspError> {
        let new_total = diff.total_rows as usize;
        self.rows.resize(new_total, String::new());
        for (idx, text) in &diff.changed_rows {
            let i = *idx as usize;
            if i >= new_total {
                return Err(SspError::InvalidDiff(format!(
                    "row index {idx} out of bounds (total_rows={})",
                    diff.total_rows
                )));
            }
            self.rows[i].clone_from(text);
        }
        self.cursor_x = diff.cursor_x;
        self.cursor_y = diff.cursor_y;
        Ok(())
    }
}

/// Diff between two screen states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenDiff {
    /// Only rows that differ (`row_index`, `new_text`).
    pub changed_rows: Vec<(u16, String)>,
    /// New cursor column.
    pub cursor_x: u16,
    /// New cursor row.
    pub cursor_y: u16,
    /// Total row count (handles resize).
    pub total_rows: u16,
}

impl ScreenDiff {
    /// Encodes this diff to bytes.
    ///
    /// Format: `[cursor_x: u16][cursor_y: u16][total_rows: u16][num_changed: u16]`
    /// followed by each changed row: `[row_index: u16][text_len: u16][text bytes]`
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.cursor_x.to_be_bytes());
        buf.extend_from_slice(&self.cursor_y.to_be_bytes());
        buf.extend_from_slice(&self.total_rows.to_be_bytes());
        buf.extend_from_slice(&(self.changed_rows.len() as u16).to_be_bytes());
        for (idx, text) in &self.changed_rows {
            buf.extend_from_slice(&idx.to_be_bytes());
            buf.extend_from_slice(&(text.len() as u16).to_be_bytes());
            buf.extend_from_slice(text.as_bytes());
        }
        buf
    }

    /// Decodes a diff from bytes.
    ///
    /// # Errors
    ///
    /// Returns `SspError::MalformedFrame` if the data is truncated or invalid.
    pub fn decode(data: &[u8]) -> Result<Self, SspError> {
        if data.len() < 8 {
            return Err(SspError::MalformedFrame("ScreenDiff too short".to_string()));
        }
        let cursor_x = u16::from_be_bytes([data[0], data[1]]);
        let cursor_y = u16::from_be_bytes([data[2], data[3]]);
        let total_rows = u16::from_be_bytes([data[4], data[5]]);
        let num_changed = u16::from_be_bytes([data[6], data[7]]);
        let mut offset = 8;
        let mut changed_rows = Vec::with_capacity(num_changed as usize);
        for _ in 0..num_changed {
            if offset + 4 > data.len() {
                return Err(SspError::MalformedFrame(
                    "truncated changed row header".to_string(),
                ));
            }
            let idx = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let text_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            if offset + text_len > data.len() {
                return Err(SspError::MalformedFrame(
                    "truncated changed row text".to_string(),
                ));
            }
            let text = String::from_utf8(data[offset..offset + text_len].to_vec())
                .map_err(|e| SspError::MalformedFrame(format!("invalid UTF-8 in row: {e}")))?;
            offset += text_len;
            changed_rows.push((idx, text));
        }
        Ok(Self {
            changed_rows,
            cursor_x,
            cursor_y,
            total_rows,
        })
    }
}

// Wire format constants
const FRAME_STATE_UPDATE: u8 = 0x01;
const FRAME_ACK_ONLY: u8 = 0x02;

/// Wire format for one QUIC datagram carrying SSP data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SspFrame {
    /// Diff base state number.
    pub old_num: u64,
    /// Resulting state number.
    pub new_num: u64,
    /// Acknowledges remote's state.
    pub ack_num: u64,
    /// Diff payload (`None` for ack-only frames).
    pub diff: Option<ScreenDiff>,
}

impl SspFrame {
    /// Creates an ack-only frame.
    #[must_use]
    pub const fn ack_only(ack_num: u64) -> Self {
        Self {
            old_num: 0,
            new_num: 0,
            ack_num,
            diff: None,
        }
    }

    /// Encodes this frame to bytes.
    ///
    /// Format: `[frame_type: u8][old_num: u64][new_num: u64][ack_num: u64][diff bytes...]`
    #[must_use]
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(ref diff) = self.diff {
            buf.push(FRAME_STATE_UPDATE);
            buf.extend_from_slice(&self.old_num.to_be_bytes());
            buf.extend_from_slice(&self.new_num.to_be_bytes());
            buf.extend_from_slice(&self.ack_num.to_be_bytes());
            buf.extend_from_slice(&diff.encode());
        } else {
            buf.push(FRAME_ACK_ONLY);
            buf.extend_from_slice(&self.old_num.to_be_bytes());
            buf.extend_from_slice(&self.new_num.to_be_bytes());
            buf.extend_from_slice(&self.ack_num.to_be_bytes());
        }
        buf
    }

    /// Decodes a frame from bytes.
    ///
    /// # Errors
    ///
    /// Returns `SspError::MalformedFrame` if the data is truncated or invalid.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn decode(data: &[u8]) -> Result<Self, SspError> {
        if data.len() < 25 {
            return Err(SspError::MalformedFrame("SspFrame too short".to_string()));
        }
        let frame_type = data[0];
        // Length already validated ≥ 25, so these slices are guaranteed to be 8 bytes.
        let old_num = u64::from_be_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]);
        let new_num = u64::from_be_bytes([
            data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
        ]);
        let ack_num = u64::from_be_bytes([
            data[17], data[18], data[19], data[20], data[21], data[22], data[23], data[24],
        ]);
        match frame_type {
            FRAME_STATE_UPDATE => {
                let diff = ScreenDiff::decode(&data[25..])?;
                Ok(Self {
                    old_num,
                    new_num,
                    ack_num,
                    diff: Some(diff),
                })
            }
            FRAME_ACK_ONLY => Ok(Self {
                old_num,
                new_num,
                ack_num,
                diff: None,
            }),
            other => Err(SspError::MalformedFrame(format!(
                "unknown frame type: {other:#x}"
            ))),
        }
    }
}

impl SspFrame {
    /// Encodes this frame to a stream format with a length prefix.
    ///
    /// Format: `[len: u32 big-endian][frame bytes]`
    #[must_use]
    pub fn encode_for_stream(&self) -> Vec<u8> {
        let encoded = self.encode();
        let mut buf = Vec::with_capacity(4 + encoded.len());
        buf.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        buf.extend_from_slice(&encoded);
        buf
    }

    /// Decodes a frame from a length-prefixed byte buffer (as read from a stream).
    ///
    /// # Errors
    ///
    /// Returns `SspError::MalformedFrame` if the data is truncated or invalid.
    pub fn decode_from_stream(data: &[u8]) -> Result<Self, SspError> {
        if data.len() < 4 {
            return Err(SspError::MalformedFrame(
                "stream frame too short for length prefix".to_string(),
            ));
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return Err(SspError::MalformedFrame(format!(
                "stream frame truncated: expected {len} bytes, got {}",
                data.len() - 4
            )));
        }
        Self::decode(&data[4..4 + len])
    }
}

/// Datagram prefix for client-to-server raw keystroke data.
pub const DATAGRAM_KEYSTROKE: u8 = 0x00;

/// Datagram prefix for client-to-server SSP ACK frames.
pub const DATAGRAM_SSP_ACK: u8 = 0x02;

/// Maximum number of screen states retained in the sender queue.
const MAX_QUEUE_SIZE: usize = 32;

/// Server-side SSP sender. Manages a queue of screen state snapshots
/// and generates diffs for the client.
pub struct SspSender {
    states: VecDeque<(u64, ScreenState)>,
    next_num: u64,
    ack_num: u64,
}

impl SspSender {
    /// Creates a new sender with no states.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            states: VecDeque::new(),
            next_num: 1,
            ack_num: 0,
        }
    }

    /// Pushes a new screen state, assigning it a sequence number.
    /// Returns the assigned sequence number.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn push_state(&mut self, state: ScreenState) -> u64 {
        let num = self.next_num;
        self.next_num += 1;
        self.states.push_back((num, state));
        self.prune();
        num
    }

    /// Processes an acknowledgment from the client.
    pub fn process_ack(&mut self, ack_num: u64) {
        if ack_num > self.ack_num {
            self.ack_num = ack_num;
            self.prune();
        }
    }

    /// Returns the latest state sequence number, or 0 if empty.
    #[must_use]
    pub fn current_num(&self) -> u64 {
        self.states.back().map_or(0, |(num, _)| *num)
    }

    /// Generates an SSP frame diffing from the ack'd base to the latest state.
    ///
    /// Returns `None` if the client already has the latest state or no states exist.
    /// Uses an optimization: if the init diff is smaller than the incremental diff,
    /// sends the init diff instead. Skips the init diff computation when the
    /// incremental diff is clearly shorter (few rows changed).
    #[must_use]
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn generate_frame(&self) -> Option<SspFrame> {
        let (latest_num, latest_state) = self.states.back()?;

        if *latest_num <= self.ack_num {
            return None;
        }

        let ack_state = self.states.iter().find(|(num, _)| *num == self.ack_num);

        if let Some((_, base_state)) = ack_state {
            let incremental = latest_state.diff_from(base_state);

            // When few rows changed, incremental is clearly shorter than init
            // (which includes all non-empty rows). Skip the init computation.
            let total = incremental.total_rows as usize;
            if incremental.changed_rows.len() <= total / 2 {
                return Some(SspFrame {
                    old_num: self.ack_num,
                    new_num: *latest_num,
                    ack_num: 0,
                    diff: Some(incremental),
                });
            }

            // Many rows changed — init might be shorter (e.g. screen clear
            // turns 24 filled rows into 1 non-empty row).
            let init = latest_state.diff_from_empty();
            let inc_encoded = incremental.encode();
            let init_encoded = init.encode();

            if init_encoded.len() < inc_encoded.len() {
                Some(SspFrame {
                    old_num: 0,
                    new_num: *latest_num,
                    ack_num: 0,
                    diff: Some(init),
                })
            } else {
                Some(SspFrame {
                    old_num: self.ack_num,
                    new_num: *latest_num,
                    ack_num: 0,
                    diff: Some(incremental),
                })
            }
        } else {
            let diff = latest_state.diff_from_empty();
            Some(SspFrame {
                old_num: 0,
                new_num: *latest_num,
                ack_num: 0,
                diff: Some(diff),
            })
        }
    }

    /// Prunes the queue to at most `MAX_QUEUE_SIZE`, preserving the ack'd state.
    fn prune(&mut self) {
        while self.states.len() > MAX_QUEUE_SIZE {
            match self.states.front() {
                Some((num, _)) if *num == self.ack_num => {
                    // Don't remove the ack'd state; remove the next oldest instead.
                    // COVERAGE: The else/None branches below are unreachable because the
                    // outer while guarantees len > MAX_QUEUE_SIZE (32), so len > 2 is
                    // always true and the queue is always non-empty. They exist as
                    // defensive guards against future changes to MAX_QUEUE_SIZE.
                    if self.states.len() > 2 {
                        self.states.remove(1);
                    } else {
                        break;
                    }
                }
                Some(_) => {
                    self.states.pop_front();
                }
                None => break,
            }
        }
    }
}

impl Default for SspSender {
    fn default() -> Self {
        Self::new()
    }
}

/// Client-side SSP receiver. Applies incoming diffs to maintain the current
/// screen state.
pub struct SspReceiver {
    state: ScreenState,
    state_num: u64,
}

impl SspReceiver {
    /// Creates a new receiver with an empty screen of the given dimensions.
    #[must_use]
    pub fn new(rows: u16) -> Self {
        Self {
            state: ScreenState::empty(rows),
            state_num: 0,
        }
    }

    /// Processes an incoming SSP frame.
    ///
    /// Returns `Some(new_num)` when the state was updated (caller should render).
    /// Returns `Ok(None)` for ack-only frames, stale frames, or wrong-base frames.
    ///
    /// # Errors
    ///
    /// Returns `SspError::InvalidDiff` if the diff cannot be applied.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn process_frame(&mut self, frame: &SspFrame) -> Result<Option<u64>, SspError> {
        let Some(ref diff) = frame.diff else {
            return Ok(None); // ack-only frame
        };

        // Ignore stale/duplicate frames
        if frame.new_num <= self.state_num {
            return Ok(None);
        }

        // Accept init diffs (old_num=0) or diffs matching our current state
        if frame.old_num != 0 && frame.old_num != self.state_num {
            return Ok(None);
        }

        // For init diffs, reset state before applying
        if frame.old_num == 0 {
            self.state = ScreenState::empty(diff.total_rows);
        }

        self.state.apply_diff(diff)?;
        self.state_num = frame.new_num;
        Ok(Some(frame.new_num))
    }

    /// Returns the current state number (for use as ack value).
    #[must_use]
    pub const fn ack_num(&self) -> u64 {
        self.state_num
    }

    /// Returns a reference to the current screen state.
    #[must_use]
    pub const fn state(&self) -> &ScreenState {
        &self.state
    }
}

/// Detects whether `new` is `old` scrolled up by `k` lines, i.e. the top `k`
/// lines were pushed off and `k` new lines appeared at the bottom.
///
/// Returns `Some(k)` if `old[k..] == new[..n-k]` for some `k >= 1`.
fn detect_scroll_up(old: &ScreenState, new: &ScreenState) -> Option<usize> {
    let n = old.rows.len();
    if n == 0 || n != new.rows.len() {
        return None;
    }
    // Check shift amounts 1..n (stop early once rows diverge)
    for k in 1..n {
        if old.rows[k..] == new.rows[..n - k] {
            return Some(k);
        }
        // Optimisation: if old[k] != new[0] there's no point checking larger k
        // values (they'd require old[k+1..] == new[..n-k-1] which can't hold
        // when old[k] already didn't match new[0]).
        if old.rows[k] != new.rows[0] {
            break;
        }
    }
    None
}

/// Generates minimal ANSI escape sequences to update the real terminal
/// from `old` screen state to `new` screen state.
///
/// When the change is a scroll (content shifted up), emits real newlines
/// at the bottom of the screen so the user's terminal scrolls and builds
/// up a scrollback buffer. Non-scroll changes use absolute cursor
/// positioning to update individual rows in place.
#[must_use]
#[tracing::instrument(level = "trace", skip_all)]
pub fn render_diff_ansi(old: &ScreenState, new: &ScreenState) -> Vec<u8> {
    let mut buf = Vec::new();
    let n = new.rows.len();

    if let Some(k) = detect_scroll_up(old, new) {
        // Scroll path: move cursor to the last row, emit k newlines to
        // cause the real terminal to scroll (pushing old top rows into
        // scrollback), then redraw ALL visible rows to ensure the live
        // area is fully consistent with the SSP state.
        buf.extend_from_slice(format!("\x1b[{n};1H").as_bytes());
        buf.extend(std::iter::repeat_n(b'\n', k));
        for i in 0..n {
            buf.extend_from_slice(format!("\x1b[{};1H\x1b[0m\x1b[2K", i + 1).as_bytes());
            buf.extend_from_slice(new.rows[i].as_bytes());
        }
    } else {
        // Non-scroll path: update changed rows in place
        let max_rows = n.max(old.rows.len());
        for i in 0..max_rows {
            let old_row = old.rows.get(i).map_or("", String::as_str);
            let new_row = new.rows.get(i).map_or("", String::as_str);

            if old_row != new_row {
                buf.extend_from_slice(format!("\x1b[{};1H\x1b[0m\x1b[2K", i + 1).as_bytes());
                buf.extend_from_slice(new_row.as_bytes());
            }
        }
    }

    // Position cursor at final location (1-indexed)
    buf.extend_from_slice(format!("\x1b[{};{}H", new.cursor_y + 1, new.cursor_x + 1).as_bytes());

    buf
}

/// Generates ANSI output for a full terminal redraw including scrollback.
///
/// Wraps output in synchronized-output markers to prevent flicker.
/// Clears the terminal's screen and scrollback buffer, prints all scrollback
/// lines (which naturally scroll into the terminal's native scrollback as
/// more content is printed), then renders the visible screen state and
/// positions the cursor.
///
/// Used when scrollback changes, the terminal resizes, or the client
/// reconnects — cases where incremental [`render_diff_ansi`] is insufficient.
// TODO: use terminal-specific scrollback editing OSCs (e.g., kitty's)
// for smarter partial updates instead of full clear-and-redraw.
#[must_use]
#[tracing::instrument(level = "trace", skip_all)]
pub fn render_full_redraw(scrollback: &[ScrollbackLine], visible: &ScreenState) -> Vec<u8> {
    let mut buf = Vec::new();

    // Begin synchronized output (prevents flicker during redraw)
    buf.extend_from_slice(b"\x1b[?2026h");

    // Clear scrollback + screen + cursor home
    buf.extend_from_slice(b"\x1b[3J\x1b[2J\x1b[H");

    // Print scrollback lines — they naturally scroll off the top into the
    // terminal's native scrollback buffer as more content is printed below
    for line in scrollback {
        buf.extend_from_slice(line.text.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    // Flush any remaining scrollback lines off the visible area.
    // Each scrollback line's \r\n already moved the cursor down once,
    // so we need (visible_rows - 1) additional newlines to push the
    // last visible scrollback lines into the scrollback buffer.
    if !scrollback.is_empty() {
        let flush = visible.rows.len().saturating_sub(1);
        buf.extend(std::iter::repeat_n(b'\n', flush));
    }

    // Render visible rows with absolute positioning
    for (i, row) in visible.rows.iter().enumerate() {
        buf.extend_from_slice(format!("\x1b[{};1H\x1b[0m\x1b[2K", i + 1).as_bytes());
        buf.extend_from_slice(row.as_bytes());
    }

    // Position cursor at final location (1-indexed)
    buf.extend_from_slice(
        format!("\x1b[{};{}H", visible.cursor_y + 1, visible.cursor_x + 1).as_bytes(),
    );

    // End synchronized output
    buf.extend_from_slice(b"\x1b[?2026l");

    buf
}

/// Client-side keystroke predictor.
///
/// Maintains a local terminal emulator that processes keystrokes immediately,
/// providing instant visual feedback before the server confirms the state.
/// When the server state arrives, it is reconciled with the prediction.
pub struct Predictor {
    terminal: crate::terminal::RoseTerminal,
    confirmed_state: ScreenState,
    active: bool,
    last_keystroke: std::time::Instant,
}

/// Prediction timeout: after this duration without keystrokes, predictions
/// are discarded in favor of the server state.
const PREDICTION_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

impl Predictor {
    /// Creates a new predictor with the given terminal dimensions.
    #[must_use]
    pub fn new(rows: u16, cols: u16) -> Self {
        Self {
            terminal: crate::terminal::RoseTerminal::new(rows, cols),
            confirmed_state: ScreenState::empty(rows),
            active: false,
            last_keystroke: std::time::Instant::now(),
        }
    }

    /// Feeds a keystroke into the local terminal for prediction.
    ///
    /// Returns the predicted screen state after this keystroke.
    pub fn predict_keystroke(&mut self, data: &[u8]) -> ScreenState {
        self.terminal.advance(data);
        self.active = true;
        self.last_keystroke = std::time::Instant::now();
        self.terminal.snapshot()
    }

    /// Reconciles the prediction with the authoritative server state.
    ///
    /// - If no prediction is active, returns the server state.
    /// - If the prediction has expired (>500ms since last keystroke), returns
    ///   the server state and deactivates prediction.
    /// - If prediction is active and recent, returns the predicted state
    ///   (local terminal snapshot).
    #[must_use]
    pub fn reconcile(&mut self, server_state: &ScreenState) -> ScreenState {
        self.confirmed_state = server_state.clone();

        if !self.active {
            return server_state.clone();
        }

        if self.last_keystroke.elapsed() > PREDICTION_TIMEOUT {
            // Prediction expired — trust server, sync local terminal
            self.active = false;
            self.sync_terminal(server_state);
            return server_state.clone();
        }

        // Prediction still active — use local terminal state
        self.terminal.snapshot()
    }

    /// Resizes the prediction terminal.
    pub fn resize(&mut self, rows: u16, cols: u16) {
        self.terminal.resize(rows, cols);
    }

    /// Returns the current predicted screen state.
    #[must_use]
    pub fn predicted_state(&self) -> ScreenState {
        self.terminal.snapshot()
    }

    /// Syncs the local terminal to match the server state.
    ///
    /// Resets the terminal and replays the server state content.
    fn sync_terminal(&mut self, state: &ScreenState) {
        let (rows, cols) = self.terminal.size();
        self.terminal = crate::terminal::RoseTerminal::new(rows as u16, cols as u16);
        // Replay server state by writing each row
        for (i, row) in state.rows.iter().enumerate() {
            if !row.is_empty() {
                self.terminal
                    .advance(format!("\x1b[{};1H{}", i + 1, row).as_bytes());
            }
        }
        // Position cursor
        self.terminal
            .advance(format!("\x1b[{};{}H", state.cursor_y + 1, state.cursor_x + 1).as_bytes());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // -- ScreenState diffing --------------------------------------------------

    #[test]
    fn diff_identical_states() {
        let state = ScreenState {
            rows: vec!["hello".into(), "world".into()],
            cursor_x: 3,
            cursor_y: 1,
        };
        let diff = state.diff_from(&state);
        assert!(diff.changed_rows.is_empty());
        assert_eq!(diff.cursor_x, 3);
        assert_eq!(diff.cursor_y, 1);
        assert_eq!(diff.total_rows, 2);
    }

    #[test]
    fn diff_one_row_changed() {
        let old = ScreenState {
            rows: vec!["hello".into(), "world".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        let new = ScreenState {
            rows: vec!["hello".into(), "earth".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        let diff = new.diff_from(&old);
        assert_eq!(diff.changed_rows, vec![(1, "earth".into())]);
    }

    #[test]
    fn diff_cursor_only() {
        let old = ScreenState {
            rows: vec!["abc".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        let new = ScreenState {
            rows: vec!["abc".into()],
            cursor_x: 3,
            cursor_y: 0,
        };
        let diff = new.diff_from(&old);
        assert!(diff.changed_rows.is_empty());
        assert_eq!(diff.cursor_x, 3);
    }

    #[test]
    fn diff_from_none_includes_all_nonempty() {
        let state = ScreenState {
            rows: vec!["hello".into(), String::new(), "world".into()],
            cursor_x: 5,
            cursor_y: 2,
        };
        let diff = state.diff_from_empty();
        assert_eq!(
            diff.changed_rows,
            vec![(0, "hello".into()), (2, "world".into())]
        );
        assert_eq!(diff.total_rows, 3);
    }

    #[test]
    fn apply_diff_roundtrip() {
        let old = ScreenState {
            rows: vec!["aaa".into(), "bbb".into(), "ccc".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        let new = ScreenState {
            rows: vec!["aaa".into(), "XXX".into(), "ccc".into()],
            cursor_x: 2,
            cursor_y: 1,
        };
        let diff = new.diff_from(&old);
        let mut applied = old;
        applied.apply_diff(&diff).unwrap();
        assert_eq!(applied, new);
    }

    #[test]
    fn apply_diff_resize() {
        let mut state = ScreenState {
            rows: vec!["a".into(), "b".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        let diff = ScreenDiff {
            changed_rows: vec![(2, "c".into())],
            cursor_x: 0,
            cursor_y: 2,
            total_rows: 4,
        };
        state.apply_diff(&diff).unwrap();
        assert_eq!(state.rows.len(), 4);
        assert_eq!(state.rows[2], "c");
        assert_eq!(state.rows[3], "");
    }

    // -- ScreenDiff encode/decode ---------------------------------------------

    #[test]
    fn screen_diff_encode_decode() {
        let diff = ScreenDiff {
            changed_rows: vec![(0, "hello".into()), (3, "world".into())],
            cursor_x: 5,
            cursor_y: 0,
            total_rows: 24,
        };
        let encoded = diff.encode();
        let decoded = ScreenDiff::decode(&encoded).unwrap();
        assert_eq!(diff, decoded);
    }

    // -- SspFrame encode/decode -----------------------------------------------

    #[test]
    fn ssp_frame_encode_decode() {
        let frame = SspFrame {
            old_num: 1,
            new_num: 2,
            ack_num: 0,
            diff: Some(ScreenDiff {
                changed_rows: vec![(0, "test".into())],
                cursor_x: 4,
                cursor_y: 0,
                total_rows: 24,
            }),
        };
        let encoded = frame.encode();
        let decoded = SspFrame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn ssp_frame_ack_only() {
        let frame = SspFrame::ack_only(42);
        let encoded = frame.encode();
        let decoded = SspFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.ack_num, 42);
        assert!(decoded.diff.is_none());
    }

    // -- SspSender ------------------------------------------------------------

    #[test]
    fn sender_push_and_generate() {
        let mut sender = SspSender::new();
        let mut rows = vec![String::new(); 24];
        rows[0] = "hello".into();
        sender.push_state(ScreenState {
            rows,
            cursor_x: 5,
            cursor_y: 0,
        });

        let frame = sender.generate_frame().unwrap();
        assert_eq!(frame.old_num, 0, "first frame should be init diff");
        assert_eq!(frame.new_num, 1);
        let diff = frame.diff.unwrap();
        assert_eq!(diff.changed_rows, vec![(0, "hello".into())]);
    }

    #[test]
    fn sender_incremental_after_ack() {
        let mut sender = SspSender::new();

        // Push state 1 with multiple non-empty rows
        let mut rows1 = vec![String::new(); 24];
        rows1[0] = "line one".into();
        rows1[1] = "line two".into();
        rows1[2] = "line three".into();
        sender.push_state(ScreenState {
            rows: rows1,
            cursor_x: 0,
            cursor_y: 0,
        });
        sender.process_ack(1);

        // Push state 2 changing only one row
        let mut rows2 = vec![String::new(); 24];
        rows2[0] = "line one".into();
        rows2[1] = "line two MODIFIED".into();
        rows2[2] = "line three".into();
        sender.push_state(ScreenState {
            rows: rows2,
            cursor_x: 0,
            cursor_y: 0,
        });

        let frame = sender.generate_frame().unwrap();
        assert_eq!(frame.new_num, 2);
        // Incremental is shorter (1 changed row) than init (3 changed rows)
        assert_eq!(frame.old_num, 1);
        let diff = frame.diff.unwrap();
        assert_eq!(diff.changed_rows.len(), 1);
        assert_eq!(diff.changed_rows[0], (1, "line two MODIFIED".into()));
    }

    #[test]
    fn sender_no_change_no_frame() {
        let mut sender = SspSender::new();
        sender.push_state(ScreenState::empty(24));
        sender.process_ack(1);
        assert!(sender.generate_frame().is_none());
    }

    #[test]
    fn sender_prune_respects_ack() {
        let mut sender = SspSender::new();

        // Push state 1 and ack it
        let mut rows = vec![String::new(); 24];
        rows[0] = "hello".into();
        sender.push_state(ScreenState {
            rows: rows.clone(),
            cursor_x: 0,
            cursor_y: 0,
        });
        sender.process_ack(1);

        // Push 32 more identical states (nums 2..=33), triggering pruning
        for _ in 0..32 {
            sender.push_state(ScreenState {
                rows: rows.clone(),
                cursor_x: 0,
                cursor_y: 0,
            });
        }

        // Push one more with a change
        let mut rows2 = vec![String::new(); 24];
        rows2[0] = "hello world".into();
        sender.push_state(ScreenState {
            rows: rows2,
            cursor_x: 0,
            cursor_y: 0,
        });

        let frame = sender.generate_frame().unwrap();
        assert_eq!(frame.new_num, 34);
        // Ack'd state 1 should be retained, enabling incremental diff
        assert_eq!(
            frame.old_num, 1,
            "ack'd state should be retained as diff base"
        );
    }

    // -- SspReceiver ----------------------------------------------------------

    #[test]
    fn receiver_apply_sequential() {
        let mut receiver = SspReceiver::new(24);

        // Frame 1: init diff
        let frame1 = SspFrame {
            old_num: 0,
            new_num: 1,
            ack_num: 0,
            diff: Some(ScreenDiff {
                changed_rows: vec![(0, "hello".into())],
                cursor_x: 5,
                cursor_y: 0,
                total_rows: 24,
            }),
        };
        assert_eq!(receiver.process_frame(&frame1).unwrap(), Some(1));
        assert_eq!(receiver.state().rows[0], "hello");

        // Frame 2: incremental
        let frame2 = SspFrame {
            old_num: 1,
            new_num: 2,
            ack_num: 0,
            diff: Some(ScreenDiff {
                changed_rows: vec![(1, "world".into())],
                cursor_x: 5,
                cursor_y: 1,
                total_rows: 24,
            }),
        };
        assert_eq!(receiver.process_frame(&frame2).unwrap(), Some(2));
        assert_eq!(receiver.state().rows[0], "hello");
        assert_eq!(receiver.state().rows[1], "world");
    }

    #[test]
    fn receiver_ignore_stale() {
        let mut receiver = SspReceiver::new(24);
        // Apply init to get to state 2
        let frame = SspFrame {
            old_num: 0,
            new_num: 2,
            ack_num: 0,
            diff: Some(ScreenDiff {
                changed_rows: vec![(0, "current".into())],
                cursor_x: 0,
                cursor_y: 0,
                total_rows: 24,
            }),
        };
        receiver.process_frame(&frame).unwrap();

        // Stale frame (new_num=1 <= state_num=2)
        let stale = SspFrame {
            old_num: 0,
            new_num: 1,
            ack_num: 0,
            diff: Some(ScreenDiff {
                changed_rows: vec![(0, "old".into())],
                cursor_x: 0,
                cursor_y: 0,
                total_rows: 24,
            }),
        };
        assert_eq!(receiver.process_frame(&stale).unwrap(), None);
        assert_eq!(receiver.state().rows[0], "current");
    }

    #[test]
    fn receiver_ignore_wrong_base() {
        let mut receiver = SspReceiver::new(24);
        // Get to state 2
        let frame = SspFrame {
            old_num: 0,
            new_num: 2,
            ack_num: 0,
            diff: Some(ScreenDiff {
                changed_rows: vec![(0, "at two".into())],
                cursor_x: 0,
                cursor_y: 0,
                total_rows: 24,
            }),
        };
        receiver.process_frame(&frame).unwrap();

        // Frame with wrong base (old_num=1, but receiver is at 2)
        let wrong_base = SspFrame {
            old_num: 1,
            new_num: 3,
            ack_num: 0,
            diff: Some(ScreenDiff {
                changed_rows: vec![(0, "wrong base".into())],
                cursor_x: 0,
                cursor_y: 0,
                total_rows: 24,
            }),
        };
        assert_eq!(receiver.process_frame(&wrong_base).unwrap(), None);
        assert_eq!(receiver.state().rows[0], "at two");
    }

    #[test]
    fn receiver_init_diff_resets() {
        let mut receiver = SspReceiver::new(24);
        // Get to state 2 with some content
        let frame = SspFrame {
            old_num: 0,
            new_num: 2,
            ack_num: 0,
            diff: Some(ScreenDiff {
                changed_rows: vec![(0, "old content".into())],
                cursor_x: 0,
                cursor_y: 0,
                total_rows: 24,
            }),
        };
        receiver.process_frame(&frame).unwrap();
        assert_eq!(receiver.state().rows[0], "old content");

        // Init diff (old_num=0) resets and applies new state
        let reset = SspFrame {
            old_num: 0,
            new_num: 5,
            ack_num: 0,
            diff: Some(ScreenDiff {
                changed_rows: vec![(0, "fresh".into())],
                cursor_x: 5,
                cursor_y: 0,
                total_rows: 24,
            }),
        };
        assert_eq!(receiver.process_frame(&reset).unwrap(), Some(5));
        assert_eq!(receiver.state().rows[0], "fresh");
        // Old content on row 0 is replaced; other rows are empty after reset
        assert_eq!(receiver.state().rows[1], "");
        assert_eq!(receiver.ack_num(), 5);
    }

    // -- render_diff_ansi -----------------------------------------------------

    #[test]
    fn render_diff_changed_row() {
        let old = ScreenState {
            rows: vec!["abc".into(), "def".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        let new = ScreenState {
            rows: vec!["abc".into(), "xyz".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        let ansi = render_diff_ansi(&old, &new);
        let s = String::from_utf8(ansi).unwrap();
        // Should move to row 2 (1-indexed), clear line, write "xyz"
        assert!(s.contains("\x1b[2;1H"));
        assert!(s.contains("\x1b[2K"));
        assert!(s.contains("xyz"));
        // Should NOT re-draw unchanged row 1
        assert!(!s.contains("abc"));
    }

    #[test]
    fn render_diff_cursor_position() {
        let old = ScreenState {
            rows: vec!["same".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        let new = ScreenState {
            rows: vec!["same".into()],
            cursor_x: 4,
            cursor_y: 0,
        };
        let ansi = render_diff_ansi(&old, &new);
        let s = String::from_utf8(ansi).unwrap();
        // No row changes, but cursor should be positioned at (0, 4) → CSI 1;5 H
        assert!(s.contains("\x1b[1;5H"));
    }

    // -- Full redraw -----------------------------------------------------------

    #[test]
    fn render_full_redraw_no_scrollback() {
        let state = ScreenState {
            rows: vec!["hello".into(), "world".into()],
            cursor_x: 5,
            cursor_y: 0,
        };
        let ansi = render_full_redraw(&[], &state);
        let s = String::from_utf8(ansi).unwrap();

        // Synchronized output markers
        assert!(s.starts_with("\x1b[?2026h"));
        assert!(s.ends_with("\x1b[?2026l"));

        // Clear sequence
        assert!(s.contains("\x1b[3J\x1b[2J\x1b[H"));

        // No extra newlines when there's no scrollback
        let clear_end = s.find("\x1b[H").unwrap() + 3;
        let first_row = s.find("\x1b[1;1H").unwrap();
        assert_eq!(
            &s[clear_end..first_row],
            "",
            "no newlines between clear and first row when no scrollback"
        );

        // Visible rows rendered
        assert!(s.contains("hello"));
        assert!(s.contains("world"));

        // Cursor positioned
        assert!(s.contains("\x1b[1;6H"));
    }

    #[test]
    fn render_full_redraw_with_scrollback() {
        use crate::scrollback::ScrollbackLine;

        let scrollback = vec![
            ScrollbackLine {
                stable_row: 0,
                text: "sb line 0".into(),
            },
            ScrollbackLine {
                stable_row: 1,
                text: "sb line 1".into(),
            },
            ScrollbackLine {
                stable_row: 2,
                text: "sb line 2".into(),
            },
        ];
        let state = ScreenState {
            rows: vec!["visible A".into(), "visible B".into()],
            cursor_x: 3,
            cursor_y: 1,
        };
        let ansi = render_full_redraw(&scrollback, &state);
        let s = String::from_utf8(ansi).unwrap();

        // Sync markers
        assert!(s.starts_with("\x1b[?2026h"));
        assert!(s.ends_with("\x1b[?2026l"));

        // Scrollback lines present in order
        let pos0 = s.find("sb line 0\r\n").unwrap();
        let pos1 = s.find("sb line 1\r\n").unwrap();
        let pos2 = s.find("sb line 2\r\n").unwrap();
        assert!(pos0 < pos1);
        assert!(pos1 < pos2);

        // Flush newlines present (1 for 2 visible rows minus 1)
        let after_sb = pos2 + "sb line 2\r\n".len();
        let flush_region = &s[after_sb..s.find("\x1b[1;1H").unwrap()];
        assert_eq!(flush_region.matches('\n').count(), 1);

        // Visible rows rendered
        assert!(s.contains("visible A"));
        assert!(s.contains("visible B"));

        // Cursor at (3, 1) → CSI 2;4H
        assert!(s.contains("\x1b[2;4H"));
    }

    #[test]
    fn render_full_redraw_scrollback_text_preserved() {
        use crate::scrollback::ScrollbackLine;

        let scrollback = vec![
            ScrollbackLine {
                stable_row: 0,
                text: "$ ls -la".into(),
            },
            ScrollbackLine {
                stable_row: 1,
                text: "total 42".into(),
            },
        ];
        let state = ScreenState::empty(3);
        let ansi = render_full_redraw(&scrollback, &state);
        let s = String::from_utf8(ansi).unwrap();

        assert!(s.contains("$ ls -la\r\n"));
        assert!(s.contains("total 42\r\n"));
        // Order preserved
        assert!(s.find("$ ls -la").unwrap() < s.find("total 42").unwrap());
    }

    // -- Wire format edge cases -----------------------------------------------

    #[test]
    fn decode_truncated_frame_is_error() {
        assert!(SspFrame::decode(&[0x01; 10]).is_err());
    }

    #[test]
    fn decode_unknown_frame_type_is_error() {
        let mut data = vec![0xFF];
        data.extend_from_slice(&[0u8; 24]);
        assert!(SspFrame::decode(&data).is_err());
    }

    #[test]
    fn decode_truncated_diff_is_error() {
        // Valid frame header but truncated diff
        let mut data = vec![FRAME_STATE_UPDATE];
        data.extend_from_slice(&0u64.to_be_bytes());
        data.extend_from_slice(&1u64.to_be_bytes());
        data.extend_from_slice(&0u64.to_be_bytes());
        // Only 4 bytes of diff (needs 8 minimum)
        data.extend_from_slice(&[0u8; 4]);
        assert!(SspFrame::decode(&data).is_err());
    }

    #[test]
    fn apply_diff_out_of_bounds_is_error() {
        let mut state = ScreenState::empty(2);
        let diff = ScreenDiff {
            changed_rows: vec![(5, "oob".into())],
            cursor_x: 0,
            cursor_y: 0,
            total_rows: 2,
        };
        assert!(state.apply_diff(&diff).is_err());
    }

    #[test]
    fn screen_diff_decode_invalid_utf8() {
        let mut data = vec![0u8; 8]; // header: all zeros (cursor, total_rows, num_changed=0)
        // Set num_changed to 1
        data[6] = 0;
        data[7] = 1;
        // Row header: index=0, text_len=2
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        // Invalid UTF-8 bytes
        data.extend_from_slice(&[0xFF, 0xFE]);
        assert!(ScreenDiff::decode(&data).is_err());
    }

    #[test]
    fn screen_diff_decode_truncated_row_header() {
        let mut data = vec![0u8; 8];
        // Set num_changed to 1
        data[6] = 0;
        data[7] = 1;
        // Only 2 bytes of row header (needs 4)
        data.extend_from_slice(&[0u8; 2]);
        assert!(ScreenDiff::decode(&data).is_err());
    }

    #[test]
    fn screen_diff_decode_truncated_row_text() {
        let mut data = vec![0u8; 8];
        // Set num_changed to 1
        data[6] = 0;
        data[7] = 1;
        // Row header: index=0, text_len=10
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&10u16.to_be_bytes());
        // Only 3 bytes of text (needs 10)
        data.extend_from_slice(&[b'a'; 3]);
        assert!(ScreenDiff::decode(&data).is_err());
    }

    // -- Additional coverage tests --------------------------------------------

    #[test]
    fn sender_current_num() {
        let mut sender = SspSender::new();
        assert_eq!(sender.current_num(), 0);
        sender.push_state(ScreenState::empty(24));
        assert_eq!(sender.current_num(), 1);
        sender.push_state(ScreenState::empty(24));
        assert_eq!(sender.current_num(), 2);
    }

    #[test]
    fn sender_generate_frame_empty() {
        let sender = SspSender::new();
        assert!(sender.generate_frame().is_none());
    }

    #[test]
    fn sender_default() {
        let sender = SspSender::default();
        assert_eq!(sender.current_num(), 0);
    }

    #[test]
    fn sender_init_shorter_than_incremental() {
        // When most rows changed, init diff (only non-empty rows) can be shorter
        // than incremental diff (all changed rows including rows that became empty).
        let mut sender = SspSender::new();

        // State 1: all 24 rows filled
        let rows1: Vec<String> = (0..24)
            .map(|i| format!("row {i} with lots of text padding here"))
            .collect();
        sender.push_state(ScreenState {
            rows: rows1,
            cursor_x: 0,
            cursor_y: 0,
        });
        sender.process_ack(1);

        // State 2: only 1 row non-empty (23 rows went from filled to empty)
        // Incremental: 24 changed rows (23 became empty + 1 changed)
        // Init: 1 changed row (just the non-empty one)
        let mut rows2 = vec![String::new(); 24];
        rows2[0] = "only this row".into();
        sender.push_state(ScreenState {
            rows: rows2,
            cursor_x: 0,
            cursor_y: 0,
        });

        let frame = sender.generate_frame().unwrap();
        assert_eq!(frame.new_num, 2);
        // Init diff should be chosen (shorter: 1 row vs 24 rows)
        assert_eq!(frame.old_num, 0, "init diff should be shorter here");
    }

    #[test]
    fn sender_prune_without_ack() {
        // When no ack has been received, prune removes the oldest (non-ack'd) state
        let mut sender = SspSender::new();
        // Push 33 states without acking — ack_num stays 0, no state has num=0
        for _ in 0..33 {
            sender.push_state(ScreenState::empty(24));
        }
        // Queue should be pruned to 32
        assert_eq!(sender.current_num(), 33);
        // Should still generate a frame (init diff since ack_num=0 not in queue)
        let frame = sender.generate_frame().unwrap();
        assert_eq!(frame.old_num, 0);
    }

    #[test]
    fn sender_stale_ack_ignored() {
        let mut sender = SspSender::new();
        sender.push_state(ScreenState::empty(24));
        sender.process_ack(1);
        // Stale ack (1 is not > current ack_num of 1)
        sender.process_ack(1);
        // Even older ack
        sender.process_ack(0);
        // State should still work
        assert!(sender.generate_frame().is_none());
    }

    #[test]
    fn receiver_ack_only_frame_ignored() {
        let mut receiver = SspReceiver::new(24);
        let ack_frame = SspFrame::ack_only(5);
        assert_eq!(receiver.process_frame(&ack_frame).unwrap(), None);
        assert_eq!(receiver.ack_num(), 0); // unchanged
    }

    #[test]
    fn ssp_frame_stream_encode_decode() {
        let frame = SspFrame {
            old_num: 0,
            new_num: 1,
            ack_num: 0,
            diff: Some(ScreenDiff {
                changed_rows: vec![(0, "hello stream".into())],
                cursor_x: 12,
                cursor_y: 0,
                total_rows: 24,
            }),
        };
        let encoded = frame.encode_for_stream();
        let decoded = SspFrame::decode_from_stream(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn ssp_frame_stream_decode_truncated_header() {
        assert!(SspFrame::decode_from_stream(&[0, 0]).is_err());
    }

    #[test]
    fn ssp_frame_stream_decode_truncated_body() {
        // Length says 100 bytes but only 4 + 2 bytes present
        let data = vec![0, 0, 0, 100, 0, 0];
        assert!(SspFrame::decode_from_stream(&data).is_err());
    }

    #[test]
    fn receiver_rejects_invalid_diff() {
        let mut receiver = SspReceiver::new(2);
        // Frame with row index out of bounds for the total_rows
        let bad_frame = SspFrame {
            old_num: 0,
            new_num: 1,
            ack_num: 0,
            diff: Some(ScreenDiff {
                changed_rows: vec![(5, "oob".into())],
                cursor_x: 0,
                cursor_y: 0,
                total_rows: 2,
            }),
        };
        assert!(receiver.process_frame(&bad_frame).is_err());
    }

    // -- Predictor --------------------------------------------------------

    #[test]
    fn predictor_basic() {
        let mut predictor = Predictor::new(24, 80);
        let state = predictor.predict_keystroke(b"hello");
        assert!(state.rows[0].contains("hello"));
    }

    #[test]
    fn predictor_reconcile_no_prediction() {
        let mut predictor = Predictor::new(24, 80);
        let server_state = ScreenState {
            rows: vec!["server".into(); 24],
            cursor_x: 6,
            cursor_y: 0,
        };
        let result = predictor.reconcile(&server_state);
        assert_eq!(result, server_state);
    }

    #[test]
    fn predictor_reconcile_active_prediction() {
        let mut predictor = Predictor::new(24, 80);
        predictor.predict_keystroke(b"local");

        let server_state = ScreenState::empty(24);
        // Prediction is recent and active — should return predicted state
        let result = predictor.reconcile(&server_state);
        assert!(
            result.rows[0].contains("local"),
            "active prediction should override server state"
        );
    }

    #[test]
    fn predictor_reconcile_expired() {
        let mut predictor = Predictor::new(24, 80);
        predictor.predict_keystroke(b"old");

        // Force expiration by backdating the last keystroke
        predictor.last_keystroke = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();

        let mut server_rows = vec![String::new(); 24];
        server_rows[0] = "server-confirmed".into();
        let server_state = ScreenState {
            rows: server_rows,
            cursor_x: 16,
            cursor_y: 0,
        };
        let result = predictor.reconcile(&server_state);
        assert_eq!(
            result.rows[0], "server-confirmed",
            "expired prediction should yield server state"
        );
    }

    #[test]
    fn predictor_resize() {
        let mut predictor = Predictor::new(24, 80);
        predictor.resize(40, 120);
        let state = predictor.predicted_state();
        assert_eq!(state.rows.len(), 40);
    }

    #[test]
    fn detect_scroll_up_empty_state() {
        let old = ScreenState::empty(0);
        let new = ScreenState::empty(0);
        assert_eq!(detect_scroll_up(&old, &new), None);
    }

    #[test]
    fn detect_scroll_up_mismatched_rows() {
        let old = ScreenState::empty(3);
        let new = ScreenState::empty(5);
        assert_eq!(detect_scroll_up(&old, &new), None);
    }

    #[test]
    fn detect_scroll_up_no_scroll() {
        let state = ScreenState {
            rows: vec!["a".into(), "b".into(), "c".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        assert_eq!(detect_scroll_up(&state, &state), None);
    }

    #[test]
    fn detect_scroll_up_one_line() {
        let old = ScreenState {
            rows: vec!["a".into(), "b".into(), "c".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        let new = ScreenState {
            rows: vec!["b".into(), "c".into(), "d".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        assert_eq!(detect_scroll_up(&old, &new), Some(1));
    }

    #[test]
    fn detect_scroll_up_early_exit() {
        // old[1] != new[0], so k>1 can't work
        let old = ScreenState {
            rows: vec!["a".into(), "x".into(), "c".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        let new = ScreenState {
            rows: vec!["y".into(), "z".into(), "w".into()],
            cursor_x: 0,
            cursor_y: 0,
        };
        assert_eq!(detect_scroll_up(&old, &new), None);
    }

    #[test]
    fn sender_queue_pruning_with_ack() {
        let mut sender = SspSender::new();
        // Push many states to exceed MAX_QUEUE_SIZE
        for i in 0..35 {
            let state = ScreenState {
                rows: vec![format!("line {i}")],
                cursor_x: 0,
                cursor_y: 0,
            };
            sender.push_state(state);
        }
        // Ack state 1 so it's retained during pruning
        sender.process_ack(1);
        // Queue should be pruned, but state 1 should still be there
        let frame = sender.generate_frame();
        assert!(frame.is_some());
    }
}
