//! Session persistence for `RoSE`.
//!
//! Manages detached sessions that survive network disconnections.
//! When a client disconnects, the PTY, terminal emulator, and SSP
//! state are preserved in a [`SessionStore`]. Reconnecting clients
//! can resume where they left off.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::pty::PtySession;
use crate::ssp::{ScreenState, SspFrame, SspSender};
use crate::terminal::RoseTerminal;

/// A session that has been detached from its network connection.
///
/// Contains all the state needed to resume: the PTY, terminal emulator,
/// and SSP sender.
pub struct DetachedSession {
    /// The running PTY (still alive while detached).
    pub pty: PtySession,
    /// Server-side terminal emulator state.
    pub terminal: Arc<Mutex<RoseTerminal>>,
    /// SSP sender with accumulated state history.
    pub ssp_sender: Arc<Mutex<SspSender>>,
    /// Terminal rows at time of detach.
    pub rows: u16,
    /// Terminal columns at time of detach.
    pub cols: u16,
    /// DER-encoded TLS client certificate of the session owner.
    /// Used to verify that only the original client can reconnect.
    pub owner_cert_der: Option<Vec<u8>>,
    /// When this session was detached (for idle timeout pruning).
    pub detached_at: Instant,
}

/// Thread-safe store of detached sessions indexed by session ID.
#[derive(Clone)]
pub struct SessionStore {
    state: Arc<Mutex<SessionState>>,
}

#[derive(Default)]
struct SessionState {
    sessions: HashMap<[u8; 16], DetachedSession>,
    ended: HashSet<[u8; 16]>,
    ended_order: VecDeque<[u8; 16]>,
    final_screens: VecDeque<([u8; 16], Arc<FinalCheckpoint>)>,
}

/// A completed session's final screen, without PTY or emulator resources.
pub(crate) struct FinalCheckpoint {
    /// Length-prefixed full SSP frame with sequence number one.
    pub data: Box<[u8]>,
    /// Original session owner's TLS certificate.
    pub owner_cert_der: Option<Vec<u8>>,
    expires_at: Instant,
}

impl FinalCheckpoint {
    fn retained_bytes(&self) -> usize {
        self.data.len() + self.owner_cert_der.as_ref().map_or(0, Vec::len)
    }
}

impl SessionStore {
    /// Creates an empty session store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(SessionState::default())),
        }
    }

    /// Inserts a detached session. Returns the previous session if one
    /// existed for this ID.
    ///
    /// # Panics
    ///
    /// Panics if the session store mutex is poisoned.
    #[must_use]
    pub fn insert(&self, id: [u8; 16], session: DetachedSession) -> Option<DetachedSession> {
        self.state
            .lock()
            .expect("session store lock poisoned")
            .sessions
            .insert(id, session)
    }

    /// Removes and returns a session by ID, or `None` if not found.
    ///
    /// # Panics
    ///
    /// Panics if the session store mutex is poisoned.
    #[must_use]
    pub fn remove(&self, id: &[u8; 16]) -> Option<DetachedSession> {
        self.state
            .lock()
            .expect("session store lock poisoned")
            .sessions
            .remove(id)
    }

    pub(crate) fn mark_ended(&self, id: [u8; 16]) {
        const MAX_ENDED_SESSIONS: usize = 1_024;

        let mut state = self.state.lock().expect("session store lock poisoned");
        if state.ended.insert(id) {
            state.ended_order.push_back(id);
        }
        if state.ended_order.len() > MAX_ENDED_SESSIONS
            && let Some(expired) = state.ended_order.pop_front()
        {
            state.ended.remove(&expired);
            state.final_screens.retain(|(id, _)| *id != expired);
        }
    }

    pub(crate) fn is_ended(&self, id: &[u8; 16]) -> bool {
        self.state
            .lock()
            .expect("session store lock poisoned")
            .ended
            .contains(id)
    }

    /// Retains a final screen for at most one minute, within shared cache limits.
    pub(crate) fn retain_final_screen(
        &self,
        id: [u8; 16],
        screen: ScreenState,
        owner_cert_der: Option<Vec<u8>>,
    ) {
        let frame = SspFrame {
            old_num: 0,
            new_num: 1,
            ack_num: 0,
            diff: Some(screen.bounded_for_transport().diff_from_empty()),
        };
        let checkpoint = Arc::new(FinalCheckpoint {
            data: frame.encode_for_stream().into_boxed_slice(),
            owner_cert_der,
            expires_at: Instant::now() + Duration::from_secs(60),
        });
        let mut state = self.state.lock().expect("session store lock poisoned");
        state
            .final_screens
            .retain(|(key, old)| *key != id && old.expires_at > Instant::now());
        state.final_screens.push_back((id, checkpoint));
        while state.final_screens.len() > 64
            || state
                .final_screens
                .iter()
                .map(|(_, checkpoint)| checkpoint.retained_bytes())
                .sum::<usize>()
                > 64 * 1024 * 1024
        {
            state.final_screens.pop_front();
        }
    }

    /// Looks up a retained screen without consuming it on a failed reconnect.
    pub(crate) fn final_screen(&self, id: &[u8; 16]) -> Option<Arc<FinalCheckpoint>> {
        let mut state = self.state.lock().expect("session store lock poisoned");
        state
            .final_screens
            .retain(|(_, checkpoint)| checkpoint.expires_at > Instant::now());
        state
            .final_screens
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, checkpoint)| Arc::clone(checkpoint))
    }

    /// Releases a completed screen after its application acknowledgment.
    pub(crate) fn remove_final_screen(&self, id: &[u8; 16]) {
        self.state
            .lock()
            .expect("session store lock poisoned")
            .final_screens
            .retain(|(key, _)| key != id);
    }

    /// Remaining lifetime of the newest retained screen, including expired entries.
    pub(crate) fn final_screen_timeout(&self) -> Option<Duration> {
        self.state
            .lock()
            .expect("session store lock poisoned")
            .final_screens
            .back()
            .map(|(_, checkpoint)| {
                checkpoint
                    .expires_at
                    .saturating_duration_since(Instant::now())
            })
    }

    /// Returns `true` if a session with the given ID exists.
    ///
    /// # Panics
    ///
    /// Panics if the session store mutex is poisoned.
    #[must_use]
    pub fn contains(&self, id: &[u8; 16]) -> bool {
        self.state
            .lock()
            .expect("session store lock poisoned")
            .sessions
            .contains_key(id)
    }

    /// Returns the number of detached sessions.
    ///
    /// # Panics
    ///
    /// Panics if the session store mutex is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .expect("session store lock poisoned")
            .sessions
            .len()
    }

    /// Returns `true` if there are no detached sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes and returns an arbitrary detached session.
    ///
    /// # Panics
    ///
    /// Panics if the session store mutex is poisoned.
    #[must_use]
    pub fn remove_any(&self) -> Option<([u8; 16], DetachedSession)> {
        let mut state = self.state.lock().expect("session store lock poisoned");
        let id = *state.sessions.keys().next()?;
        state.sessions.remove(&id).map(|session| (id, session))
    }

    /// Removes detached sessions that have been idle longer than `timeout`.
    /// Returns the number of removed sessions.
    ///
    /// # Panics
    ///
    /// Panics if the session store mutex is poisoned.
    #[must_use]
    pub fn prune_idle(&self, timeout: Duration) -> usize {
        let mut state = self.state.lock().expect("session store lock poisoned");
        let expired: Vec<_> = state
            .sessions
            .iter()
            .filter_map(|(id, detached)| (detached.detached_at.elapsed() >= timeout).then_some(*id))
            .collect();
        for id in &expired {
            state.sessions.remove(id);
        }
        drop(state);
        for id in &expired {
            self.mark_ended(*id);
        }
        expired.len()
    }

    /// Removes detached sessions whose PTY child has already exited.
    /// Returns the number of removed sessions.
    ///
    /// # Panics
    ///
    /// Panics if the session store mutex is poisoned.
    #[must_use]
    pub fn prune_exited(&self) -> usize {
        let mut state = self.state.lock().expect("session store lock poisoned");
        let exited: Vec<_> = state
            .sessions
            .iter_mut()
            .filter_map(|(id, detached)| detached.pty.try_wait().ok().flatten().map(|_| *id))
            .collect();
        for id in &exited {
            state.sessions.remove(id);
        }
        drop(state);
        for id in &exited {
            self.mark_ended(*id);
        }
        exited.len()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn final_checkpoints_expire_without_extending_on_reconnect() {
        let store = SessionStore::new();
        let id = [1; 16];
        store.mark_ended(id);
        store.retain_final_screen(id, ScreenState::empty(2), None);
        let first_expiry = store.final_screen(&id).unwrap().expires_at;
        assert_eq!(store.final_screen(&id).unwrap().expires_at, first_expiry);
        {
            let mut state = store.state.lock().unwrap();
            Arc::get_mut(&mut state.final_screens[0].1)
                .unwrap()
                .expires_at = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        }
        assert_eq!(store.final_screen_timeout(), Some(Duration::ZERO));
        assert!(store.final_screen(&id).is_none());
        assert!(store.final_screen_timeout().is_none());
        assert!(store.is_ended(&id));
    }

    #[test]
    fn final_checkpoint_count_and_replacement_are_bounded() {
        let store = SessionStore::new();
        for value in 0..=64 {
            store.retain_final_screen([value; 16], ScreenState::empty(2), None);
        }
        assert!(store.final_screen(&[0; 16]).is_none());
        assert!(store.final_screen(&[1; 16]).is_some());
        store.retain_final_screen([64; 16], ScreenState::empty(3), None);
        assert_eq!(store.state.lock().unwrap().final_screens.len(), 64);
        assert!(store.final_screen(&[1; 16]).is_some());
        let latest = store.final_screen(&[64; 16]).unwrap();
        let frame = SspFrame::decode(&latest.data[4..]).unwrap();
        assert_eq!(frame.diff.unwrap().total_rows, 3);
        store.remove_final_screen(&[64; 16]);
        assert!(store.final_screen(&[64; 16]).is_none());
        assert_eq!(store.state.lock().unwrap().final_screens.len(), 63);
    }

    #[test]
    fn final_checkpoint_bytes_are_bounded_independently_of_count() {
        let store = SessionStore::new();
        let mut screen = ScreenState::empty(200);
        screen.rows.fill("x".repeat(65_000));
        for value in 0..6 {
            store.retain_final_screen([value; 16], screen.clone(), None);
        }
        let state = store.state.lock().unwrap();
        assert_eq!(state.final_screens.len(), 5);
        assert_eq!(state.final_screens.front().unwrap().0, [1; 16]);
        assert!(
            state
                .final_screens
                .iter()
                .map(|(_, checkpoint)| checkpoint.retained_bytes())
                .sum::<usize>()
                <= 64 * 1024 * 1024
        );
    }

    #[test]
    fn ended_id_eviction_also_releases_its_final_checkpoint() {
        let store = SessionStore::new();
        store.mark_ended([0; 16]);
        store.retain_final_screen([0; 16], ScreenState::empty(2), None);
        for value in 1_u16..=1_024 {
            let mut id = [0; 16];
            id[..2].copy_from_slice(&value.to_be_bytes());
            store.mark_ended(id);
        }
        assert!(store.final_screen(&[0; 16]).is_none());
    }

    #[test]
    fn ended_session_history_is_bounded() {
        let store = SessionStore::new();
        for value in 0_u16..=1_024 {
            let mut id = [0; 16];
            id[..2].copy_from_slice(&value.to_be_bytes());
            store.mark_ended(id);
        }
        assert!(!store.is_ended(&[0; 16]));
        let mut newest = [0; 16];
        newest[..2].copy_from_slice(&1_024_u16.to_be_bytes());
        assert!(store.is_ended(&newest));
    }

    fn make_detached() -> DetachedSession {
        let pty = PtySession::open_command(24, 80, "cat", &[]).unwrap();
        let terminal = Arc::new(Mutex::new(RoseTerminal::new(24, 80)));
        let ssp_sender = Arc::new(Mutex::new(SspSender::new()));
        DetachedSession {
            pty,
            terminal,
            ssp_sender,
            rows: 24,
            cols: 80,
            owner_cert_der: None,
            detached_at: Instant::now(),
        }
    }

    #[test]
    fn insert_and_remove() {
        let store = SessionStore::new();
        let id = [1u8; 16];

        assert!(!store.contains(&id));
        assert!(store.is_empty());

        let _ = store.insert(id, make_detached());
        assert!(store.contains(&id));
        assert_eq!(store.len(), 1);

        let session = store.remove(&id);
        assert!(session.is_some());
        assert!(!store.contains(&id));
        assert!(store.is_empty());
    }

    #[test]
    fn remove_nonexistent() {
        let store = SessionStore::new();
        assert!(store.remove(&[0u8; 16]).is_none());
    }

    #[test]
    fn replace_existing() {
        let store = SessionStore::new();
        let id = [2u8; 16];

        let _ = store.insert(id, make_detached());
        let old = store.insert(id, make_detached());
        assert!(old.is_some());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn default_is_empty() {
        let store = SessionStore::default();
        assert!(store.is_empty());
    }

    #[test]
    fn prune_exited_removes_dead_sessions() {
        let store = SessionStore::new();
        let id = [3u8; 16];
        let session = DetachedSession {
            pty: PtySession::open_command(24, 80, "sh", &["-c", "exit 0"]).unwrap(),
            terminal: Arc::new(Mutex::new(RoseTerminal::new(24, 80))),
            ssp_sender: Arc::new(Mutex::new(SspSender::new())),
            rows: 24,
            cols: 80,
            owner_cert_der: None,
            detached_at: Instant::now(),
        };
        let _ = store.insert(id, session);
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if store.prune_exited() > 0 {
                break;
            }
        }
        assert!(store.is_empty());
        assert!(store.is_ended(&id));
    }

    #[test]
    fn prune_idle_removes_old_sessions() {
        let store = SessionStore::new();
        let id = [4u8; 16];
        let mut session = make_detached();
        session.detached_at = Instant::now()
            .checked_sub(Duration::from_secs(100))
            .unwrap();
        let _ = store.insert(id, session);

        assert_eq!(store.prune_idle(Duration::from_secs(50)), 1);
        assert!(store.is_empty());
        assert!(store.is_ended(&id));
    }

    #[test]
    fn prune_idle_keeps_recent_sessions() {
        let store = SessionStore::new();
        let id = [5u8; 16];
        let _ = store.insert(id, make_detached());

        assert_eq!(store.prune_idle(Duration::from_secs(3600)), 0);
        assert_eq!(store.len(), 1);
    }
}
