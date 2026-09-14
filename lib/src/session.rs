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
use crate::ssp::SspSender;
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
        }
    }

    pub(crate) fn is_ended(&self, id: &[u8; 16]) -> bool {
        self.state
            .lock()
            .expect("session store lock poisoned")
            .ended
            .contains(id)
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
