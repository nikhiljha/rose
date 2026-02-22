//! Session persistence for `RoSE`.
//!
//! Manages detached sessions that survive network disconnections.
//! When a client disconnects, the PTY, terminal emulator, and SSP
//! state are preserved in a [`SessionStore`]. Reconnecting clients
//! can resume where they left off.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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
}

/// Thread-safe store of detached sessions indexed by session ID.
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<Mutex<HashMap<[u8; 16], DetachedSession>>>,
}

impl SessionStore {
    /// Creates an empty session store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
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
        self.sessions
            .lock()
            .expect("session store lock poisoned")
            .insert(id, session)
    }

    /// Removes and returns a session by ID, or `None` if not found.
    ///
    /// # Panics
    ///
    /// Panics if the session store mutex is poisoned.
    #[must_use]
    pub fn remove(&self, id: &[u8; 16]) -> Option<DetachedSession> {
        self.sessions
            .lock()
            .expect("session store lock poisoned")
            .remove(id)
    }

    /// Returns `true` if a session with the given ID exists.
    ///
    /// # Panics
    ///
    /// Panics if the session store mutex is poisoned.
    #[must_use]
    pub fn contains(&self, id: &[u8; 16]) -> bool {
        self.sessions
            .lock()
            .expect("session store lock poisoned")
            .contains_key(id)
    }

    /// Returns the number of detached sessions.
    ///
    /// # Panics
    ///
    /// Panics if the session store mutex is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions
            .lock()
            .expect("session store lock poisoned")
            .len()
    }

    /// Returns `true` if there are no detached sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
}
