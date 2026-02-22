//! PTY management using portable-pty.
//!
//! The server spawns a shell (or command) in a PTY and reads/writes to it.
//! By default, spawns the user's login shell.
