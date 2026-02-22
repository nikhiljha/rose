//! QUIC transport layer using quinn.
//!
//! Uses QUIC datagrams (RFC 9221) for interactive terminal data (unreliable,
//! most-recent-state-wins) and QUIC streams for reliable data (control channel,
//! scrollback sync).
