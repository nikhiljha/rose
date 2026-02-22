//! State synchronization protocol.
//!
//! Inspired by Mosh's SSP (State Synchronization Protocol). The server
//! maintains authoritative screen state, computes diffs from the last
//! acknowledged state, and sends them as QUIC datagrams. The client
//! maintains a predicted state for local echo.
