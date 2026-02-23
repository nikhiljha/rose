#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! `RoSE` — Remote Shell Environment.
//!
//! A modern replacement for Mosh built on QUIC and wezterm's terminal emulator.

pub mod cli;
pub mod config;
pub mod protocol;
pub mod pty;
pub mod scrollback;
pub mod session;
pub mod ssp;
pub mod stun;
pub mod terminal;
pub mod transport;
