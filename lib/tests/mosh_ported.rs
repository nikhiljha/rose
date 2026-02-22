//! Integration tests ported from the mosh project's test suite.
//!
//! These tests exercise end-to-end behavior that requires `RoSE`'s transport,
//! protocol, and PTY layers working together. They are expected to fail until
//! those layers are implemented.
//!
//! Each test is annotated with the mosh test it was ported from.

// ---------------------------------------------------------------------------
// Ported from mosh: window-resize.test
//
// Tests that window resize events (SIGWINCH) propagate correctly from the
// client through the protocol to the server PTY, and that the application
// running in the PTY redraws correctly.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires transport + protocol layers (mosh: window-resize.test)"]
fn e2e_window_resize() {
    // TODO: Start a RoSE server with a PTY running a program that redraws
    // on resize (e.g., `less` or a custom test program). Connect a client.
    // Resize the client terminal. Verify the server PTY receives SIGWINCH
    // and the program redraws correctly.
    unimplemented!("window resize e2e test");
}

// ---------------------------------------------------------------------------
// Ported from mosh: e2e-success.test
//
// Basic smoke test: client connects to server, runs a command, and
// disconnects cleanly.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires transport + protocol layers (mosh: e2e-success.test)"]
fn e2e_basic_connection() {
    // TODO: Start a RoSE server. Connect a client. Verify the connection
    // is established and the client can see the shell prompt. Send "exit"
    // and verify clean disconnection.
    unimplemented!("basic connection e2e test");
}

// ---------------------------------------------------------------------------
// Ported from mosh: local.test
//
// Tests local (loopback) connection mode.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires transport + protocol layers (mosh: local.test)"]
fn e2e_local_connection() {
    // TODO: Start server and client on localhost. Verify they connect
    // and can exchange data.
    unimplemented!("local connection e2e test");
}

// ---------------------------------------------------------------------------
// Ported from mosh: repeat.test
//
// Tests repeated connect/disconnect cycles to verify no resource leaks.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires transport + protocol layers (mosh: repeat.test)"]
fn e2e_repeat_connections() {
    // TODO: Connect and disconnect 5+ times in sequence. Verify each
    // connection works and there are no leaked file descriptors, ports,
    // or PTYs.
    unimplemented!("repeat connections e2e test");
}

// ---------------------------------------------------------------------------
// Ported from mosh: network-no-diff.test
//
// Regression test: the server should not spin CPU when the screen state
// has not changed (e.g., cursor blink writes overwriting the same character).
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires protocol layer (mosh: network-no-diff.test)"]
fn protocol_no_diff_no_spin() {
    // TODO: Set up a server terminal and repeatedly write the same
    // character at the same position (e.g., "x\b" in a loop). Verify
    // that the diff engine produces no output / minimal CPU usage
    // when the framebuffer hasn't actually changed.
    unimplemented!("no-diff optimization test");
}

// ---------------------------------------------------------------------------
// Ported from mosh: prediction-unicode.test
//
// Regression test: client prediction should correctly handle multi-byte
// Unicode characters. Previously, mosh would show garbled predictions
// for characters like ü (U+00FC) because the prediction engine would
// emit the low byte as an 8-bit character.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires prediction engine (mosh: prediction-unicode.test)"]
fn prediction_unicode_multibyte() {
    // TODO: Set up a client with prediction enabled. Type "glück" and
    // "faĩl" with delays between characters. Verify the predicted
    // display shows the correct Unicode characters at all times, never
    // showing replacement characters or wrong characters.
    unimplemented!("unicode prediction test");
}

// ---------------------------------------------------------------------------
// Ported from mosh: pty-deadlock.test
//
// Regression test for BSD PTY flow control bug: on FreeBSD/OpenBSD/macOS,
// a PTY master can block on read() after select() indicates data available,
// if ^S (XOFF) is written between select() and read().
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires PTY layer (mosh: pty-deadlock.test)"]
fn pty_flow_control_no_deadlock() {
    // TODO: Start a RoSE server running a program that produces high
    // output volume. Send ^S (XOFF) to pause output, wait, then send
    // ^Q (XON) to resume. Verify the server does not deadlock and the
    // program eventually produces a clean exit message.
    unimplemented!("PTY flow control deadlock test");
}

// ---------------------------------------------------------------------------
// RoSE-specific: session persistence across network changes
//
// Inspired by mosh's core value proposition but not directly ported from
// a specific mosh test. Verifies that a session survives simulated
// network disruption.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires transport layer"]
fn session_persists_across_network_disruption() {
    // TODO: Establish a RoSE session. Simulate a network disruption
    // (drop all datagrams for N seconds). Resume. Verify the session
    // is still alive and the screen state synchronizes correctly.
    unimplemented!("session persistence test");
}

// ---------------------------------------------------------------------------
// RoSE-specific: scrollback synchronization
//
// Unique to RoSE (mosh doesn't support scrollback). Verifies that
// scrollback history is synchronized over the dedicated QUIC stream.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires scrollback sync"]
fn scrollback_sync_over_reliable_stream() {
    // TODO: Establish a session. Generate enough output to fill the
    // scrollback buffer. Verify the client can scroll back and see
    // the history, and that it was delivered over the reliable QUIC
    // stream (not datagrams).
    unimplemented!("scrollback sync test");
}

// ---------------------------------------------------------------------------
// RoSE-specific: SSH bootstrap mode
//
// Tests the SSH bootstrap connection mode where RoSE automatically SSHs
// in, starts a temporary server, exchanges certificates, and switches
// to QUIC.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires SSH bootstrap implementation"]
fn ssh_bootstrap_mode() {
    // TODO: Start an SSH server (or mock). Run `rose connect --ssh`.
    // Verify the client:
    // 1. SSHs in
    // 2. Starts rose server on a high port
    // 3. Exchanges certificates
    // 4. Connects via QUIC
    // 5. Drops the SSH connection
    // 6. The session works over QUIC
    unimplemented!("SSH bootstrap mode test");
}

// ---------------------------------------------------------------------------
// RoSE-specific: certificate-based authentication (native mode)
//
// Tests that mutual TLS authentication works with X.509 certificates.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires certificate management"]
fn native_mode_mutual_tls_auth() {
    // TODO: Generate client and server certificates with `rose keygen`.
    // Place client cert in server's authorized_certs. Start server.
    // Connect client. Verify mutual TLS authentication succeeds.
    // Also test rejection when the client cert is not authorized.
    unimplemented!("mutual TLS auth test");
}

// ---------------------------------------------------------------------------
// RoSE-specific: TOFU (Trust On First Use) for self-signed server certs
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires certificate management"]
fn native_mode_tofu_self_signed() {
    // TODO: Generate a self-signed server certificate. Connect a client
    // for the first time — should prompt/succeed and cache the cert in
    // known_hosts. Connect again — should verify against cached cert.
    // Change the server cert — should reject (TOFU violation).
    unimplemented!("TOFU self-signed cert test");
}
