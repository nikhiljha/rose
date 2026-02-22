# RoSE Specification

## Overview

RoSE (Remote Shell Environment) is a remote terminal application inspired by Mosh. It provides a roaming-capable, always-on remote shell over QUIC.

## Architecture

### Components

RoSE is a single binary (`rose`) with subcommands:

- `rose connect <host>` — connect to a remote host
- `rose server` — run the server daemon (native mode)
- `rose keygen` — generate X.509 client certificates

Aliases (`rose-client`, `rose-server`, `rose-keygen`) and man pages (via `clap-mangen`) will be generated for discoverability.

### Terminal Emulator

Both the client and server embed wezterm's terminal emulator (via the `wezterm-term` crate):

- **Server side:** Interprets raw PTY output into a structured screen state. Diffs the screen state and sends updates to the client over QUIC datagrams.
- **Client side:** Maintains a local copy of the screen state. Applies diffs received from the server. Performs local keystroke prediction for responsiveness.

This mirrors Mosh's dual-emulator architecture but replaces Mosh's custom terminal emulator with wezterm, gaining full support for modern terminal features.

### PTY Management

The server uses `portable-pty` to manage the PTY. By default it spawns the user's login shell, but arbitrary commands can be specified (like SSH's `ssh user@host command`).

## Transport Layer

### QUIC

RoSE uses QUIC (RFC 9000) via the `quinn` crate as its transport layer.

#### Datagram Channel (RFC 9221)

Interactive terminal data flows over QUIC datagrams (unreliable, unordered). The protocol uses a "most recent state wins" approach identical to Mosh:

- The server sends screen state diffs. If a datagram is lost, the next one contains a diff from the last acknowledged state, making the lost one irrelevant.
- The client sends keystrokes. Lost keystrokes are naturally retried by the user.
- Old unacknowledged frames are discarded.

#### Reliable Streams

QUIC streams are used for data that must not be lost:

- **Control stream:** Initial handshake, session setup, connection parameters.
- **Scrollback stream:** Scrollback history synchronization. This uses a separate QUIC stream from the control channel to avoid head-of-line blocking on the interactive datagram channel.

Additional reliable streams may be added in the future for features like file transfer and port forwarding.

## Connection Modes

### Native Mode

Both client and server run persistent RoSE processes. Authentication uses mutual TLS with X.509 certificates.

#### Certificate Management

- `rose keygen` generates a client X.509 certificate and private key.
- Server certificates can be self-signed or CA-signed.
- Client certificates are authorized by placing them in `~/.config/rose/authorized_certs/` on the server.

#### Trust Model

- **CA-signed server certificates:** Verified against the system trust store. No additional configuration needed. Compatible with standard reverse proxies and SNI routing (e.g., `ssh.myserver.mydomain.com`).
- **Self-signed server certificates:** Trust on first use (TOFU). The server's certificate is cached in `~/.config/rose/known_hosts/<hostname>.crt` on first connection and verified on subsequent connections.

### SSH Bootstrap Mode

No persistent server daemon required. The client:

1. SSHs into the remote host.
2. Starts a temporary `rose server` on a high port (coordinated over the SSH channel).
3. Downloads the server's certificate and uploads the client's certificate over SSH.
4. Connects via QUIC to the temporary server.
5. The SSH connection is dropped.

This mode does not cache certificates (the session is ephemeral).

## State Synchronization Protocol

Heavily inspired by Mosh's State Synchronization Protocol (SSP), but not wire-compatible.

### Principles

- The server maintains the authoritative screen state.
- The client maintains a predicted screen state for local echo.
- Both sides track sequence numbers to know what state the other side has acknowledged.
- Diffs are computed from the last acknowledged state, so lost datagrams are automatically superseded.

### Session Persistence

- Sessions survive network changes (WiFi to cellular, IP address changes, NAT rebinding).
- Sessions survive client sleep/resume.
- Sessions persist indefinitely until the server-side shell process exits. There is no idle timeout.

## Platforms

- **Server:** Linux, macOS
- **Client:** Linux, macOS
- **Windows:** Not a goal.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `quinn` | QUIC implementation |
| `wezterm-term` | Terminal emulator (client + server) |
| `portable-pty` | PTY management (server) |
| `clap` | CLI argument parsing |
| `rcgen` | X.509 certificate generation |
| `tokio` | Async runtime |
| `tracing` | Instrumentation |
