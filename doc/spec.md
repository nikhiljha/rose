# RoSE Specification

## Overview

RoSE (Remote Shell Environment) is a remote terminal application inspired by Mosh. It provides a roaming-capable, always-on remote shell over QUIC.

## Architecture

### Components

RoSE is a single binary (`rose`) with subcommands:

- `rose connect <host>` — connect to a remote host
- `rose server` — run the server daemon (native mode)
- `rose keygen` — generate X.509 client certificates

Man pages are generated at build time via `clap_mangen` (`rose.1`, `rose-connect.1`, `rose-server.1`, `rose-keygen.1`). Shell aliases (e.g., `alias rose-server='rose server'`) can be created by users if desired.

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

- **Control stream (bi-directional):** Initial handshake (Hello/Reconnect), session setup (SessionInfo), resize events, and graceful disconnect (Goodbye).
- **Scrollback stream (uni, server→client):** Scrollback history synchronization. The server opens a long-lived uni stream prefixed with a `0x02` type byte and incrementally sends scrollback lines as they appear. This avoids head-of-line blocking on the interactive datagram channel.
- **Oversized SSP frames (uni, server→client):** When an SSP frame exceeds the QUIC datagram MTU, it is sent via a one-shot uni stream prefixed with a `0x01` type byte, followed by the length-prefixed frame data.

Additional reliable streams may be added in the future for features like file transfer and port forwarding.

## Connection Modes

### Native Mode

Both client and server run persistent RoSE processes. Authentication uses mutual TLS with X.509 certificates.

#### Certificate Management

- `rose keygen` generates a client X.509 certificate and private key.
- Server certificates can be self-signed or CA-signed.
- Client certificates are authorized by placing them in `~/.config/rose/authorized_certs/` on the server.

#### Trust Model

- **CA-signed server certificates:** Verified against the system trust store via `rustls-platform-verifier`. No additional configuration needed. Compatible with standard reverse proxies and SNI routing (e.g., `ssh.myserver.mydomain.com`).
- **Self-signed server certificates:** Trust on first use (TOFU). The server's certificate is cached in `~/.config/rose/known_hosts/<hostname>.crt` on first connection and verified on subsequent connections.

### SSH Bootstrap Mode

No persistent server daemon required. RoSE uses the system `ssh` binary for bootstrap connections, which means it inherits your `~/.ssh/config` settings, ProxyJump rules, agent forwarding, host aliases, and any other SSH configuration. No separate SSH library or configuration is needed.

The client:

1. Generates an ephemeral client certificate (private key stays local).
2. Spawns `ssh <host> rose server --bootstrap --ephemeral` and writes the client's public certificate (hex-encoded DER) to the SSH process's stdin.
3. The server reads the client cert from stdin, generates its own server certificate, binds with mutual TLS requiring that specific client cert, picks a random UDP port in the 60000-61000 range, and prints `ROSE_BOOTSTRAP <port> <server_cert_hex>` to stdout.
4. The client parses the server cert and port, then connects QUIC to `<host>:<port>` using mutual TLS.
5. The client kills the SSH process — the QUIC connection is fully independent and supports roaming.
6. The ephemeral server exits when the shell process exits (not when SSH dies).

**Security:** The client's private key never leaves the client process. The public certificate is sent to the server over the authenticated SSH channel, and the server requires it for mutual TLS — preventing unauthorized connections to the bootstrap port. Both certificates are ephemeral and not cached.

#### STUN Hole-Punching Fallback

If the direct QUIC connection to the server's UDP port fails (e.g., the port is firewalled), the client falls back to STUN-based NAT hole-punching using the SSH channel for signaling:

1. The client sends a STUN Binding Request to a public Google STUN server to discover its own public IP:port (NAT-mapped address).
2. The client writes `ROSE_STUN <ip> <port>` to the SSH process's stdin.
3. The server reads this and sends QUIC Initial packets from its RoSE port to the client's STUN-discovered address. This creates a stateful firewall entry allowing return traffic.
4. The client creates a QUIC endpoint from the same UDP socket used for STUN (preserving the NAT mapping) and connects to the server.

STUN discovery runs in parallel with the direct connection attempt (3-second timeout), so the fallback path adds minimal latency. This is best-effort — it works for full-cone and restricted-cone NATs (typical consumer routers) and stateful firewalls, but not for symmetric NAT or stateless packet filters.

## State Synchronization Protocol

Heavily inspired by Mosh's State Synchronization Protocol (SSP), but not wire-compatible.

### Principles

- The server maintains the authoritative screen state.
- The client maintains a predicted screen state for local echo.
- Both sides track sequence numbers to know what state the other side has acknowledged.
- Diffs are computed from the last acknowledged state, so lost datagrams are automatically superseded.

### Session Persistence

Sessions survive network changes (WiFi to cellular, IP address changes, NAT rebinding). The client automatically reconnects with exponential backoff (100ms to 5s) when the connection is lost. On reconnect:

- The client sends a `Reconnect` message with the session ID from the original `SessionInfo`.
- The server resumes the detached session (PTY, terminal state, SSP sender are all preserved).
- The server resets its `SspSender` so the client gets a full init diff.
- The client starts fresh SSP state each connection.

Sessions persist indefinitely until the server-side shell process exits. There is no idle timeout.

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
| `clap_mangen` | Man page generation (build-time) |
| `rcgen` | X.509 certificate generation |
| `rustls-platform-verifier` | OS trust store verification for CA-signed certs |
| `tokio` | Async runtime |
| `tracing` | Instrumentation |
