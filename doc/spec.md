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

The server interprets terminal output with `wezterm-term`:

- **Server side:** Maintains the authoritative emulator throughout the PTY's lifetime. Diffs its visible screen state and sends updates over QUIC.
- **Client side:** Maintains a replica of the visible screen and renders it into the local terminal with ANSI sequences.

#### Terminal Feature Boundary

The current snapshot contains ANSI row strings, cursor coordinates, cursor
visibility and shape (including blink policy), and viewport identity. This
represents text, colors, cell attributes, scrolling, and
alternate-screen contents. It is not a serialization of the complete emulator.
Graphics, hyperlinks, dynamic cursor colors, application input modes, clipboard
events, and other terminal effects are not all represented in the wire format.
WezTerm parsing a feature does not imply that the client can reproduce it.

The server returns emulator-generated query responses directly to the PTY,
including cursor-position reports, even while detached. These responses describe
the server emulator; capability responses are not yet negotiated with the local
display and may include features outside the current rendering contract.

### PTY Management

The server uses `portable-pty` to manage the PTY. By default it spawns the user's login shell, but arbitrary commands can be specified (like SSH's `ssh user@host command`).

For server sessions, the dedicated PTY reader thread advances the emulator before
broadcasting output notifications. This continues during detach and naturally
backpressures the child when emulation cannot keep up. Connection tasks may
coalesce or lose notifications without losing authoritative terminal state.
Resize operations hold the same terminal lock while resizing the PTY and emulator.
The low-level `PtySession` constructors without an attached terminal expose a
lossy broadcast stream for callers that need raw output.

The server monitors both the direct child and PTY EOF. If the child exits while
a descendant retains the slave PTY, output continues draining until EOF or for
one additional second, whichever comes first. Child polling does not cancel
partially received control messages.

On Unix, PTY reads and writes use nonblocking descriptors with cancellable
readiness waits. Destroying the session wakes both workers, even if input is
backed up and a descendant still holds the slave open. Detach and reconnect
preserve the session and do not cancel its I/O. Session creation fails before
spawning the shell when the platform cannot monitor the allocated descriptors.

At PTY EOF or the drain deadline, the server snapshots the final authoritative
state regardless of pending output notifications or frame throttling. It sends a full SSP frame on a
reliable stream and waits for the client's SSP acknowledgment before closing the
connection. Missing application acknowledgments trigger another reliable copy.
Final delivery is bounded to two seconds; connection failure or timeout can
still prevent delivery.

## Transport Layer

### QUIC

RoSE uses QUIC (RFC 9000) via the `quinn` crate as its transport layer.

#### Datagram Channel (RFC 9221)

Replaceable screen updates flow over QUIC datagrams (unreliable, unordered).
The protocol uses a "most recent state wins" approach identical to Mosh:

- The server sends screen state diffs. If a datagram is lost, the next one contains a diff from the last acknowledged state, making the lost one irrelevant.
- Old unacknowledged frames are discarded.

#### Reliable Streams

QUIC streams are used for data that must not be lost:

- **Control stream (bi-directional):** Initial handshake (Hello/Reconnect), session setup (SessionInfo), resize events, and graceful disconnect (Goodbye).
- **Input stream (bi-directional):** Each CLI connection opens a stream prefixed with a `0x03` type byte. The server first sends its eight-byte cumulative accepted input offset. The client then sends frames containing an eight-byte cumulative offset, a four-byte length, and 1–4096 input bytes. The server writes new bytes through the session-owned PTY writer and acknowledges its eight-byte cumulative accepted offset. All integers use big-endian encoding. Replayed overlaps are skipped, gaps are rejected, and up to 64 KiB of unacknowledged input survives automatic reconnects.
- **Scrollback stream (uni, server→client):** Scrollback history synchronization. The server opens a long-lived uni stream prefixed with a `0x02` type byte and incrementally sends scrollback lines as they appear. This avoids head-of-line blocking on the interactive datagram channel.
- **Oversized SSP frames (uni, server→client):** When an SSP frame exceeds the QUIC datagram MTU, it is sent via a one-shot uni stream prefixed with a `0x01` type byte, followed by the length-prefixed frame data.

Input that reaches the 64 KiB transport retention bound uses a bounded 128-byte
keyboard lookahead, allowing immediate local escape sequences to be recognized.
Once that lookahead fills, further keyboard events are backpressured; an escape
behind a larger queued paste must wait for that input to drain.
An explicit detach waits until earlier input is acknowledged. An explicit
disconnect may abandon unacknowledged input. An acknowledgment means the bytes
were written to the PTY, not that the application executed them. A newly attached
client adopts the session's accepted offset; an automatically reconnecting client
validates that offset against its retained and previously sent bytes.

The reliable input protocol requires handshake version 2 on both ends. The
low-level `ClientSession::send_input` datagram API remains available without
ordering or replay guarantees; the CLI uses the reliable stream.

### Resource bounds

The server terminal retains at most 3,500 history rows. The client retains at most
3,500 rows and 8 MiB of UTF-8 history text, including ANSI sequences, evicting the
oldest rows first. Duplicate and out-of-order rows are ignored. Redraw bookkeeping
uses the retained stable-row range so that eviction still triggers a redraw when
the retained row count stays constant.

History collection targets 256 KiB of text per batch. One larger row may occupy a
batch by itself; rows exceeding 8 MiB are skipped. An SSP stream payload is limited
to 16 MiB. Clients validate declared lengths before reading payloads and stop
malformed streams. At most eight incoming stream readers run per connection, and
connection cleanup cancels them.

Before retaining a screen snapshot, the server checks its row count, each row's
encoded text length, and the worst-case frame size including empty-row headers.
Screens outside the wire limits become a bounded display notice in SSP state;
the authoritative terminal and connection continue running. Resizing or clearing
the terminal restores normal display when the next snapshot fits. This also
applies to final screens and avoids treating an oversized frame as a disconnected
peer. SSP's current row count and row text length fields are 16-bit.

The screen sender has one reliable transfer in progress and one latest frame
waiting. New oversized frames replace the waiting frame while allowing the
current transfer to finish, so continuous output cannot repeatedly interrupt all
progress. Acknowledgment of the latest state, a newer datagram-sized update, or
connection cleanup cancels outstanding stream work. Lost application
acknowledgments can still trigger another completed-frame transmission. History
and screen streams share QUIC congestion control with interactive datagrams.

## Connection Modes

### Native Mode

Both client and server run persistent RoSE processes. Authentication uses mutual TLS with X.509 certificates.

#### Certificate Management

- **Client certificates** are stored in `~/.config/rose/client.crt` (PEM) and `client.crt.der` (DER). Generated by `rose keygen` or automatically on first connection. The same certificate is used for all connection modes (native, bootstrap, reattach).
- **Server certificates** are stored in `~/.config/rose/server.crt` and `server.key` (DER). Generated on first server start and reused across restarts to preserve TOFU trust.
- Client certificates are authorized by placing them in `~/.config/rose/authorized_certs/` on the server.

#### Trust Model

- **CA-signed server certificates:** Verified against the system trust store via `rustls-platform-verifier`. No additional configuration needed. Compatible with standard reverse proxies and SNI routing (e.g., `ssh.myserver.mydomain.com`).
- **Self-signed server certificates:** Trust on first use (TOFU). The server's certificate is cached in `~/.config/rose/known_hosts/<hostname>.crt` on first connection and verified on subsequent connections.

### SSH Bootstrap Mode

No persistent server daemon required. RoSE uses the system `ssh` binary for bootstrap connections, which means it inherits your `~/.ssh/config` settings, ProxyJump rules, agent forwarding, host aliases, and any other SSH configuration. No separate SSH library or configuration is needed.

The client:

1. Loads or generates the persistent client certificate from `~/.config/rose/`.
2. Spawns `ssh <host> nohup rose server --bootstrap --ephemeral` and writes the client's public certificate (hex-encoded DER) to the SSH process's stdin.
3. The server reads the client cert from stdin, loads or generates its persistent server certificate, binds with mutual TLS requiring that specific client cert, picks a random UDP port in the 60000-61000 range, and prints `ROSE_BOOTSTRAP <port> <server_cert_hex>` to stdout.
4. The client parses the server cert and port, saves the server cert to `~/.config/rose/known_hosts/`, then connects QUIC to `<host>:<port>` using mutual TLS.
5. The client kills the SSH process — the QUIC connection is fully independent and supports roaming. The server survives via `nohup`.
6. The ephemeral server exits when the shell process exits.

**Session detach:** The user can press `Enter~d` to detach from the session without killing it. The client prints the command needed to reattach directly (without SSH) using the saved certificates.

**Security:** The client's private key never leaves the client machine. The public certificate is sent to the server over the authenticated SSH channel, and the server requires it for mutual TLS — preventing unauthorized connections to the bootstrap port. Certificates are persistent (not ephemeral) and reused across sessions.

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
- The receiver retains up to 32 states and applies a diff to its actual base.
  Duplicate frames and frames with unavailable bases still elicit an ACK of the
  current state. Invalid diffs leave both the screen and its ACK unchanged.

### Viewport Identity

Screen diffs may append a nine-byte viewport extension after the changed rows:
`[alternate_screen: u8][first_row: u64 big-endian]`. The stable first-row index
distinguishes actual scrolling from a redraw that happens to reuse row text.
Clients only synthesize native scrolling when both snapshots identify movement
within the primary screen and the overlapping rows match. Without this metadata,
history arrives through the reliable scrollback stream. Older decoders ignore
the extension; newer decoders accept frames without it.

### Cursor Appearance

A diff can append `[0xc0: u8][cursor_style: u8]` after its rows and optional
viewport metadata. The style byte uses bit 7 for hidden visibility and bits 0–6
for the DECSCUSR shape: 0 = default, 1/2 = blinking/steady block,
3/4 = blinking/steady underline, 5/6 = blinking/steady bar. Other shape values
are invalid. Omitted cursor metadata means a visible cursor with default shape,
including when restoring that state after a non-default style.

Cursor appearance participates in snapshot equality and SSP recovery even when
no text or cursor coordinates change. Incremental rendering emits DECSCUSR and
DECTCEM when the style changes; a full redraw always restores it. Client teardown
shows the cursor and restores the local terminal's default shape. Production
snapshots include viewport metadata before cursor metadata, so viewport-only
decoders can ignore the cursor suffix.

### Session Persistence

Sessions survive network changes (WiFi to cellular, IP address changes, NAT rebinding). The client automatically reconnects with exponential backoff (100ms to 5s) when the connection is lost. On reconnect:

- The client sends a `Reconnect` message with the session ID from the original `SessionInfo`.
- The server resumes the detached session (PTY, terminal state, SSP sender are all preserved).
- Output produced while detached has already been interpreted and is included in
  the reattached screen and retained history.
- The server resets its `SspSender` so the client gets a full init diff.
- The client starts fresh SSP state each connection.

After an explicit detach, `rose connect <host> --port <port> --session <id>`
sends `Reconnect` on the first connection. The printed reattach command includes
the session ID and any explicit certificate paths. The server checks the
connecting client's certificate against the session owner.

If resizing or sending session metadata fails during reattachment, the server
returns the session to the detached store so a later connection can retry.
Successful resizes remain reflected in both the PTY and emulator even if sending
the metadata subsequently fails.

Detached sessions are retained in server memory until the shell exits, the
configured idle timeout expires, or the server stops. The default idle timeout is
seven days. They do not survive a server process restart.

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
