# RoSE — Remote Shell Environment

A modern replacement for [Mosh](https://mosh.org/) written in Rust, built on QUIC and wezterm's terminal emulator.

## Why RoSE?

Mosh proved that mobile-friendly remote terminals are possible, but its architecture limits what it can do. RoSE takes the same core ideas — local keystroke prediction, UDP-like unreliable transport, roaming support — and rebuilds them on modern foundations:

- **QUIC (RFC 9000) + Datagrams (RFC 9221):** Instead of a custom encrypted UDP protocol, RoSE uses QUIC. This gives us TLS 1.3 encryption for free, multiplexed reliable streams alongside unreliable datagrams, and standard X.509 certificate-based authentication. It also means RoSE servers can sit behind ordinary reverse proxies with SNI routing.
- **wezterm terminal emulator:** Instead of a custom terminal emulator, RoSE embeds [wezterm](https://github.com/wez/wezterm)'s terminal emulation. This gives us full support for modern terminal features (true color, sixel, kitty graphics, etc.) without reinventing the wheel.
- **Scrollback support:** Unlike Mosh, RoSE supports scrollback history, synchronized over a dedicated QUIC stream.
- **Session persistence:** Detach and reattach to sessions seamlessly. Lost connections automatically reconnect with exponential backoff.
- **Extensible:** QUIC's multiplexed streams make it straightforward to add features like file transfer, port forwarding, and other capabilities that currently require a separate SSH connection.

## Status

Early development. The core is functional — terminal emulation, PTY management, QUIC transport, state synchronization, scrollback, and session reconnection all work — but expect rough edges.

## Usage

### Native Mode

Both client and server run persistent RoSE daemons. Authentication uses mutual TLS with X.509 certificates:

1. `rose keygen` generates a client certificate
2. Copy the certificate to `~/.config/rose/authorized_certs/` on the server
3. For self-signed server certificates, the client uses TOFU (trust on first use) via `~/.config/rose/known_hosts/`
4. For servers behind a reverse proxy with real TLS certificates, no TOFU is needed

```sh
rose connect myserver.example.com
```

### SSH Bootstrap Mode

No server daemon required. RoSE SSHs in, starts a temporary server, exchanges certificates, and switches to QUIC — all in one step:

```sh
rose connect --ssh user@myserver.example.com
```

### Escape Sequences

While connected, press `Enter` then `~` to access escape commands:

- `~.` — disconnect
- `~~` — send a literal `~`
- `~?` — show help

## Building

```sh
cargo build
```

## Development

See [`AGENTS.md`](AGENTS.md) for full development guidelines.

```sh
cargo fmt --all                                         # format
cargo clippy --workspace --all-targets                  # lint
cargo nextest run --all --no-fail-fast                  # test
cargo +nightly llvm-cov-easy nextest --workspace --branch  # coverage
cargo deny check                                        # security audit
cargo bench -p rose                                     # benchmarks
```

## Architecture

See [`doc/spec.md`](doc/spec.md) for the full specification.

RoSE is a Cargo workspace with two crates:

- **`lib/`** — library crate (`rose`) containing core logic: terminal emulation, state synchronization protocol (SSP), QUIC transport, PTY management, scrollback sync, and session persistence.
- **`cli/`** — binary crate (`rose-cli`, binary name `rose`) providing subcommands: `connect`, `server`, `keygen`. Man pages are generated at build time.

Key dependencies: [quinn](https://github.com/quinn-rs/quinn) (QUIC), [wezterm-term](https://github.com/wez/wezterm) (terminal emulation), [portable-pty](https://docs.rs/portable-pty) (PTY management), [rustls](https://github.com/rustls/rustls) (TLS 1.3), [rcgen](https://github.com/rustls/rcgen) (certificate generation).

## License

GPL-3.0-or-later — RoSE includes [tests ported from Mosh](lib/tests/mosh_ported.rs), which is GPL-3.0-or-later.
