# RoSE — Remote Shell Environment

A modern replacement for [Mosh](https://mosh.org/) written in Rust, built on QUIC and wezterm's terminal emulator.

## Why RoSE?

Mosh proved that mobile-friendly remote terminals are possible, but its architecture limits what it can do. RoSE takes the same core ideas — local keystroke prediction, UDP-like unreliable transport, roaming support — and rebuilds them on modern foundations:

- **QUIC (RFC 9000) + Datagrams (RFC 9221):** Instead of a custom encrypted UDP protocol, RoSE uses QUIC. This gives us TLS 1.3 encryption for free, multiplexed reliable streams alongside unreliable datagrams, and standard X.509 certificate-based authentication. It also means RoSE servers can sit behind ordinary reverse proxies with SNI routing.
- **wezterm terminal emulator:** Instead of a custom terminal emulator, RoSE embeds [wezterm](https://github.com/wez/wezterm)'s terminal emulation. This gives us full support for modern terminal features (true color, sixel, kitty graphics, etc.) without reinventing the wheel.
- **Scrollback support:** Unlike Mosh, RoSE supports scrollback history, synchronized over a dedicated QUIC stream.
- **Extensible:** QUIC's multiplexed streams make it straightforward to add features like file transfer, port forwarding, and other capabilities that currently require a separate SSH connection.

## Status

Early development. Not yet usable.

## Connection Modes

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

## Building

```sh
cargo build
```

## License

MIT
