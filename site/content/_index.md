+++
title = "RoSE - Remote Shell Environment"
+++

[Mosh](https://mosh.org/) showed us that mobile-friendly remote terminals are possible, but its architecture limits what it can do. RoSE takes the same core ideas — local keystroke prediction, UDP-like unreliable transport, roaming support — and rebuilds them on modern foundations:

- **QUIC (RFC 9000) + Datagrams (RFC 9221):** Instead of a custom encrypted UDP protocol, RoSE uses QUIC. This gives us TLS 1.3 encryption for free, multiplexed reliable streams alongside unreliable datagrams, and standard X.509 certificate-based authentication. It also means RoSE servers can sit behind ordinary reverse proxies with SNI routing.
- **wezterm terminal emulator:** Instead of a custom terminal emulator, RoSE embeds [wezterm](https://github.com/wez/wezterm)'s terminal emulation. This gives us full support for modern terminal features (true color, sixel, kitty graphics, etc.) without reinventing the wheel.
- **Scrollback support:** Unlike Mosh, RoSE supports scrollback history, synchronized (at lower priority) over a dedicated QUIC stream.
- **Session persistence:** Detach and reattach to sessions seamlessly. Unlike mosh, connections are stateful at the transport layer, but new transports (for roaming) only require 1 RTT to reconnect.
- **Extensible:** QUIC's multiplexed streams make it straightforward to add features like file transfer, port forwarding, and other capabilities that currently require a separate SSH connection.

