use std::net::SocketAddr;
use std::time::Duration;

use super::client::{
    StunReconnectContext, client_session_loop_with_client, client_session_loop_with_conn,
};
use super::util::{RawModeGuard, hex_encode, load_or_generate_client_cert, parse_bootstrap_line};
use crate::config::{self, RosePaths};
use crate::transport::QuicClient;

/// SSH bootstrap mode: generates an ephemeral client cert, spawns
/// `ssh <host> rose server --bootstrap --ephemeral`, sends the client's
/// public cert over stdin, parses the `ROSE_BOOTSTRAP` line, then connects
/// QUIC directly to the host with mutual TLS.
///
/// If the direct QUIC connection fails (e.g., server's UDP port is
/// firewalled), falls back to STUN-based NAT hole-punching: discovers
/// the client's public address via STUN, tells the server over SSH stdin,
/// and the server sends packets to open its firewall for return traffic.
///
/// The client's private key never leaves this process.
///
/// COVERAGE: CLI bootstrap mode is tested via unit tests for parsing.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) async fn run_ssh_bootstrap(
    host: &str,
    server_binary: &str,
    force_stun: bool,
    ssh_port: Option<u16>,
    ssh_options: &[String],
) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let client_cert = load_or_generate_client_cert()?;

    eprintln!("Starting SSH bootstrap to {host}...");

    let mut cmd = tokio::process::Command::new("ssh");
    if let Some(port) = ssh_port {
        cmd.arg("-p").arg(port.to_string());
    }
    for opt in ssh_options {
        cmd.arg("-o").arg(opt);
    }
    let mut ssh = cmd
        .arg(host)
        .arg("nohup")
        .arg(server_binary)
        .arg("server")
        .arg("--bootstrap")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        // Use Stdio::null() instead of Stdio::inherit() to avoid leaking
        // the PTY slave FD to the nohup server process.  When stderr is
        // inherited the server keeps the FD open after `ssh.kill()`, which
        // prevents clean PTY EOF detection under llvm-cov instrumentation.
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn ssh: {e}"))?;

    {
        let stdin = ssh
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("failed to capture ssh stdin"))?;
        let cert_hex = hex_encode(client_cert.cert_der.as_ref());
        stdin.write_all(cert_hex.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
    }

    let stdout = ssh
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture ssh stdout"))?;
    let mut reader = tokio::io::BufReader::new(stdout);
    let mut line = String::new();

    tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut line))
        .await
        .map_err(|_| anyhow::anyhow!("timeout waiting for ROSE_BOOTSTRAP line"))?
        .map_err(|e| anyhow::anyhow!("failed to read bootstrap line: {e}"))?;

    let (port, server_cert_der) = parse_bootstrap_line(&line)?;
    eprintln!("Bootstrap: server on port {port}");

    let server_cert_der = rustls::pki_types::CertificateDer::from(server_cert_der);

    let resolved_host = resolve_ssh_hostname(host).await?;
    let addr: SocketAddr = {
        use std::net::ToSocketAddrs;
        let addrs: Vec<SocketAddr> = format!("{resolved_host}:{port}")
            .to_socket_addrs()
            .map(Iterator::collect)
            .unwrap_or_default();
        addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs.first())
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "could not resolve {resolved_host}:{port} (from ssh config for {host})"
                )
            })?
    };

    let paths = RosePaths::resolve();
    let cfg = config::RoseConfig::load(&paths.config_dir)?;
    std::fs::create_dir_all(&paths.known_hosts_dir)?;
    std::fs::write(
        paths.known_hosts_dir.join(format!("{}.crt", addr.ip())),
        server_cert_der.as_ref(),
    )?;

    let stun_servers_for_discover = cfg.stun_servers.clone();
    let stun_handle = tokio::task::spawn_blocking(move || {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let public_addr =
            crate::stun::stun_discover(&socket, stun_servers_for_discover.as_deref())?;
        Ok::<_, anyhow::Error>((socket, public_addr))
    });

    let direct_result = if force_stun {
        eprintln!("[RoSE: --force-stun: skipping direct attempt]");
        None
    } else {
        Some(
            tokio::time::timeout(Duration::from_secs(3), async {
                let client = QuicClient::new()?;
                let conn = client
                    .connect_with_cert(addr, &resolved_host, &server_cert_der, &client_cert)
                    .await?;
                Ok::<_, crate::transport::TransportError>((client, conn))
            })
            .await,
        )
    };

    let use_stun = match &direct_result {
        Some(Ok(Ok(_))) => false,
        Some(Ok(Err(e))) => {
            tracing::debug!("direct connection failed: {e}");
            true
        }
        Some(Err(_)) => {
            tracing::debug!("direct connection timed out");
            true
        }
        None => true,
    };

    let stun_socket = if use_stun {
        eprintln!("[RoSE: direct UDP failed, trying STUN hole-punch...]");

        match stun_handle.await {
            Ok(Ok((stun_socket, public_addr))) => {
                eprintln!("[RoSE: STUN discovered {public_addr}]");

                let stun_msg = format!("ROSE_STUN {} {}\n", public_addr.ip(), public_addr.port());
                if let Some(stdin) = ssh.stdin.as_mut() {
                    use tokio::io::AsyncWriteExt;
                    let _ = stdin.write_all(stun_msg.as_bytes()).await;
                    let _ = stdin.flush().await;
                }

                tokio::time::sleep(Duration::from_millis(500)).await;

                eprintln!(
                    "[RoSE: connected via STUN — roaming may be limited, \
                     consider forwarding UDP 60000-61000]"
                );

                Some(stun_socket)
            }
            Ok(Err(e)) => {
                eprintln!("[RoSE: STUN discovery failed: {e}]");
                anyhow::bail!("direct UDP connection failed and STUN fallback unavailable: {e}");
            }
            Err(e) => {
                anyhow::bail!("STUN discovery task panicked: {e}");
            }
        }
    } else {
        None
    };

    let _ = ssh.kill().await;

    let _raw_guard = RawModeGuard::enable()?;

    let client_config = config::build_client_config_with_cert(&server_cert_der, &client_cert)?;

    if let Some(stun_socket) = stun_socket {
        let client = QuicClient::from_socket(stun_socket)?;
        client_session_loop_with_client(
            client,
            addr,
            &resolved_host,
            client_config,
            StunReconnectContext {
                stun_servers: cfg.stun_servers.clone(),
            },
        )
        .await
    } else if let Some(Ok(Ok((_client, conn)))) = direct_result {
        client_session_loop_with_conn(conn, addr, &resolved_host, client_config).await
    } else {
        unreachable!()
    }
}

/// Resolves an SSH host alias to the actual hostname using `ssh -G`.
///
/// SSH config aliases (e.g., `myserver` mapping to `10.0.0.5` via `HostName`)
/// aren't DNS-resolvable, so we ask SSH what it would actually connect to.
///
/// COVERAGE: Requires SSH to be installed.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn resolve_ssh_hostname(host: &str) -> anyhow::Result<String> {
    let output = tokio::process::Command::new("ssh")
        .arg("-G")
        .arg(host)
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run `ssh -G {host}`: {e}"))?;

    if !output.status.success() {
        anyhow::bail!(
            "`ssh -G {host}` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(hostname) = line.strip_prefix("hostname ") {
            return Ok(hostname.to_string());
        }
    }

    Ok(host.to_string())
}
