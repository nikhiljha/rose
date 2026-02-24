use super::util::write_private_key;
use crate::config::{self, RosePaths};

/// COVERAGE: Keygen is a simple CLI command tested manually.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn run_keygen() -> anyhow::Result<()> {
    let paths = RosePaths::resolve();
    std::fs::create_dir_all(&paths.config_dir)?;

    let cert = config::generate_self_signed_cert(&["localhost".to_string()])?;

    std::fs::write(paths.config_dir.join("client.crt"), &cert.cert_pem)?;
    write_private_key(
        &paths.config_dir.join("client.key"),
        cert.key_pem.as_bytes(),
    )?;
    std::fs::write(
        paths.config_dir.join("client.crt.der"),
        cert.cert_der.as_ref(),
    )?;
    write_private_key(&paths.config_dir.join("client.key.der"), &cert.key_der)?;

    eprintln!(
        "Certificate: {}",
        paths.config_dir.join("client.crt").display()
    );
    eprintln!(
        "Private key: {}",
        paths.config_dir.join("client.key").display()
    );

    Ok(())
}
