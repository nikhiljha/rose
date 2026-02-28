FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl ca-certificates pkg-config git openssh-client gnupg \
    && rm -rf /var/lib/apt/lists/*

# Rust stable + nightly
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH="/usr/local/cargo/bin:$PATH"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable --component clippy,rustfmt \
    && rustup toolchain install nightly --profile minimal \
    && rustup component add llvm-tools-preview --toolchain nightly \
    && rustfmt --version && cargo clippy --version

# Cargo tools
RUN cargo install --locked cargo-nextest \
    && cargo install cargo-llvm-cov cargo-deny \
    && cargo install --git https://github.com/nikhiljha/llvm-cov-easy

# Zola
RUN curl -sL https://github.com/getzola/zola/releases/download/v0.22.1/zola-v0.22.1-x86_64-unknown-linux-gnu.tar.gz \
    | tar xz -C /usr/local/bin

# Codecov CLI
RUN curl https://keybase.io/codecovsecurity/pgp_keys.asc | gpg --no-default-keyring --keyring trustedkeys.gpg --import \
    && curl -Os https://cli.codecov.io/latest/linux/codecov \
    && curl -Os https://cli.codecov.io/latest/linux/codecov.SHA256SUM \
    && curl -Os https://cli.codecov.io/latest/linux/codecov.SHA256SUM.sig \
    && gpgv codecov.SHA256SUM.sig codecov.SHA256SUM \
    && sha256sum -c codecov.SHA256SUM \
    && chmod +x codecov \
    && mv codecov /usr/local/bin/codecov \
    && rm -f codecov.SHA256SUM codecov.SHA256SUM.sig

# Node + wrangler
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g wrangler
