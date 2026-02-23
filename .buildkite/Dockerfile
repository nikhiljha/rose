FROM rust:1-bookworm

# Nightly toolchain + components
RUN rustup toolchain install nightly --profile minimal \
    && rustup component add clippy rustfmt --toolchain stable \
    && rustup component add llvm-tools-preview --toolchain nightly

# Cargo tools
RUN cargo install --locked cargo-nextest \
    && cargo install cargo-llvm-cov cargo-deny \
    && cargo install --git https://github.com/nikhiljha/llvm-cov-easy

# Zola
RUN curl -sL https://github.com/getzola/zola/releases/download/v0.22.1/zola-v0.22.1-x86_64-unknown-linux-gnu.tar.gz \
    | tar xz -C /usr/local/bin

# Node (for wrangler)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
