#!/usr/bin/env bash
set -euo pipefail

if ! command -v rustup &>/dev/null; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "${CARGO_HOME:-$HOME/.cargo}/env"
fi

if ! rustup toolchain list | grep -q '^nightly'; then
    echo "Installing nightly toolchain..."
    rustup toolchain install nightly --profile minimal --component llvm-tools-preview
else
    rustup component add llvm-tools-preview --toolchain nightly 2>/dev/null || true
fi

rustup component add clippy rustfmt rust-analyzer 2>/dev/null || true

install_cargo_tool() {
    local cmd="$1"
    local pkg="${2:-$1}"
    if ! command -v "$cmd" &>/dev/null; then
        echo "Installing $pkg..."
        cargo install "$pkg"
    fi
}

install_cargo_tool cargo-nextest cargo-nextest
install_cargo_tool cargo-llvm-cov cargo-llvm-cov
install_cargo_tool cargo-deny cargo-deny
install_cargo_tool cargo-insta cargo-insta

if ! command -v cargo-llvm-cov-easy &>/dev/null; then
    echo "Installing cargo-llvm-cov-easy..."
    cargo install --git https://github.com/nikhiljha/llvm-cov-easy
fi

if ! command -v polydup &>/dev/null; then
    echo "Installing polydup..."
    cargo install --git https://github.com/nikhiljha/polydup-fork
fi

git config core.hooksPath .githooks
echo "Done! Pre-commit hook enabled."
