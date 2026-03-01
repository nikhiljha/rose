#!/usr/bin/env bash
set -euo pipefail

# Builds rose-cli natively on a macOS aarch64 agent and packages it
# as a cargo-binstall-compatible .tar.gz archive.
#
# Prerequisites: Rust toolchain installed on the macOS agent.
# Artifacts are placed in dist/ for Buildkite artifact upload.

TAG="${BUILDKITE_TAG:?BUILDKITE_TAG is required}"
BINARY_NAME="rose"
CRATE_NAME="rose-cli"
TARGET="aarch64-apple-darwin"

# ---------------------------------------------------------------------------
# Ensure Rust is available
# ---------------------------------------------------------------------------
echo "--- :gear: Checking Rust toolchain"

if ! command -v cargo &> /dev/null; then
    echo "Rust not found, installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

rustc --version
cargo --version

# ---------------------------------------------------------------------------
# Build and package
# ---------------------------------------------------------------------------
echo "--- :hammer: Building ${CRATE_NAME} for ${TARGET}"

cargo build --release -p "$CRATE_NAME"

mkdir -p dist

ARCHIVE_DIR="${CRATE_NAME}-${TARGET}-${TAG}"
mkdir -p "$ARCHIVE_DIR"
cp "target/release/${BINARY_NAME}" "$ARCHIVE_DIR/"

ARCHIVE_NAME="${ARCHIVE_DIR}.tar.gz"
tar czf "dist/${ARCHIVE_NAME}" "$ARCHIVE_DIR"
rm -rf "$ARCHIVE_DIR"

echo "  -> dist/${ARCHIVE_NAME}"
echo "--- :white_check_mark: macOS build complete"
ls -lh dist/
