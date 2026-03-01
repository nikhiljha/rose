#!/usr/bin/env bash
set -euo pipefail

# Builds rose-cli for Linux x86_64 and aarch64 using cargo-zigbuild,
# then packages them as cargo-binstall-compatible .tar.gz archives.
#
# Artifacts are placed in dist/ for Buildkite artifact upload.

TAG="${BUILDKITE_TAG:?BUILDKITE_TAG is required}"
BINARY_NAME="rose"
CRATE_NAME="rose-cli"

TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
)

# ---------------------------------------------------------------------------
# Install cross-compilation toolchain
# ---------------------------------------------------------------------------
echo "--- :gear: Installing cross-compilation tools"

ZIG_VERSION="0.13.0"
if ! command -v zig &> /dev/null; then
    echo "Installing zig ${ZIG_VERSION}..."
    curl -sSfL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
        | tar xJ -C /usr/local
    export PATH="/usr/local/zig-linux-x86_64-${ZIG_VERSION}:${PATH}"
fi

if ! command -v cargo-zigbuild &> /dev/null; then
    echo "Installing cargo-zigbuild..."
    cargo install --locked cargo-zigbuild
fi

for target in "${TARGETS[@]}"; do
    rustup target add "$target"
done

# ---------------------------------------------------------------------------
# Build and package
# ---------------------------------------------------------------------------
mkdir -p dist

for target in "${TARGETS[@]}"; do
    echo "--- :hammer: Building ${CRATE_NAME} for ${target}"
    cargo zigbuild --release --target "$target" -p "$CRATE_NAME"

    # Archive layout: {crate}-{target}-{tag}/{binary}
    # This matches cargo-binstall's default bin-dir search pattern.
    ARCHIVE_DIR="${CRATE_NAME}-${target}-${TAG}"
    mkdir -p "$ARCHIVE_DIR"
    cp "target/${target}/release/${BINARY_NAME}" "$ARCHIVE_DIR/"

    ARCHIVE_NAME="${ARCHIVE_DIR}.tar.gz"
    tar czf "dist/${ARCHIVE_NAME}" "$ARCHIVE_DIR"
    rm -rf "$ARCHIVE_DIR"

    echo "  -> dist/${ARCHIVE_NAME}"
done

echo "--- :white_check_mark: Linux builds complete"
ls -lh dist/
