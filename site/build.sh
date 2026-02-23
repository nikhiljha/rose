#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SITE_DIR="$REPO_ROOT/site"

# Build Zola site
zola --root "$SITE_DIR" build

# Build rustdoc
cargo doc --workspace --no-deps --document-private-items --manifest-path "$REPO_ROOT/Cargo.toml"

# Copy rustdoc into site output
cp -r "$REPO_ROOT/target/doc" "$SITE_DIR/public/docs"

echo "Site built at $SITE_DIR/public/"
