#!/usr/bin/env bash
set -euo pipefail

# This script is called by Buildkite when a new git tag is pushed.
# It reads release metadata from releases.toml, cross-compiles for all
# supported targets, and creates a GitHub release with the binaries.
#
# Required environment variables:
#   BUILDKITE_TAG   - The git tag that triggered the build (e.g. "v0.1.0")
#   GITHUB_TOKEN    - A GitHub token with permission to create releases

TAG="${BUILDKITE_TAG:?BUILDKITE_TAG is required}"
VERSION="${TAG#v}"

BINARY_NAME="rose"
CRATE_NAME="rose-cli"
REPO="nikhiljha/rose"

TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
    "aarch64-apple-darwin"
)

# ---------------------------------------------------------------------------
# Install release dependencies
# ---------------------------------------------------------------------------
echo "--- :gear: Installing release dependencies"

# Python 3 for TOML parsing (tomllib is built-in since Python 3.11)
apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 > /dev/null 2>&1

# Zig (used by cargo-zigbuild for cross-compilation)
ZIG_VERSION="0.13.0"
if ! command -v zig &> /dev/null; then
    echo "Installing zig ${ZIG_VERSION}..."
    curl -sSfL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
        | tar xJ -C /usr/local
    export PATH="/usr/local/zig-linux-x86_64-${ZIG_VERSION}:${PATH}"
fi

# cargo-zigbuild for cross-compilation
if ! command -v cargo-zigbuild &> /dev/null; then
    echo "Installing cargo-zigbuild..."
    cargo install --locked cargo-zigbuild
fi

# Add cross-compilation targets
for target in "${TARGETS[@]}"; do
    rustup target add "$target"
done

# ---------------------------------------------------------------------------
# Read release metadata from releases.toml
# ---------------------------------------------------------------------------
echo "--- :memo: Generating release metadata"

python3 - "$TAG" << 'PYEOF' > /tmp/release_meta.json
import tomllib
import json
import sys

tag = sys.argv[1]

with open("releases.toml", "rb") as f:
    data = tomllib.load(f)

release = data.get(tag, {})
title = release.get("title", tag)
blurb = release.get("blurb", "")
callouts = release.get("callouts", [])

# Build the release body as Markdown
lines = []
if blurb:
    lines.append(blurb)
    lines.append("")

for callout in callouts:
    kind = callout.get("kind", "NOTE").upper()
    text = callout.get("text", "")
    lines.append(f"> [!{kind}]")
    lines.append(f"> {text}")
    lines.append("")

lines.append("## Installation")
lines.append("")
lines.append("```bash")
lines.append("cargo binstall rose-cli")
lines.append("```")

json.dump({"title": title, "body": "\n".join(lines)}, sys.stdout)
PYEOF

RELEASE_TITLE=$(python3 -c "import json; print(json.load(open('/tmp/release_meta.json'))['title'])")
echo "Release title: ${RELEASE_TITLE}"

# ---------------------------------------------------------------------------
# Build release binaries
# ---------------------------------------------------------------------------
echo "--- :hammer: Building release binaries"

ARTIFACTS=()
for target in "${TARGETS[@]}"; do
    echo "Building ${CRATE_NAME} for ${target}..."
    cargo zigbuild --release --target "$target" -p "$CRATE_NAME"

    # Package the binary in a binstall-compatible archive layout:
    #   {crate}-{target}-v{version}/{binary}
    ARCHIVE_DIR="${CRATE_NAME}-${target}-${TAG}"
    mkdir -p "$ARCHIVE_DIR"
    cp "target/${target}/release/${BINARY_NAME}" "$ARCHIVE_DIR/"

    ARCHIVE_NAME="${ARCHIVE_DIR}.tar.gz"
    tar czf "$ARCHIVE_NAME" "$ARCHIVE_DIR"
    ARTIFACTS+=("$ARCHIVE_NAME")

    rm -rf "$ARCHIVE_DIR"
    echo "  -> ${ARCHIVE_NAME}"
done

# ---------------------------------------------------------------------------
# Create GitHub release and upload assets
# ---------------------------------------------------------------------------
echo "--- :github: Creating GitHub release"

RELEASE_JSON=$(python3 -c "
import json
meta = json.load(open('/tmp/release_meta.json'))
print(json.dumps({
    'tag_name': '${TAG}',
    'name': meta['title'],
    'body': meta['body'],
    'draft': False,
    'prerelease': False,
}))
")

RESPONSE=$(curl -sSf \
    -X POST \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO}/releases" \
    -d "$RELEASE_JSON")

UPLOAD_URL=$(echo "$RESPONSE" | python3 -c "
import sys, json
print(json.load(sys.stdin)['upload_url'].split('{')[0])
")

for artifact in "${ARTIFACTS[@]}"; do
    name=$(basename "$artifact")
    echo "Uploading ${name}..."
    curl -sSf \
        -X POST \
        -H "Authorization: token ${GITHUB_TOKEN}" \
        -H "Content-Type: application/gzip" \
        --data-binary "@${artifact}" \
        "${UPLOAD_URL}?name=${name}" > /dev/null
done

echo "--- :tada: Release ${TAG} published!"
echo "https://github.com/${REPO}/releases/tag/${TAG}"
