#!/usr/bin/env bash
set -euo pipefail

# Downloads build artifacts from prior steps, reads release metadata from
# releases.toml, and creates a GitHub release with all binaries attached.
#
# Required environment variables:
#   BUILDKITE_TAG   - The git tag that triggered the build (e.g. "v0.1.0")
#   GITHUB_TOKEN    - A GitHub token with permission to create releases

TAG="${BUILDKITE_TAG:?BUILDKITE_TAG is required}"
REPO="nikhiljha/rose"

# ---------------------------------------------------------------------------
# Install dependencies
# ---------------------------------------------------------------------------
echo "--- :gear: Installing publish dependencies"

# Python 3 for TOML parsing (tomllib is built-in since Python 3.11)
apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 > /dev/null 2>&1

# ---------------------------------------------------------------------------
# Download artifacts from build steps
# ---------------------------------------------------------------------------
echo "--- :arrow_down: Downloading build artifacts"

mkdir -p dist
buildkite-agent artifact download "dist/*.tar.gz" . --step build-linux
# macOS artifacts are optional — only available when a macOS agent is configured
buildkite-agent artifact download "dist/*.tar.gz" . --step build-macos 2>/dev/null || echo "No macOS artifacts (macOS build step not configured)"

echo "Collected artifacts:"
ls -lh dist/

# ---------------------------------------------------------------------------
# Generate release notes from releases.toml
# ---------------------------------------------------------------------------
echo "--- :memo: Generating release notes"

export RELEASE_TAG="$TAG"
python3 << 'PYEOF' > /tmp/release_meta.json
import tomllib
import json
import os

tag = os.environ["RELEASE_TAG"]

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

json.dump({"title": title, "body": "\n".join(lines)}, open("/tmp/release_meta.json", "w"))
PYEOF

RELEASE_TITLE=$(python3 -c "import json; print(json.load(open('/tmp/release_meta.json'))['title'])")
echo "Release title: ${RELEASE_TITLE}"

# ---------------------------------------------------------------------------
# Create GitHub release and upload assets
# ---------------------------------------------------------------------------
echo "--- :github: Creating GitHub release"

RELEASE_JSON=$(python3 << 'PYEOF'
import json, os
meta = json.load(open("/tmp/release_meta.json"))
print(json.dumps({
    "tag_name": os.environ["RELEASE_TAG"],
    "name": meta["title"],
    "body": meta["body"],
    "draft": False,
    "prerelease": False,
}))
PYEOF
)

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

for artifact in dist/*.tar.gz; do
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
