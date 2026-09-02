#!/usr/bin/env bash
# Resolve a Loyalsoldier/geoip release tag (default: latest) and download the
# tag-pinned Country.mmdb asset. Prints: "<tag> <sha256> <path>"
#
# Usage: ./fetch_mmdb.sh [out_dir] [tag]
#
# Release assets are immutable per tag — unlike the force-pushed `release`
# branch raw URL that import-geoip.sh used previously (which has no history
# and silently decouples the DB name from the data version).
# Set GITHUB_TOKEN to avoid unauthenticated API rate limits in CI.
set -euo pipefail

OUT_DIR="${1:-tmp}"
TAG="${2:-}"

mkdir -p "$OUT_DIR"

if [[ -z "$TAG" ]]; then
    TAG=$(curl -fsSL --proto '=https' -H "Accept: application/vnd.github+json" \
        ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
        https://api.github.com/repos/Loyalsoldier/geoip/releases/latest | jq -r .tag_name)
    if [[ -z "$TAG" || "$TAG" == "null" ]]; then
        echo "Error: could not resolve latest release tag" >&2
        exit 1
    fi
fi

MMDB="$OUT_DIR/Country-$TAG.mmdb"
curl -fsSL --proto '=https' --retry 3 -o "$MMDB" \
    "https://github.com/Loyalsoldier/geoip/releases/download/$TAG/Country.mmdb"
SHA=$(sha256sum "$MMDB" | cut -d' ' -f1)

echo "$TAG $SHA $MMDB"
