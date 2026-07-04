#!/usr/bin/env bash
# (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.
#
# Sync the vendored canboat schema to an upstream canboat ref:
#
#   scripts/sync-canboat.sh <ref>     # tag, branch, or SHA, e.g. v7.2.0
#
# Copies <ref>:docs/canboat.json into crates/canboat-core/data/ and
# records the resolved full SHA in crates/canboat-core/data/CANBOAT_REF.
# CI reads that pin to (a) check out the matching golden fixtures and
# (b) verify the vendored json is byte-identical to the pinned ref —
# so schema and fixtures can never drift apart on main.
#
# Uses a sibling ../canboat checkout when present (fetching first),
# otherwise a shallow temporary clone.

set -euo pipefail

REF="${1:?usage: scripts/sync-canboat.sh <canboat ref>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/crates/canboat-core/data"

if [ -d "$ROOT/../canboat/.git" ]; then
    CANBOAT="$ROOT/../canboat"
    git -C "$CANBOAT" fetch --quiet origin
else
    CANBOAT="$(mktemp -d)/canboat"
    trap 'rm -rf "$(dirname "$CANBOAT")"' EXIT
    git clone --quiet --filter=blob:none https://github.com/canboat/canboat "$CANBOAT"
fi

SHA="$(git -C "$CANBOAT" rev-parse "${REF}^{commit}")"
git -C "$CANBOAT" show "$SHA:docs/canboat.json" > "$DATA/canboat.json"
echo "$SHA" > "$DATA/CANBOAT_REF"

VERSION="$(sed -n 's/.*"Version":"\([^"]*\)".*/\1/p' "$DATA/canboat.json" | head -1)"
echo "synced canboat.json to $REF ($SHA), schema version $VERSION"
echo "next: cargo test --workspace, then commit both files together"
