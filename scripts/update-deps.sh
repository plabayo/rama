#!/usr/bin/env bash
# Upgrade the workspace and every standalone project that keeps its own lock file.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

cargo install cargo-edit --locked
for lockfile in Cargo.lock $(git ls-files '*/Cargo.lock'); do
    dir=$(dirname "$lockfile")
    echo "== $dir"
    (cd "$dir" && cargo upgrade --incompatible && cargo update && cargo generate-lockfile)
done
just rama-quic/update-aioquic-pin
