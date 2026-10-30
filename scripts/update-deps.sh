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

# `uv add` moves the exact pins of direct dependencies; `uv lock --upgrade` the transitive ones.
for lockfile in $(git ls-files 'uv.lock' '*/uv.lock'); do
    dir=$(dirname "$lockfile")
    echo "== $dir"
    (
        cd "$dir"
        direct=$(uv run --no-project --isolated python -I -c 'import re, tomllib; print(" ".join(re.split(r"[\s<>=!~\[;]", d, maxsplit=1)[0] for d in tomllib.load(open("pyproject.toml", "rb"))["project"].get("dependencies", [])))')
        if [ -n "$direct" ]; then
            # shellcheck disable=SC2086
            uv add --no-sync --bounds exact --preview-features add-bounds --upgrade $direct
        fi
        uv lock --upgrade
    )
done

for gomod in $(git ls-files 'go.mod' '*/go.mod'); do
    dir=$(dirname "$gomod")
    echo "== $dir"
    (cd "$dir" && go get -u -t ./... && go mod tidy)
done

echo "== GitHub Actions"
GITHUB_TOKEN=${GITHUB_TOKEN:-$(gh auth token)} \
    go run github.com/suzuki-shunsuke/pinact/v3/cmd/pinact@latest run --update
