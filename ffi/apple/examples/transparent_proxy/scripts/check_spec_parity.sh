#!/usr/bin/env bash
# Cross-file parity checks for the transparent-proxy example. Fast, no Xcode
# toolchain needed, so they run early in `just qa` (and thus in CI).
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# dev and dist Xcode specs must declare the same SPM products, else a product
# added to Project.yml but forgotten in Project.dist.yml silently breaks the
# Developer-ID build (which no other recipe compiles).
dev=$(grep -E '^[[:space:]]*product:' tproxy_app/Project.yml | awk '{print $2}' | sort -u)
dist=$(grep -E '^[[:space:]]*product:' tproxy_app/Project.dist.yml | awk '{print $2}' | sort -u)
if [ "$dev" != "$dist" ]; then
    echo "Project.yml vs Project.dist.yml SPM product deps diverged:" >&2
    diff <(echo "$dev") <(echo "$dist") >&2 || true
    fail=1
fi

# CA keychain service names must match between the Rust sysext and the Swift
# container, else `Clear CA` wipes nothing and leaves orphaned key material.
rs=$(grep -oE 'rama-tproxy-demo-ca-[a-z-]+' tproxy_rs/src/tls/mod.rs | sort -u)
sw=$(grep -oE 'rama-tproxy-demo-ca-[a-z-]+' tproxy_app/Container/main.swift | sort -u)
if [ "$rs" != "$sw" ]; then
    echo "CA keychain service names diverged between Rust and Swift:" >&2
    diff <(echo "$rs") <(echo "$sw") >&2 || true
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "spec parity OK (dev/dist products, Rust/Swift keychain names)"
