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

# Both application variants and both targets must embed the exact source
# identity passed by their build wrapper.  Missing one side would make a
# built/installed/running evidence comparison ambiguous.
for spec in tproxy_app/Project.yml tproxy_app/Project.dist.yml; do
    if [ "$(grep -c 'RAMA_TPROXY_GIT_HEAD:' "$spec")" -ne 2 ] \
        || [ "$(grep -c 'RAMA_TPROXY_GIT_DIRTY:' "$spec")" -ne 2 ]; then
        echo "$spec must define source identity settings for both targets" >&2
        fail=1
    fi
done
for plist in tproxy_app/Container/Info.plist tproxy_app/Extension/Info.plist; do
    if ! grep -q '<key>RamaGitHead</key>' "$plist" \
        || ! grep -q '<key>RamaGitDirty</key>' "$plist"; then
        echo "$plist does not embed the source identity" >&2
        fail=1
    fi
done
for build_script in \
    scripts/build_tproxy_app_with_signing.sh \
    scripts/build_tproxy_app_with_developer_id_signing.sh
do
    if ! grep -q 'RAMA_TPROXY_GIT_HEAD=' "$build_script" \
        || ! grep -q 'RAMA_TPROXY_GIT_DIRTY=' "$build_script"; then
        echo "$build_script does not pass the source identity to Xcode" >&2
        fail=1
    fi
done

if [ "$(grep -c 'org.ramaproxy.example.tproxy.dist.provider.systemextension' justfile)" -ne 2 ] \
    || grep -q 'org.ramaproxy.example.tproxy.provider.systemextension' justfile; then
    echo "dist install recipes must use the exact Project.dist provider bundle directory" >&2
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

# The pressure parser is evidence-critical. Keep its accepted field order aligned
# with the actual Swift emitters so a runtime wording change cannot degrade a
# complete on-device run into silently ignored telemetry.
if ! python3 scripts/check_spec_parity.py "$(pwd)"; then
    echo "pressure telemetry emitters diverged from pressure parser" >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "spec parity OK (dev/dist products, keychain names, TCP/UDP pressure telemetry schema)"
