#!/usr/bin/env bash
# Check actual native-test output, including missing categories and failed tests.
set -euo pipefail
cd "$(dirname "$0")/.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT
cargo test --locked --manifest-path ../../../../rama-net-apple-networkextension/Cargo.toml \
    --lib overload_telemetry_is_power_of_two_sampled -- --nocapture | tee "$log"
swift test --traits PrivateNetworkProxyControl \
    -Xlinker -L"$(pwd)/tproxy_rs/target/debug" \
    -Xlinker -lrama_tproxy_example -Xlinker -lz \
    -Xlinker -framework -Xlinker NetworkExtension \
    -Xlinker -framework -Xlinker SystemConfiguration "$@" | tee -a "$log"
uv run --frozen --project ../../../../scripts/ci python scripts/check_pressure_telemetry.py "$log"
