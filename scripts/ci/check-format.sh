#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all --check
for project in \
  ffi/apple/examples/transparent_proxy/tproxy_rs \
  ffi/apple/examples/transparent_proxy/tproxy_ffi_e2e \
  rama-quic/e2e/interop-common \
  rama-quic/e2e/quinn-interop \
  rama-quic/e2e/quiche-interop \
  rama-quic/e2e/aioquic-interop \
  rama-quic/e2e/interop-runner
do
  cargo fmt --manifest-path "$project/Cargo.toml" --all --check
done
