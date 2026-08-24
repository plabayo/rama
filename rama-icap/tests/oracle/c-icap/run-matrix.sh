#!/bin/bash
set -eu

root=$(cd "$(dirname "$0")/../../../.." && pwd)
compose="$root/rama-icap/tests/oracle/c-icap/compose.yaml"
project="rama-icap-oracle-$$"

available_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

export COMPOSE_PROJECT_NAME=$project
export RAMA_ICAP_C_ICAP_PORT=${RAMA_ICAP_C_ICAP_PORT:-$(available_port)}
export RAMA_ICAP_C_ICAP_204_PORT=${RAMA_ICAP_C_ICAP_204_PORT:-$(available_port)}
export RAMA_ICAP_RAMA_PORT=${RAMA_ICAP_RAMA_PORT:-$(available_port)}
export RAMA_ICAP_RAMA_204_PORT=${RAMA_ICAP_RAMA_204_PORT:-$(available_port)}

failed=1
cleanup() {
    if test "$failed" -ne 0; then
        docker compose -p "$project" -f "$compose" logs --no-color 2>/dev/null || true
    fi
    docker compose -p "$project" -f "$compose" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

cd "$root"
docker compose -p "$project" -f "$compose" up --build --detach --wait

printf 'oracle phase: c-icap client to c-icap server\n'
docker compose -p "$project" -f "$compose" exec -T c-icap \
    /opt/rama-icap-oracle/reference-matrix.sh normal
docker compose -p "$project" -f "$compose" exec -T c-icap-204 \
    /opt/rama-icap-oracle/reference-matrix.sh 204

printf 'oracle phase: Rama client to c-icap server\n'
RAMA_ICAP_ORACLE_REQUIRED=1 \
RAMA_ICAP_ORACLE_ECHO_ADDR="127.0.0.1:$RAMA_ICAP_C_ICAP_PORT" \
RAMA_ICAP_ORACLE_204_ADDR="127.0.0.1:$RAMA_ICAP_C_ICAP_204_PORT" \
    cargo test --locked -p rama-icap --features http \
        --test c_icap_interop -- --include-ignored --nocapture

printf 'oracle phase: c-icap client to Rama server\n'
rama-icap/tests/oracle/c-icap/rama-server-matrix.sh

printf 'oracle phase: Rama client to Rama server\n'
cargo test --locked -p rama-icap --all-features \
    --test async_transactions --test http_transactions

failed=0
printf 'complete ICAP oracle matrix: OK\n'
