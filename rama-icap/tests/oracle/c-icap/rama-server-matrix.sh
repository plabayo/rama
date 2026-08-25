#!/bin/bash
set -eu

root=$(cd "$(dirname "$0")/../../../.." && pwd)
normal_port=${RAMA_ICAP_RAMA_PORT:-21344}
port_204=${RAMA_ICAP_RAMA_204_PORT:-21345}
pid=

cleanup() {
    if test -n "$pid"; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

cd "$root"
cargo build -p rama-icap --features std --example c_icap_oracle_server
oracle_bin=${CARGO_TARGET_DIR:-target}/debug/examples/c_icap_oracle_server

run_matrix() {
    mode=$1
    port=$2
    if nc -z 127.0.0.1 "$port" 2>/dev/null; then
        printf 'Rama ICAP oracle port %s is already in use\n' "$port" >&2
        return 1
    fi
    "$oracle_bin" "$mode" "0.0.0.0:$port" &
    pid=$!
    attempt=0
    while test "$attempt" -lt 50; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            return 1
        fi
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            break
        fi
        sleep 0.1
        attempt=$((attempt + 1))
    done
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid"
        return 1
    fi
    nc -z 127.0.0.1 "$port"
    docker compose -f rama-icap/tests/oracle/c-icap/compose.yaml run \
        --rm --no-deps --build \
        --entrypoint /opt/rama-icap-oracle/reference-matrix.sh \
        c-icap "$mode" host.docker.internal "$port" rama
    kill "$pid"
    wait "$pid" 2>/dev/null || true
    pid=
}

run_matrix normal "$normal_port"
run_matrix 204 "$port_204"
