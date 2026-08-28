#!/bin/bash
set -eu

root=$(cd "$(dirname "$0")/../../../.." && pwd)
compose="$root/rama-icap/tests/oracle/c-icap/compose.yaml"
project="rama-icap-oracle-$$"
project_file=${RAMA_ICAP_ORACLE_PROJECT_FILE:-}

available_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

export COMPOSE_PROJECT_NAME=$project
export RAMA_ICAP_C_ICAP_PORT=${RAMA_ICAP_C_ICAP_PORT:-$(available_port)}
export RAMA_ICAP_C_ICAP_204_PORT=${RAMA_ICAP_C_ICAP_204_PORT:-$(available_port)}
export RAMA_ICAP_C_ICAP_TLS_PORT=${RAMA_ICAP_C_ICAP_TLS_PORT:-$(available_port)}
export RAMA_ICAP_RAMA_PORT=${RAMA_ICAP_RAMA_PORT:-$(available_port)}
export RAMA_ICAP_RAMA_204_PORT=${RAMA_ICAP_RAMA_204_PORT:-$(available_port)}

if test -n "$project_file"; then
    printf '%s\n' "$project" > "$project_file"
fi

failed=1
rama_tunnel_pid=
rama_tunnel_log=
cleanup() {
    status=$1
    trap - EXIT HUP INT TERM
    if test -n "$rama_tunnel_pid"; then
        kill "$rama_tunnel_pid" 2>/dev/null || true
        wait "$rama_tunnel_pid" 2>/dev/null || true
    fi
    if test -n "$rama_tunnel_log"; then
        if test "$status" -ne 0 || test "$failed" -ne 0; then
            sed -n '1,240p' "$rama_tunnel_log" >&2
        fi
        rm -f "$rama_tunnel_log"
    fi
    if test "$status" -ne 0 || test "$failed" -ne 0; then
        docker compose -p "$project" -f "$compose" logs --no-color 2>/dev/null || true
    fi
    if docker compose -p "$project" -f "$compose" down --volumes --remove-orphans; then
        if test -n "$project_file"; then
            rm -f "$project_file"
        fi
    else
        printf 'failed to remove ICAP oracle Compose project %s\n' "$project" >&2
        if test "$status" -eq 0; then
            status=1
        fi
    fi
    exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

cd "$root"
docker compose -p "$project" -f "$compose" up --build --detach --wait

cargo build --locked -p rama-cli
rama_target_dir=$(cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
rama_tunnel_log=$(mktemp "${TMPDIR:-/tmp}/rama-icap-tunnel.XXXXXX")
"$rama_target_dir/debug/rama" serve stunnel exit \
    --bind "127.0.0.1:$RAMA_ICAP_C_ICAP_TLS_PORT" \
    --forward "127.0.0.1:$RAMA_ICAP_C_ICAP_PORT" \
    >"$rama_tunnel_log" 2>&1 &
rama_tunnel_pid=$!

tunnel_ready=0
for _ in {1..120}; do
    if ! kill -0 "$rama_tunnel_pid" 2>/dev/null; then
        break
    fi
    if RAMA_ICAP_TUNNEL_PORT="$RAMA_ICAP_C_ICAP_TLS_PORT" python3 -c \
        'import os, socket; socket.create_connection(("127.0.0.1", int(os.environ["RAMA_ICAP_TUNNEL_PORT"])), 0.25).close()' 2>/dev/null
    then
        tunnel_ready=1
        break
    fi
    sleep 0.25
done
if test "$tunnel_ready" -ne 1; then
    printf 'Rama TLS tunnel failed to become ready\n' >&2
    exit 1
fi

printf 'oracle phase: c-icap client to c-icap server\n'
docker compose -p "$project" -f "$compose" exec -T c-icap \
    /opt/rama-icap-oracle/reference-matrix.sh normal
docker compose -p "$project" -f "$compose" exec -T c-icap-204 \
    /opt/rama-icap-oracle/reference-matrix.sh 204

printf 'oracle phase: Rama client to c-icap server\n'
RAMA_ICAP_ORACLE_REQUIRED=1 \
RAMA_ICAP_ORACLE_ECHO_ADDR="127.0.0.1:$RAMA_ICAP_C_ICAP_PORT" \
RAMA_ICAP_ORACLE_204_ADDR="127.0.0.1:$RAMA_ICAP_C_ICAP_204_PORT" \
RAMA_ICAP_ORACLE_TLS_ECHO_ADDR="127.0.0.1:$RAMA_ICAP_C_ICAP_TLS_PORT" \
    cargo test --locked -p rama-icap --features http \
        --test c_icap_interop -- --include-ignored --nocapture

printf 'oracle phase: c-icap client to Rama server\n'
rama-icap/tests/oracle/c-icap/rama-server-matrix.sh

printf 'oracle phase: Rama client to Rama server\n'
cargo test --locked -p rama-icap --all-features \
    --test async_transactions --test http_transactions

failed=0
printf 'complete ICAP oracle matrix: OK\n'
