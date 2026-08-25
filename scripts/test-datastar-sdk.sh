#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT=$PWD
RUNNER=native

usage() {
    echo "usage: $0 [--native|--docker]"
    echo
    echo "  --native  run the official suite with the local Go toolchain (default)"
    echo "  --docker  run the official suite with the Go Docker image"
    echo
    echo "environment:"
    echo "  DATASTAR_SDK_TEST_VERSION  Go module version (default: latest)"
    echo "  DATASTAR_GO_IMAGE          Docker image (default: golang:1.25)"
}

if [ "$#" -gt 1 ]; then
    usage >&2
    exit 2
fi

case "${1:-}" in
    ""|--native) RUNNER=native ;;
    --docker) RUNNER=docker ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

for command in cargo curl; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command not found: $command" >&2
        exit 1
    fi
done

if [ "$RUNNER" = native ]; then
    runner_command=go
else
    runner_command=docker
fi

if ! command -v "$runner_command" >/dev/null 2>&1; then
    echo "required command not found: $runner_command" >&2
    exit 1
fi

cargo build -p rama-examples \
    --bin http_sse_datastar_test_suite \
    --features=http-full

target_dir="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
case "$target_dir" in
    /*) ;;
    *) target_dir="$REPO_ROOT/$target_dir" ;;
esac

server_log=$(mktemp "${TMPDIR:-/tmp}/rama-datastar-sdk.XXXXXX.log")
server_pid=""

cleanup() {
    status=$?
    trap - EXIT

    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid"
        wait "$server_pid" || true
    fi

    if [ "$status" -ne 0 ]; then
        echo "Datastar SDK server log:" >&2
        cat "$server_log" >&2
    fi

    rm -f "$server_log"
    exit "$status"
}
trap cleanup EXIT

"$target_dir/debug/http_sse_datastar_test_suite" >"$server_log" 2>&1 &
server_pid=$!

server_ready=false
for ((attempt = 0; attempt < 60; attempt++)); do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        echo "Datastar SDK server exited before becoming ready" >&2
        exit 1
    fi

    if curl --silent --output /dev/null --max-time 1 \
        http://127.0.0.1:62050/test; then
        server_ready=true
        break
    fi
    sleep 1
done

if [ "$server_ready" != true ]; then
    echo "Datastar SDK server did not become ready" >&2
    exit 1
fi

test_package=github.com/starfederation/datastar/sdk/tests/cmd/datastar-sdk-tests
test_version="${DATASTAR_SDK_TEST_VERSION:-latest}"

if [ "$RUNNER" = native ]; then
    go run "$test_package@$test_version" \
        -server http://127.0.0.1:62050
elif [ "$(uname -s)" = Linux ]; then
    docker run --rm --network host "${DATASTAR_GO_IMAGE:-golang:1.25}" \
        go run "$test_package@$test_version" \
        -server http://127.0.0.1:62050
else
    docker run --rm "${DATASTAR_GO_IMAGE:-golang:1.25}" \
        go run "$test_package@$test_version" \
        -server http://host.docker.internal:62050
fi
