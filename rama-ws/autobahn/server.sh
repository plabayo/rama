#!/usr/bin/env bash
set -euo pipefail
set -x
SOURCE_DIR=$(readlink -f "${BASH_SOURCE[0]}")
SOURCE_DIR=$(dirname "$SOURCE_DIR")
cd "${SOURCE_DIR}/.."

function cleanup() {
    kill -9 ${WSSERVER_PID}
}
trap cleanup TERM EXIT

function test_diff() {
    echo "Comparing server Autobahn results…"

    DIFF_OUTPUT=$(diff -q \
        <(jq -S 'del(."Rama" | .. | .duration?)' autobahn/expected-server-results.json) \
        <(jq -S 'del(."Rama" | .. | .duration?)' autobahn/server/index.json)
    )

    STATUS=$?

    if [[ $STATUS -eq 1 ]]; then
        echo "❌ Difference detected between expected and actual results:"
        echo
        echo "$DIFF_OUTPUT"
        echo
        echo "Either this is a regression, or you should update autobahn/expected-server-results.json with the new results."
        exit 64
    elif [[ $STATUS -ne 0 ]]; then
        echo "⚠️ Diff command failed (status $STATUS)"
        exit $STATUS
    else
        echo "✅ No differences found."
    fi
}

case "$(uname -s)" in
  Linux)
      ECHO_BIND_ADDR="0.0.0.0:9002"
      PLATFORM_SPECIFIC_DOCKER_ARGS="--add-host=host.docker.internal:host-gateway"
      ;;
  Darwin)
      ECHO_BIND_ADDR="127.0.0.1:9002"
      PLATFORM_SPECIFIC_DOCKER_ARGS="--network host"
      ;;
  *)
      echo "unsupported platform"
      exit 1
      ;;
esac

cargo build --release -p rama-cli
cargo run --release -p rama-cli -- echo --ws --bind "$ECHO_BIND_ADDR" & WSSERVER_PID=$!
sleep 5

docker run --rm \
    -v "${PWD}/autobahn:/autobahn" \
    $PLATFORM_SPECIFIC_DOCKER_ARGS \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingclient -s 'autobahn/fuzzingclient.json'

test_diff
