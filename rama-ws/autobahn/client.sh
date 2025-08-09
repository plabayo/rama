#!/usr/bin/env bash
set -euo pipefail
set -x
SOURCE_DIR=$(readlink -f "${BASH_SOURCE[0]}")
SOURCE_DIR=$(dirname "$SOURCE_DIR")
cd "${SOURCE_DIR}/.."

CONTAINER_NAME=fuzzingserver
function cleanup() {
    docker container stop "${CONTAINER_NAME}"
}
trap cleanup TERM EXIT

function test_diff() {
    if ! diff -q \
        <(jq -S 'del(."Rama" | .. | .duration?)' 'autobahn/expected-client-results.json') \
        <(jq -S 'del(."Rama" | .. | .duration?)' 'autobahn/client/index.json')
    then
        echo 'Difference in results, either this is a regression or' \
             'one should update autobahn/expected-client-results.json with the new results.'
        exit 64
    fi
}

docker run -d --rm \
    -v "${PWD}/autobahn:/autobahn" \
    -p 9001:9001 \
    --init \
    --name "${CONTAINER_NAME}" \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingserver -s 'autobahn/fuzzingserver.json'

sleep 5
cargo run --release -p rama --example autobahn_client --features=http-full,ws
test_diff
