#!/usr/bin/env bash
set -euo pipefail
set -x

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "${SOURCE_DIR}/.."

CONTAINER_NAME=fuzzingserver

cleanup() {
  docker container stop "${CONTAINER_NAME}"
}
trap cleanup TERM EXIT

test_diff() {
  echo "Comparing client Autobahn results…"

  DIFF_OUTPUT=$(
    diff -u \
      <(jq -S 'del(."Rama" | .. | .duration?)' autobahn/expected-client-results.json) \
      <(jq -S 'del(."Rama" | .. | .duration?)' autobahn/client/index.json)
  )
  STATUS=$?

  if [[ $STATUS -eq 1 ]]; then
    echo "❌ Difference detected between expected and actual results:"
    echo
    # echo "$DIFF_OUTPUT"
    echo
    echo "Either this is a regression, or update autobahn/expected-client-results.json with the new results."
    return 64
  elif [[ $STATUS -ne 0 ]]; then
    echo "⚠️ diff failed (status $STATUS)"
    return $STATUS
  else
    echo "✅ No differences found."
    return 0
  fi
}

case "$(uname -s)" in
  Linux)
    PLATFORM_SPECIFIC_DOCKER_ARGS="--add-host=host.docker.internal:host-gateway"
    ;;
  Darwin)
    PLATFORM_SPECIFIC_DOCKER_ARGS=""
    ;;
  *)
    echo "unsupported platform"; exit 1;;
esac

docker run -d --rm \
  -v "${PWD}/autobahn:/autobahn" \
  $PLATFORM_SPECIFIC_DOCKER_ARGS \
  -p 9001:9001 \
  --init \
  --name "${CONTAINER_NAME}" \
  crossbario/autobahn-testsuite \
  wstest -m fuzzingserver -s 'autobahn/fuzzingserver.json'

sleep 5

set +e
cargo run --release -p rama --example autobahn_client --features=http-full
CLIENT_STATUS=$?
set -e

if ! test_diff; then
  echo "---- fuzzingserver logs ----"
  docker logs "${CONTAINER_NAME}" || true
  echo "----------------------------"
  exit 64
fi

if [[ $CLIENT_STATUS -ne 0 ]]; then
  echo "Client exited with status ${CLIENT_STATUS}"
  docker logs "${CONTAINER_NAME}" || true
  exit "$CLIENT_STATUS"
fi
