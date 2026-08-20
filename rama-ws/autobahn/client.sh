#!/usr/bin/env bash
set -euo pipefail
set -x

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "${SOURCE_DIR}/.."

CONTAINER_NAME=fuzzingserver
AUTOBAHN_IMAGE="crossbario/autobahn-testsuite:25.10.1@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"

cleanup() {
  docker container rm --force "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup TERM EXIT

container_is_running() {
  [[ "$(docker inspect --format '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null)" == "true" ]]
}

show_container_diagnostics() {
  echo "---- fuzzingserver inspect ----"
  docker inspect "${CONTAINER_NAME}" || true
  echo "---- fuzzingserver logs ----"
  docker logs "${CONTAINER_NAME}" || true
  echo "----------------------------"
}

start_fuzzingserver() {
  cleanup
  docker run -d \
    -v "${PWD}/autobahn:/autobahn" \
    $PLATFORM_SPECIFIC_DOCKER_ARGS \
    -p 9001:9001 \
    --init \
    --name "${CONTAINER_NAME}" \
    "${AUTOBAHN_IMAGE}" \
    wstest -m fuzzingserver -s 'autobahn/fuzzingserver.json'

  sleep 5
  if ! container_is_running; then
    show_container_diagnostics
    return 1
  fi
}

test_diff() {
  echo "Comparing client Autobahn results…"

  if
    diff -u \
      <(jq -S 'del(."Rama" | .. | .duration?)' autobahn/expected-client-results.json) \
      <(jq -S 'del(."Rama" | .. | .duration?)' autobahn/client/index.json) \
      >/dev/null
  then
    STATUS=0
  else
    STATUS=$?
  fi

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

for ATTEMPT in 1 2; do
  start_fuzzingserver

  set +e
  cargo run --release -p rama-examples --bin autobahn_client --features=http-full
  CLIENT_STATUS=$?
  test_diff
  DIFF_STATUS=$?
  set -e

  if [[ $CLIENT_STATUS -eq 0 && $DIFF_STATUS -eq 0 ]]; then
    exit 0
  fi

  if ! container_is_running; then
    show_container_diagnostics
    if [[ $ATTEMPT -eq 1 ]]; then
      echo "fuzzingserver exited unexpectedly; retrying the suite once"
      continue
    fi
  fi

  if [[ $DIFF_STATUS -ne 0 ]]; then
    exit "$DIFF_STATUS"
  fi

  echo "Client exited with status ${CLIENT_STATUS}"
  show_container_diagnostics
  exit "$CLIENT_STATUS"
done
