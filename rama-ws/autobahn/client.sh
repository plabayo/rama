#!/usr/bin/env bash
set -euo pipefail
set -x

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "${SOURCE_DIR}/.."

CONTAINER_NAME=fuzzingserver
AUTOBAHN_IMAGE="crossbario/autobahn-testsuite:25.10.1@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
SHARD_SPEC=""
MERGED_REPORT=""

cleanup_container() {
  docker container rm --force "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}

cleanup() {
  cleanup_container
  [[ -z "${SHARD_SPEC}" ]] || rm -f "${SHARD_SPEC}"
  [[ -z "${MERGED_REPORT}" ]] || rm -f "${MERGED_REPORT}" "${MERGED_REPORT}.next"
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
  cleanup_container
  docker run -d \
    -v "${PWD}/autobahn:/autobahn" \
    $PLATFORM_SPECIFIC_DOCKER_ARGS \
    -p 9001:9001 \
    --init \
    --name "${CONTAINER_NAME}" \
    "${AUTOBAHN_IMAGE}" \
    wstest -m fuzzingserver -s "autobahn/${SHARD_SPEC##*/}"

  sleep 5
  container_is_running
}

write_shard_spec() {
  local cases=$1
  local exclude_cases=$2

  jq \
    --argjson cases "${cases}" \
    --argjson exclude_cases "${exclude_cases}" \
    '.cases = $cases | .["exclude-cases"] = $exclude_cases' \
    autobahn/fuzzingserver.json >"${SHARD_SPEC}"
}

merge_shard_report() {
  jq -s \
    'reduce .[] as $report ({}; . * $report)' \
    "${MERGED_REPORT}" \
    autobahn/client/index.json >"${MERGED_REPORT}.next"
  mv "${MERGED_REPORT}.next" "${MERGED_REPORT}"
}

run_shard() {
  local name=$1
  local cases=$2
  local exclude_cases=$3
  local server_status
  local client_status

  echo "Running Autobahn client shard: ${name}"
  write_shard_spec "${cases}" "${exclude_cases}"

  for attempt in 1 2; do
    rm -f autobahn/client/index.json

    set +e
    start_fuzzingserver
    server_status=$?
    if [[ ${server_status} -eq 0 ]]; then
      cargo run --release -p rama-examples --bin autobahn_client --features=http-full
      client_status=$?
    else
      client_status=${server_status}
    fi
    set -e

    if
      [[ ${client_status} -eq 0 ]] &&
      [[ -f autobahn/client/index.json ]]
    then
      merge_shard_report
      cleanup_container
      return 0
    fi

    if [[ ${client_status} -eq 0 ]]; then
      client_status=1
    fi

    show_container_diagnostics
    if [[ ${attempt} -eq 1 ]]; then
      echo "Autobahn client shard ${name} failed; retrying it once"
    fi
  done

  echo "Autobahn client shard ${name} failed with status ${client_status}"
  return "${client_status}"
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

SHARD_SPEC=$(mktemp "${PWD}/autobahn/fuzzingserver-shard.XXXXXX")
MERGED_REPORT=$(mktemp)
jq -n '{"Rama": {}}' >"${MERGED_REPORT}"

rm -rf -- autobahn/client
mkdir -p autobahn/client

run_shard \
  "base" \
  '["*"]' \
  '["12.*", "13.*"]'
run_shard \
  "compression-12.1-12.3" \
  '["12.1.*", "12.2.*", "12.3.*"]' \
  '[]'
run_shard \
  "compression-12.4-12.5" \
  '["12.4.*", "12.5.*"]' \
  '[]'
run_shard \
  "compression-13.1-13.3" \
  '["13.1.*", "13.2.*", "13.3.*"]' \
  '[]'
run_shard \
  "compression-13.4-13.5" \
  '["13.4.*", "13.5.*"]' \
  '[]'
run_shard \
  "compression-13.6-13.7" \
  '["13.6.*", "13.7.*"]' \
  '[]'

mv "${MERGED_REPORT}" autobahn/client/index.json
MERGED_REPORT=""
test_diff
