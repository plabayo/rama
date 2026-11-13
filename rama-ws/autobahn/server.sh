#!/usr/bin/env bash
set -euo pipefail
set -x

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "${SOURCE_DIR}/.."

CONTAINER_NAME=fuzzingclient
AUTOBAHN_IMAGE="crossbario/autobahn-testsuite:25.10.1@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
WSSERVER_PID=
SHARD_SPEC=""
MERGED_REPORT=""

cleanup_container() {
  docker container rm --force "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}

cleanup() {
  cleanup_container
  if [[ -n "$WSSERVER_PID" ]]; then
    kill "$WSSERVER_PID" 2>/dev/null || true
    wait "$WSSERVER_PID" 2>/dev/null || true
  fi
  [[ -z "${SHARD_SPEC}" ]] || rm -f "${SHARD_SPEC}"
  [[ -z "${MERGED_REPORT}" ]] || rm -f "${MERGED_REPORT}" "${MERGED_REPORT}.next"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

wsserver_is_running() {
  kill -0 "$WSSERVER_PID" 2>/dev/null
}

wait_for_wsserver() {
  for _ in $(seq 1 150); do
    wsserver_is_running || return 1
    if (exec 3<>"/dev/tcp/127.0.0.1/${ECHO_BIND_ADDR##*:}") 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

# A container killed from outside (status 137) leaves no report: say what ended it.
show_container_diagnostics() {
  echo "---- fuzzingclient state ----"
  docker inspect --format '{{json .State}}' "${CONTAINER_NAME}" || true
  echo "---- fuzzingclient logs (tail) ----"
  docker logs --tail 40 "${CONTAINER_NAME}" || true
  echo "---- host memory ----"
  free -m 2>/dev/null || vm_stat 2>/dev/null || true
  echo "----------------------------"
}

write_shard_spec() {
  local cases=$1
  local exclude_cases=$2

  jq \
    --argjson cases "${cases}" \
    --argjson exclude_cases "${exclude_cases}" \
    '.cases = $cases | .["exclude-cases"] = $exclude_cases' \
    autobahn/fuzzingclient.json >"${SHARD_SPEC}"
}

merge_shard_report() {
  jq -s \
    'reduce .[] as $report ({}; . * $report)' \
    "${MERGED_REPORT}" \
    autobahn/server/index.json >"${MERGED_REPORT}.next"
  mv "${MERGED_REPORT}.next" "${MERGED_REPORT}"
}

run_shard() {
  local name=$1
  local cases=$2
  local exclude_cases=$3
  local client_status

  echo "Running Autobahn server shard: ${name}"
  write_shard_spec "${cases}" "${exclude_cases}"

  for attempt in 1 2; do
    rm -f autobahn/server/index.json
    cleanup_container

    set +e
    docker run \
      -v "${PWD}/autobahn:/autobahn" \
      $PLATFORM_SPECIFIC_DOCKER_ARGS \
      --init \
      --name "${CONTAINER_NAME}" \
      "${AUTOBAHN_IMAGE}" \
      wstest -m fuzzingclient -s "autobahn/${SHARD_SPEC##*/}"
    client_status=$?
    set -e

    if ! wsserver_is_running; then
      show_container_diagnostics
      echo "The Rama echo server exited during Autobahn server shard ${name}"
      return 1
    fi

    if
      [[ ${client_status} -eq 0 ]] &&
      [[ -f autobahn/server/index.json ]]
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
      echo "Autobahn server shard ${name} failed; retrying it once"
    fi
  done

  echo "Autobahn server shard ${name} failed with status ${client_status}"
  return "${client_status}"
}

test_diff() {
  echo "Comparing server Autobahn results…"

  if
    DIFF_OUTPUT=$(
      diff -u \
        <(jq -S 'del(."Rama" | .. | .duration?)' autobahn/expected-server-results.json) \
        <(jq -S 'del(."Rama" | .. | .duration?)' autobahn/server/index.json)
    )
  then
    STATUS=0
  else
    STATUS=$?
  fi

  if [[ $STATUS -eq 1 ]]; then
    echo "❌ Difference detected between expected and actual results:"
    echo
    echo "$DIFF_OUTPUT"
    echo
    echo "Either this is a regression, or update autobahn/expected-server-results.json with the new results."
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
    ECHO_BIND_ADDR="0.0.0.0:9002"
    PLATFORM_SPECIFIC_DOCKER_ARGS="--add-host=host.docker.internal:host-gateway"
    ;;
  Darwin)
    ECHO_BIND_ADDR="127.0.0.1:9002"
    PLATFORM_SPECIFIC_DOCKER_ARGS="--network=host"
    ;;
  *)
    echo "unsupported platform"; exit 1;;
esac

cargo build --release -p rama-cli
target_dir=$(cargo metadata --no-deps --format-version 1 | jq -r .target_directory)
"$target_dir/release/rama" serve echo --ws --bind "$ECHO_BIND_ADDR" &
WSSERVER_PID=$!

if ! wait_for_wsserver; then
  echo "The Rama echo server did not start listening on ${ECHO_BIND_ADDR}"
  exit 1
fi

SHARD_SPEC=$(mktemp "${PWD}/autobahn/fuzzingclient-shard.XXXXXX")
MERGED_REPORT=$(mktemp)
jq -n '{"Rama": {}}' >"${MERGED_REPORT}"

rm -rf -- autobahn/server
mkdir -p autobahn/server

# One wstest process per shard: a killed container costs one shard, retried once.
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

mv "${MERGED_REPORT}" autobahn/server/index.json
MERGED_REPORT=""
test_diff
