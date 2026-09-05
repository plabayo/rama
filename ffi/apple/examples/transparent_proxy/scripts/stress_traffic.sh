#!/usr/bin/env bash
# Quick traffic stress generator for the rama transparent proxy
# example. Run from a normal terminal while the sysext is active —
# `curl` traffic from this shell flows through the proxy by default.
#
# Mixes the cases that flush retain leaks, byte-counter drift,
# backpressure stalls, and MITM relay errors:
#   - many small HTTPS GETs       (connect / TLS-handshake churn)
#   - large response GET          (egress→ingress backpressure)
#   - large POST body             (ingress→egress backpressure)
#   - HTTP/1.1 + HTTP/2 mix       (relay routing)
#   - parallel connections        (cross-flow concurrency)
#   - quick open/close churn      (session / NEAppProxyFlow churn)
#   - plain HTTP                  (peek path, no MITM)
#
# Tunables (env):
#   STRESS_DURATION       wall-clock seconds, per worker (0..86400). Default 60.
#   STRESS_CONCURRENCY    parallel curls in the pool worker (1..512). Default 16.
#   STRESS_LARGE_BYTES    bytes for the large-GET worker (max 1 GiB). Default 16 MiB.
#   STRESS_POST_BYTES     bytes for the POST-body worker (max 1 GiB). Default 8 MiB.
#   STRESS_HTTP_TARGET    plain-HTTP target. Default http-test /method
#   STRESS_HTTPS_TARGET   HTTPS target. Default http-test /method
#   STRESS_LARGE_TARGET   large-download target. Default http-test /bytes
#   STRESS_POST_TARGET    POST echo target. Default http-test /octet-stream
#   STRESS_LOG_DIR        where per-worker logs go. Default mktemp.
#   STRESS_MONITOR_PID    if set, periodically records a bounded, generation-
#                         bound resource sample for the pid. Also enables
#                         before/after `vmmap`+`heap`
#                         snapshots (`preflight.txt`, `postflight.txt`)
#                         in the log dir for self-contained diff.
#   STRESS_NDJSON         path to a captured `log show … --style ndjson`
#                         file for an unmonitored diagnostic histogram.
#                         Monitored mode owns and seals its log stream.
#                         When set, the summary parses it to
#                         produce a close-reason histogram. Collect with:
#                           sudo log show \
#                             --predicate 'subsystem == "org.ramaproxy.example.tproxy"' \
#                             --start "$(date -u -v-10M '+%Y-%m-%d %H:%M:%S')" \
#                             --style ndjson > /tmp/system.ndjson
#   STRESS_SKIP_LIVENESS  set to 1 to skip the pre-flight liveness
#                         probe. Default off — without the probe we
#                         can spend 180s pounding nothing if the
#                         sysext crashed or is uninstalled.
#   STRESS_MAX_P95_MS / STRESS_MIN_THROUGHPUT_MILLI_RPS
#                         absolute latency/throughput gates (10000 / 100).
#   STRESS_MAX_RSS_GROWTH_BYTES / STRESS_MAX_CPU_PERCENT
#                         monitored-provider resource gates (64 MiB / 400%).
#   STRESS_TRAFFIC_ROLE   unpaired-diagnostic (default), direct-baseline, or
#                         proxy-candidate; stress_compare.py verifies pairs.
#   STRESS_BUILT_PROVIDER / STRESS_INSTALLED_PROVIDER
#                         required for proxy-candidate; exact signed provider
#                         bundles passed to the common identity verifier.
#
# Evidence scope is explicit: without STRESS_MONITOR_PID this is traffic-only.
# With a pid it additionally proves that one stable provider process stayed
# alive. A proxy-candidate run also sends a private run-UUID/request-ID marker
# on every stress request; the MITM relay consumes it and emits a privacy-safe
# marker.
#
# All workers run in parallel for STRESS_DURATION seconds. When
# `STRESS_DURATION=0`, the script skips traffic generation and runs
# only the artifact-analysis summary.

set -uo pipefail

DURATION="${STRESS_DURATION-60}"
CONCURRENCY="${STRESS_CONCURRENCY-16}"
LARGE_BYTES="${STRESS_LARGE_BYTES-16777216}"   # 16 MiB
POST_BYTES="${STRESS_POST_BYTES-8388608}"      # 8 MiB
MONITOR_PID="${STRESS_MONITOR_PID:-}"
NDJSON_PATH="${STRESS_NDJSON:-}"
SKIP_LIVENESS="${STRESS_SKIP_LIVENESS-0}"
MAX_P95_MS="${STRESS_MAX_P95_MS-10000}"
MIN_THROUGHPUT_MILLI_RPS="${STRESS_MIN_THROUGHPUT_MILLI_RPS-100}"
MAX_RSS_GROWTH_BYTES="${STRESS_MAX_RSS_GROWTH_BYTES-67108864}"
MAX_CPU_PERCENT="${STRESS_MAX_CPU_PERCENT-400}"
TRAFFIC_ROLE="${STRESS_TRAFFIC_ROLE-unpaired-diagnostic}"
ALLOW_TEST_TOOLS="${STRESS_ALLOW_TEST_TOOLS-0}"
LOG_TOOL="${STRESS_LOG_TOOL:-/usr/bin/log}"
CURL_TOOL="${STRESS_CURL_TOOL:-/usr/bin/curl}"
EXPECTED_PROVIDER_SUBSYSTEM=org.ramaproxy.example.tproxy.dev.provider
EXPECTED_STRESS_EVENT_PREFIX='[rama_tproxy_example::stress_attribution] rama stress request attributed: run_uuid='
CRASH_PROCESS=RamaTransparentProxyExampleExtension
BUILT_PROVIDER="${STRESS_BUILT_PROVIDER:-}"
INSTALLED_PROVIDER="${STRESS_INSTALLED_PROVIDER:-}"

# Keep user-controlled values out of Bash arithmetic until they are known to be
# canonical decimal strings and within workload-sized bounds. In particular,
# Bash treats a leading zero as octal and silently wraps overflowing integers.
require_bounded_uint() {
  local name="$1" value="$2" maximum="$3"
  local LC_ALL=C
  if [[ ! "$value" =~ ^(0|[1-9][0-9]*)$ ]]; then
    printf '[stress] %s must be a canonical non-negative decimal integer (got %q)\n' \
      "$name" "$value" >&2
    exit 2
  fi
  if [[ ${#value} -gt ${#maximum} ]] \
    || [[ ${#value} -eq ${#maximum} && "$value" > "$maximum" ]]
  then
    printf '[stress] %s must be at most %s (got %s)\n' \
      "$name" "$maximum" "$value" >&2
    exit 2
  fi
}

require_boolean() {
  local name="$1" value="$2"
  if [[ "$value" != 0 && "$value" != 1 ]]; then
    printf '[stress] %s must be 0 or 1 (got %q)\n' "$name" "$value" >&2
    exit 2
  fi
}

require_bounded_uint STRESS_DURATION "$DURATION" 86400
require_bounded_uint STRESS_CONCURRENCY "$CONCURRENCY" 512
require_bounded_uint STRESS_LARGE_BYTES "$LARGE_BYTES" 1073741824
require_bounded_uint STRESS_POST_BYTES "$POST_BYTES" 1073741824
require_boolean STRESS_SKIP_LIVENESS "$SKIP_LIVENESS"
require_boolean STRESS_ALLOW_TEST_TOOLS "$ALLOW_TEST_TOOLS"
require_bounded_uint STRESS_MAX_P95_MS "$MAX_P95_MS" 600000
require_bounded_uint STRESS_MIN_THROUGHPUT_MILLI_RPS "$MIN_THROUGHPUT_MILLI_RPS" 1000000
require_bounded_uint STRESS_MAX_RSS_GROWTH_BYTES "$MAX_RSS_GROWTH_BYTES" 10737418240
require_bounded_uint STRESS_MAX_CPU_PERCENT "$MAX_CPU_PERCENT" 10000
case "$TRAFFIC_ROLE" in
  unpaired-diagnostic|direct-baseline|proxy-candidate) ;;
  *)
    printf '[stress] STRESS_TRAFFIC_ROLE must be unpaired-diagnostic, direct-baseline, or proxy-candidate\n' >&2
    exit 2
    ;;
esac
if [[ "$TRAFFIC_ROLE" == proxy-candidate ]]; then
  [[ -n "$MONITOR_PID" && -n "$BUILT_PROVIDER" && -n "$INSTALLED_PROVIDER" ]] || {
    printf '[stress] proxy-candidate requires STRESS_MONITOR_PID, STRESS_BUILT_PROVIDER, and STRESS_INSTALLED_PROVIDER\n' >&2
    exit 2
  }
  [[ "$LOG_TOOL" == /usr/bin/log && "$CURL_TOOL" == /usr/bin/curl ]] || {
    printf '[stress] proxy-candidate requires SIP-protected /usr/bin/log and /usr/bin/curl\n' >&2
    exit 2
  }
elif [[ "$TRAFFIC_ROLE" == direct-baseline ]]; then
  [[ -z "$MONITOR_PID" ]] || {
    printf '[stress] direct-baseline requires the development provider to be absent\n' >&2
    exit 2
  }
  [[ "$CURL_TOOL" == /usr/bin/curl ]] || {
    printf '[stress] direct-baseline requires SIP-protected /usr/bin/curl\n' >&2
    exit 2
  }
fi
if [[ "$TRAFFIC_ROLE" != proxy-candidate && "$ALLOW_TEST_TOOLS" != 1 \
  && ( "$LOG_TOOL" != /usr/bin/log || "$CURL_TOOL" != /usr/bin/curl ) ]]
then
  printf '[stress] non-release tool injection requires STRESS_ALLOW_TEST_TOOLS=1\n' >&2
  exit 2
fi
if [[ -n "$MONITOR_PID" ]]; then
  require_bounded_uint STRESS_MONITOR_PID "$MONITOR_PID" 2147483647
  [[ "$MONITOR_PID" != 0 ]] || {
    printf '[stress] STRESS_MONITOR_PID must be greater than zero\n' >&2
    exit 2
  }
  [[ -x "$LOG_TOOL" ]] || {
    printf '[stress] STRESS_LOG_TOOL must name an executable log tool\n' >&2
    exit 2
  }
fi
[[ -x "$CURL_TOOL" ]] || {
  printf '[stress] configured curl tool is not executable\n' >&2
  exit 2
}
[[ "$CONCURRENCY" != 0 ]] || {
  printf '[stress] STRESS_CONCURRENCY must be greater than zero\n' >&2
  exit 2
}
if [[ "$DURATION" != 0 && ( "$LARGE_BYTES" == 0 || "$POST_BYTES" == 0 ) ]]; then
  printf '[stress] STRESS_LARGE_BYTES and STRESS_POST_BYTES must be greater than zero when traffic is enabled\n' >&2
  exit 2
fi

HTTP_TARGET="${STRESS_HTTP_TARGET:-http://http-test.ramaproxy.org/method}"
HTTPS_TARGET="${STRESS_HTTPS_TARGET:-https://http-test.ramaproxy.org/method}"
POST_TARGET="${STRESS_POST_TARGET:-https://http-test.ramaproxy.org/octet-stream}"
LARGE_TARGET="${STRESS_LARGE_TARGET:-https://http-test.ramaproxy.org/bytes?size=${LARGE_BYTES}}"
WORKLOAD_IDENTITY=none

if [[ "$TRAFFIC_ROLE" == direct-baseline || "$TRAFFIC_ROLE" == proxy-candidate ]]; then
  if [[ "$DURATION" != 60 || "$CONCURRENCY" != 16 \
    || "$LARGE_BYTES" != 16777216 || "$POST_BYTES" != 8388608 \
    || "$MAX_P95_MS" != 10000 || "$MIN_THROUGHPUT_MILLI_RPS" != 100 \
    || "$MAX_RSS_GROWTH_BYTES" != 67108864 || "$MAX_CPU_PERCENT" != 400 \
    || "$HTTP_TARGET" != http://http-test.ramaproxy.org/method \
    || "$HTTPS_TARGET" != https://http-test.ramaproxy.org/method \
    || "$LARGE_TARGET" != 'https://http-test.ramaproxy.org/bytes?size=16777216' \
    || "$POST_TARGET" != https://http-test.ramaproxy.org/octet-stream ]]
  then
    printf '[stress] release stress roles require the canonical workload, targets, and hard threshold policy\n' >&2
    exit 2
  fi
fi

LOG_DIR="${STRESS_LOG_DIR:-$(mktemp -d /tmp/rama-stress.XXXXXX)}"
mkdir -p "$LOG_DIR"
EVIDENCE_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stress_evidence.py"
COMMON_EVIDENCE_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/signed_run_evidence.py"
RUN_UUID=none
RUN_START_EPOCH=0
RUN_END_EPOCH=0
TRAFFIC_START_EPOCH=0
TRAFFIC_END_EPOCH=0
TRAFFIC_START_MONOTONIC_NS=0
TRAFFIC_END_MONOTONIC_NS=0
ARTIFACT_MANIFEST_SHA256=none
OBSERVED_P95_MS=0
OBSERVED_THROUGHPUT_MILLI_RPS=0
OBSERVED_RSS_GROWTH_BYTES=not_applicable
OBSERVED_MAX_CPU_PERCENT=not_applicable
GIT_HEAD=none
GIT_DIRTY=none
STRESS_SCRIPT_SHA256=none
EVIDENCE_HELPER_SHA256=none
SIGNED_EVIDENCE_HELPER_SHA256=none
PROVIDER_BUILD_IDENTITY=unavailable
PROVIDER_GENERATION_IDENTITY=unavailable
PROVIDER_EXECUTABLE_SHA256=none
PROVIDER_SIGNING_IDENTIFIER=none
PROVIDER_SIGNING_TEAM=none
PROVIDER_SIGNING_CDHASH=none
NDJSON_INCLUDED=0
SYSTEM_LOG_STARTED=0
SYSTEM_LOG_ALIVE_END=0
SYSTEM_LOG_JOINED=0
SYSTEM_LOG_CHILD_RC=none
SYSTEM_LOG_TOOL_SHA256=none
PROXY_ATTRIBUTED=0
ATTRIBUTED_REQUEST_COUNT=0
DIRECT_ABSENCE_FAILED=0

ANALYZE_ONLY=0
TRAFFIC_FAILED=0
ANALYSIS_FAILED=0
EVIDENCE_FAILED=0
if [[ "$DURATION" == 0 ]]; then
  ANALYZE_ONLY=1
fi

EVIDENCE_MODE=traffic-only
[[ -n "$MONITOR_PID" ]] && EVIDENCE_MODE=provider-monitored-traffic-only
(( ANALYZE_ONLY )) && EVIDENCE_MODE=artifact-analysis-only
case "$TRAFFIC_ROLE" in
  direct-baseline) EVIDENCE_KIND=stress-direct ;;
  proxy-candidate) EVIDENCE_KIND=stress-candidate ;;
  *) EVIDENCE_KIND=stress-diagnostic ;;
esac
STATUS_PATH="$LOG_DIR/stress-status.tsv"
(( ANALYZE_ONLY )) && STATUS_PATH="$LOG_DIR/stress-analysis-status.tsv"
if (( ! ANALYZE_ONLY )) && [[ -n "$(find "$LOG_DIR" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  printf '[stress] STRESS_LOG_DIR must be empty for a new source run\n' >&2
  exit 2
fi
if (( ! ANALYZE_ONLY )); then
  WORKLOAD_IDENTITY="$(
    "$EVIDENCE_HELPER" workload "$LOG_DIR" \
      "$DURATION" "$CONCURRENCY" "$LARGE_BYTES" "$POST_BYTES" \
      "$HTTP_TARGET" "$HTTPS_TARGET" "$LARGE_TARGET" "$POST_TARGET"
  )" || {
    printf '[stress] stress targets or workload parameters are invalid\n' >&2
    exit 2
  }
  [[ "$WORKLOAD_IDENTITY" =~ ^[0-9a-f]{64}$ ]] || exit 2
fi
TRAFFIC_PIDS=()
AUXILIARY_PIDS=()
AUXILIARY_DRAIN_RECEIPTS=()
MONITOR_JOB_PID=""
ABSENCE_MONITOR_JOB_PID=""
GENERATION_MONITOR_JOB_PID=""
SYSTEM_LOG_JOB_PID=""
SYSTEM_LOG_JOB_IDENTITY=""
MONITOR_STOP_FILE="$LOG_DIR/.monitor.stop"
GENERATION_STOP_FILE="$LOG_DIR/.generation.stop"
RESPONSE_TMP_DIR="$LOG_DIR/.responses"
CLEANUP_STARTED=0
CLEANUP_INCOMPLETE=0
TERMINAL_STATUS_WRITTEN=0
TERMINAL_EXIT_CODE=2
rm -f -- "$MONITOR_STOP_FILE" "$GENERATION_STOP_FILE"

# Capture the source verdict before analysis-only mode replaces the status file
# with its own terminal verdict. A re-analysis is meaningful only when it is
# anchored to a completed, successful traffic run rather than an arbitrary
# directory containing stale or hand-written summaries.
ANALYSIS_SOURCE_STATUS_OK=0
if (( ANALYZE_ONLY )); then
  SOURCE_EVIDENCE="$("$EVIDENCE_HELPER" verify "$LOG_DIR" 2>/dev/null || true)"
  if [[ "$SOURCE_EVIDENCE" =~ ^[0-9a-f-]+$'\t'[0-9]+$'\t'[0-9]+$'\t'[0-9a-f]{64}$ ]]; then
    IFS=$'\t' read -r RUN_UUID RUN_START_EPOCH RUN_END_EPOCH \
      ARTIFACT_MANIFEST_SHA256 <<< "$SOURCE_EVIDENCE"
    source_status_value() {
      awk -F '\t' -v key="$1" '$1 == key { print $2 }' \
        "$LOG_DIR/stress-status.tsv"
    }
    MAX_P95_MS="$(source_status_value max_p95_ms)"
    MIN_THROUGHPUT_MILLI_RPS="$(source_status_value min_throughput_milli_rps)"
    MAX_RSS_GROWTH_BYTES="$(source_status_value max_rss_growth_bytes)"
    MAX_CPU_PERCENT="$(source_status_value max_cpu_percent)"
    OBSERVED_P95_MS="$(source_status_value observed_p95_ms)"
    OBSERVED_THROUGHPUT_MILLI_RPS="$(source_status_value observed_throughput_milli_rps)"
    OBSERVED_RSS_GROWTH_BYTES="$(source_status_value observed_rss_growth_bytes)"
    OBSERVED_MAX_CPU_PERCENT="$(source_status_value observed_max_cpu_percent)"
    GIT_HEAD="$(source_status_value git_head)"
    GIT_DIRTY="$(source_status_value git_dirty)"
    TRAFFIC_ROLE="$(source_status_value traffic_role)"
    WORKLOAD_IDENTITY="$(source_status_value workload_identity)"
    STRESS_SCRIPT_SHA256="$(source_status_value stress_script_sha256)"
    EVIDENCE_HELPER_SHA256="$(source_status_value evidence_helper_sha256)"
    MONITOR_PID="$(source_status_value provider_pid)"
    MONITOR_IDENTITY="$(source_status_value provider_identity)"
    PROVIDER_EXECUTABLE_SHA256="$(source_status_value provider_executable_sha256)"
    PROVIDER_SIGNING_IDENTIFIER="$(source_status_value provider_signing_identifier)"
    PROVIDER_SIGNING_TEAM="$(source_status_value provider_signing_team)"
    PROVIDER_SIGNING_CDHASH="$(source_status_value provider_signing_cdhash)"
    NDJSON_INCLUDED="$(source_status_value ndjson_included)"
    SYSTEM_LOG_STARTED="$(source_status_value system_log_started)"
    SYSTEM_LOG_ALIVE_END="$(source_status_value system_log_alive_end)"
    SYSTEM_LOG_JOINED="$(source_status_value system_log_joined)"
    SYSTEM_LOG_CHILD_RC="$(source_status_value system_log_child_rc)"
    SYSTEM_LOG_TOOL_SHA256="$(source_status_value system_log_tool_sha256)"
    [[ "$MONITOR_PID" != none ]] || MONITOR_PID=""
    [[ "$NDJSON_INCLUDED" != 1 ]] || NDJSON_PATH="$LOG_DIR/system.ndjson"
    ANALYSIS_SOURCE_STATUS_OK=1
  fi
else
  RUN_UUID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  if [[ "$TRAFFIC_ROLE" == direct-baseline ]]; then
    PROVIDER_BUILD_IDENTITY=absent
    PROVIDER_GENERATION_IDENTITY=absent
  else
    RUN_START_EPOCH="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  fi
fi

write_stress_status() {
  local complete="$1" passed="$2" exit_code="$3" issue="${4:-}"
  local tmp="$STATUS_PATH.tmp.$$"
  {
    printf 'complete\t%s\npassed\t%s\nexit_code\t%s\n' \
      "$complete" "$passed" "$exit_code"
    printf 'evidence_mode\t%s\nproxy_attributed\t%s\n' \
      "$EVIDENCE_MODE" "$PROXY_ATTRIBUTED"
    printf 'evidence_claim\tself-attested-local-integrity-not-authenticity\n'
    printf 'traffic_role\t%s\nworkload_identity\t%s\n' \
      "$TRAFFIC_ROLE" "$WORKLOAD_IDENTITY"
    printf 'run_uuid\t%s\nrun_start_epoch\t%s\nrun_end_epoch\t%s\n' \
      "$RUN_UUID" "$RUN_START_EPOCH" "$RUN_END_EPOCH"
    printf 'artifact_manifest_sha256\t%s\n' "$ARTIFACT_MANIFEST_SHA256"
    printf 'max_p95_ms\t%s\nmin_throughput_milli_rps\t%s\n' \
      "$MAX_P95_MS" "$MIN_THROUGHPUT_MILLI_RPS"
    printf 'max_rss_growth_bytes\t%s\nmax_cpu_percent\t%s\n' \
      "$MAX_RSS_GROWTH_BYTES" "$MAX_CPU_PERCENT"
    printf 'observed_p95_ms\t%s\nobserved_throughput_milli_rps\t%s\n' \
      "$OBSERVED_P95_MS" "$OBSERVED_THROUGHPUT_MILLI_RPS"
    printf 'observed_rss_growth_bytes\t%s\nobserved_max_cpu_percent\t%s\n' \
      "$OBSERVED_RSS_GROWTH_BYTES" "$OBSERVED_MAX_CPU_PERCENT"
    printf 'git_head\t%s\ngit_dirty\t%s\n' "$GIT_HEAD" "$GIT_DIRTY"
    printf 'stress_script_sha256\t%s\nevidence_helper_sha256\t%s\n' \
      "$STRESS_SCRIPT_SHA256" "$EVIDENCE_HELPER_SHA256"
    printf 'provider_pid\t%s\nprovider_identity\t%s\n' \
      "${MONITOR_PID:-none}" "${MONITOR_IDENTITY:-none}"
    printf 'provider_executable_sha256\t%s\n' "$PROVIDER_EXECUTABLE_SHA256"
    printf 'provider_signing_identifier\t%s\nprovider_signing_team\t%s\n' \
      "$PROVIDER_SIGNING_IDENTIFIER" "$PROVIDER_SIGNING_TEAM"
    printf 'provider_signing_cdhash\t%s\nndjson_included\t%s\n' \
      "$PROVIDER_SIGNING_CDHASH" "$NDJSON_INCLUDED"
    printf 'system_log_started\t%s\nsystem_log_alive_end\t%s\n' \
      "$SYSTEM_LOG_STARTED" "$SYSTEM_LOG_ALIVE_END"
    printf 'system_log_joined\t%s\nsystem_log_child_rc\t%s\n' \
      "$SYSTEM_LOG_JOINED" "$SYSTEM_LOG_CHILD_RC"
    printf 'system_log_tool_sha256\t%s\n' "$SYSTEM_LOG_TOOL_SHA256"
    printf 'attributed_request_count\t%s\n' "$ATTRIBUTED_REQUEST_COUNT"
    [[ -z "$issue" ]] || printf 'issue\t%s\n' "$issue"
    printf 'schema_complete\t1\n'
  } > "$tmp"
  mv "$tmp" "$STATUS_PATH"
}

write_terminal_status() {
  write_stress_status "$@"
  TERMINAL_STATUS_WRITTEN=1
  TERMINAL_EXIT_CODE="$3"
  if (( ! ANALYZE_ONLY )) && [[ "$TRAFFIC_ROLE" != unpaired-diagnostic ]]; then
    write_common_evidence "$1" "$2" "$3"
    if ! seal_and_verify_common_evidence "$3"; then
      # A product pass/failure without a valid common envelope is an evidence
      # failure, never a trustworthy terminal verdict.
      if [[ "$3" != 130 && "$3" != 143 ]]; then
        write_stress_status 0 0 2 "shared signed evidence could not be sealed and verified"
        write_common_evidence 0 0 2
        seal_and_verify_common_evidence 2 || true
        TERMINAL_EXIT_CODE=2
      fi
    fi
  fi
}

common_value() {
  case "$1" in
    none|not_applicable|"") printf 'unavailable\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

write_common_evidence() {
  local complete="$1" passed="$2" exit_code="$3"
  local claims="$LOG_DIR/workload-claims.tsv" status="$LOG_DIR/evidence-status.tsv"
  local claims_tmp="$claims.tmp.$$" status_tmp="$status.tmp.$$" claims_sha
  local provider_absent=0
  [[ "$TRAFFIC_ROLE" == direct-baseline ]] && provider_absent=1
  {
    printf 'evidence_kind\t%s\n' "$EVIDENCE_KIND"
    printf 'run_uuid\t%s\n' "$RUN_UUID"
    printf 'evidence_mode\t%s\nproxy_attributed\t%s\n' \
      "$EVIDENCE_MODE" "$PROXY_ATTRIBUTED"
    printf 'evidence_claim\tself-attested-local-integrity-not-authenticity\n'
    printf 'traffic_role\t%s\nworkload_identity\t%s\n' \
      "$TRAFFIC_ROLE" "$WORKLOAD_IDENTITY"
    printf 'traffic_start_epoch_ms\t%s\ntraffic_end_epoch_ms\t%s\n' \
      "$TRAFFIC_START_EPOCH" "$TRAFFIC_END_EPOCH"
    printf 'artifact_manifest_sha256\t%s\n' "$ARTIFACT_MANIFEST_SHA256"
    printf 'max_p95_ms\t%s\nmin_throughput_milli_rps\t%s\n' \
      "$MAX_P95_MS" "$MIN_THROUGHPUT_MILLI_RPS"
    printf 'max_rss_growth_bytes\t%s\nmax_cpu_percent\t%s\n' \
      "$MAX_RSS_GROWTH_BYTES" "$MAX_CPU_PERCENT"
    printf 'observed_p95_ms\t%s\nobserved_throughput_milli_rps\t%s\n' \
      "$OBSERVED_P95_MS" "$OBSERVED_THROUGHPUT_MILLI_RPS"
    printf 'observed_rss_growth_bytes\t%s\nobserved_max_cpu_percent\t%s\n' \
      "$OBSERVED_RSS_GROWTH_BYTES" "$OBSERVED_MAX_CPU_PERCENT"
    printf 'git_head\t%s\ngit_dirty\t%s\n' "$GIT_HEAD" "$GIT_DIRTY"
    printf 'stress_script_sha256\t%s\nevidence_helper_sha256\t%s\n' \
      "$STRESS_SCRIPT_SHA256" "$EVIDENCE_HELPER_SHA256"
    printf 'signed_evidence_helper_sha256\t%s\n' "$SIGNED_EVIDENCE_HELPER_SHA256"
    printf 'provider_pid\t%s\nprovider_identity\t%s\n' \
      "${MONITOR_PID:-none}" "${MONITOR_IDENTITY:-none}"
    printf 'provider_executable_sha256\t%s\n' "$PROVIDER_EXECUTABLE_SHA256"
    printf 'provider_signing_identifier\t%s\nprovider_signing_team\t%s\n' \
      "$PROVIDER_SIGNING_IDENTIFIER" "$PROVIDER_SIGNING_TEAM"
    printf 'provider_signing_cdhash\t%s\nndjson_included\t%s\n' \
      "$PROVIDER_SIGNING_CDHASH" "$NDJSON_INCLUDED"
    printf 'system_log_started\t%s\nsystem_log_alive_end\t%s\n' \
      "$SYSTEM_LOG_STARTED" "$SYSTEM_LOG_ALIVE_END"
    printf 'system_log_joined\t%s\nsystem_log_child_rc\t%s\n' \
      "$SYSTEM_LOG_JOINED" "$SYSTEM_LOG_CHILD_RC"
    printf 'system_log_tool_sha256\t%s\n' "$SYSTEM_LOG_TOOL_SHA256"
    printf 'attributed_request_count\t%s\nprovider_absent\t%s\n' \
      "$ATTRIBUTED_REQUEST_COUNT" "$provider_absent"
    printf 'schema_complete\t1\n'
  } > "$claims_tmp"
  mv "$claims_tmp" "$claims"
  claims_sha="$(shasum -a 256 "$claims" | awk '{print $1}')"
  {
    printf 'complete\t%s\npassed\t%s\nexit_code\t%s\n' \
      "$complete" "$passed" "$exit_code"
    printf 'evidence_kind\t%s\nrun_uuid\t%s\n' "$EVIDENCE_KIND" "$RUN_UUID"
    printf 'run_start_epoch_ms\t%s\nrun_end_epoch_ms\t%s\n' \
      "$RUN_START_EPOCH" "$RUN_END_EPOCH"
    printf 'git_head\t%s\ngit_dirty\t%s\n' \
      "$(common_value "$GIT_HEAD")" "$(common_value "$GIT_DIRTY")"
    printf 'provider_build_identity\t%s\nprovider_generation_identity\t%s\n' \
      "$(common_value "$PROVIDER_BUILD_IDENTITY")" \
      "$(common_value "$PROVIDER_GENERATION_IDENTITY")"
    printf 'workload_claims_sha256\t%s\nschema_complete\t1\n' "$claims_sha"
  } > "$status_tmp"
  mv "$status_tmp" "$status"
}

seal_and_verify_common_evidence() {
  local exit_code="$1"
  (( CLEANUP_INCOMPLETE == 0 )) || return 1
  "$COMMON_EVIDENCE_HELPER" seal "$LOG_DIR" --actual-exit-code "$exit_code" \
    >/dev/null \
    && "$COMMON_EVIDENCE_HELPER" verify "$LOG_DIR" \
      --actual-exit-code "$exit_code" >/dev/null
}

write_stress_status 0 0 2 "stress run did not reach its terminal verdict"

TRAFFIC_WORKERS=(
  small_https
  small_http1
  plain_http
  large_get
  post_large
  head_only
  churn_close
  parallel_pool
)

# Pretty terminal output without forcing color where the env doesn't
# claim to support it.
if [[ -t 1 ]] && tput colors >/dev/null 2>&1; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; RESET=$'\e[0m'; RED=$'\e[31m'; GREEN=$'\e[32m'
else
  BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""
fi

say() { printf '%s[stress]%s %s\n' "$DIM" "$RESET" "$*"; }
hdr() { printf '%s[stress]%s %s%s%s\n' "$DIM" "$RESET" "$BOLD" "$*" "$RESET"; }

# Provider samples include the complete command. Cleanup instead uses the
# process generation: exec and zombie command changes do not end ownership.
# A reused pid must not retain signal authority merely because it is alive.
pid_identity() {
  local pid="$1" snapshot digest
  if [[ "${2:-command}" == generation ]]; then
    snapshot="$(ps -ww -o pid= -o lstart= -p "$pid" 2>/dev/null)" || return 1
  else
    snapshot="$(ps -ww -o pid= -o lstart= -o command= -p "$pid" 2>/dev/null)" || return 1
  fi
  [[ -n "$snapshot" ]] || return 1
  digest="$(printf '%s' "$snapshot" | shasum -a 256 | awk 'NR == 1 { print $1 }')"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

owned_job_is_active() {
  jobs -p | grep -Fqx -- "$1"
}

owned_job_has_exited() {
  local pid="$1" state
  owned_job_is_active "$pid" || return 0
  state="$(ps -o state= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  # A failed/empty ps result cannot authorize an unbounded wait on a live job.
  [[ "$state" == Z* ]] || { [[ -z "$state" ]] && ! kill -0 "$pid" 2>/dev/null; }
}

wait_proven_exited() {
  local pid="$1" timeout_seconds="$2" deadline
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    owned_job_has_exited "$pid" && break
    sleep 0.1
  done
  owned_job_has_exited "$pid" || return 124
  wait "$pid"
}

collect_owned_tree() {
  local pid="$1" expected_identity="$2" child child_identity children child_ppid group
  local failed=0 discovery_rc=0 discovery_deadline="${3:-$((SECONDS + 1))}"
  if [[ "${4:-}" != recursive ]]; then
    local OWNED_COLLECT_SEEN=() OWNED_COLLECT_COUNT=0
  fi
  [[ "${OWNED_COLLECT_SEEN[pid]:-}" != "$expected_identity" ]] || return 0
  OWNED_COLLECT_SEEN[pid]="$expected_identity"
  OWNED_COLLECT_COUNT=$((OWNED_COLLECT_COUNT + 1))
  # Retain every already-stopped identity even when discovery expires, so
  # partial snapshots still carry authority to thaw and kill the root group.
  printf '%s\t%s\n' "$pid" "$expected_identity"
  (( OWNED_COLLECT_COUNT <= 128 && SECONDS < discovery_deadline )) || return 1
  # The caller has stopped this generation. Recheck before following a parent
  # pid that might otherwise have exited and been reused during discovery.
  [[ "$(pid_identity "$pid" generation || true)" == "$expected_identity" ]] || return 1
  group="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  if [[ "$group" == "$pid" ]]; then
    # Capture supervisors own a dedicated group. It also contains descendants
    # whose immediate parents exited before cleanup began.
    children="$(pgrep -g "$pid" 2>/dev/null)" || discovery_rc=$?
  else
    children="$(pgrep -P "$pid" 2>/dev/null)" || discovery_rc=$?
  fi
  # pgrep uses 1 for an empty result; errors must not become a complete tree.
  (( discovery_rc <= 1 )) || failed=1
  while IFS= read -r child; do
    [[ "$child" =~ ^[1-9][0-9]*$ ]] || continue
    [[ "$child" != "$pid" ]] || continue
    # The group snapshot also lists members reached through parent links.
    # Those stopped generations must not trigger another recursive traversal.
    [[ -z "${OWNED_COLLECT_SEEN[child]:-}" ]] || continue
    (( OWNED_COLLECT_COUNT < 128 && SECONDS < discovery_deadline )) || { failed=1; break; }
    child_identity="$(pid_identity "$child" generation || true)"
    [[ "$child_identity" =~ ^[0-9a-f]{64}$ ]] || continue
    if [[ "$group" == "$pid" ]]; then
      child_ppid="$(ps -o pgid= -p "$child" 2>/dev/null | tr -d '[:space:]')"
    else
      child_ppid="$(ps -o ppid= -p "$child" 2>/dev/null | tr -d '[:space:]')"
    fi
    [[ "$child_ppid" == "$pid" ]] || continue
    if signal_owned_identity "$child" "$child_identity" STOP; then
      collect_owned_tree "$child" "$child_identity" "$discovery_deadline" recursive || failed=1
    elif ! owned_identity_has_exited "$child" "$child_identity"; then
      failed=1
    fi
  done <<< "$children"
  return "$failed"
}

signal_owned_identity() {
  local pid="$1" expected_identity="$2" signal="$3" observed_identity state attempt target
  observed_identity="$(pid_identity "$pid" generation || true)"
  [[ "$observed_identity" == "$expected_identity" ]] || return 1
  target="$pid"
  if [[ "$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')" == "$pid" ]]; then
    target="-$pid"
  fi
  kill "-$signal" -- "$target" 2>/dev/null || return 1
  [[ "$signal" == STOP ]] || return 0
  # STOP delivery is asynchronous. Confirm it before trusting a child snapshot;
  # a still-running parent could fork after pgrep has already enumerated it.
  for ((attempt=0; attempt<10; attempt++)); do
    observed_identity="$(pid_identity "$pid" generation || true)"
    [[ "$observed_identity" == "$expected_identity" ]] || return 1
    state="$(ps -o state= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
    [[ "$state" == T* || "$state" == Z* ]] && return 0
    sleep 0.01
  done
  # Keep authority only over the generation we stopped; never CONT a changed
  # identity in an attempt to undo a raced STOP.
  observed_identity="$(pid_identity "$pid" generation || true)"
  [[ "$observed_identity" != "$expected_identity" ]] || kill -CONT -- "$target" 2>/dev/null || true
  return 1
}

owned_identity_has_exited() {
  local pid="$1" expected_identity="$2" state observed_identity
  observed_identity="$(pid_identity "$pid" generation || true)"
  if [[ -n "$observed_identity" && "$observed_identity" != "$expected_identity" ]]; then
    return 0
  fi
  state="$(ps -o state= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  [[ "$state" == Z* ]] && return 0
  # An inspection failure is not proof of exit while the pid is still alive.
  [[ -z "$state" ]] && ! kill -0 "$pid" 2>/dev/null
}

owned_tree_has_exited() {
  local tree_text="$1" pid identity
  while IFS=$'\t' read -r pid identity; do
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$identity" =~ ^[0-9a-f]{64}$ ]] || continue
    owned_identity_has_exited "$pid" "$identity" || return 1
  done <<< "$tree_text"
}

capture_drain_receipt_valid() {
  local receipt="$1" expected_status="$2" value source_pid
  [[ -f "$receipt" && ! -L "$receipt" ]] || return 1
  value="$(cat "$receipt")" || return 1
  source_pid="${value%%$'\t'*}"
  [[ "$source_pid" =~ ^[1-9][0-9]*$ \
    && "$value" == "$source_pid"$'\t'"$expected_status" ]]
}

cleanup_owned_jobs() {
  local scope="${1:-all}"
  if [[ "$scope" == all ]]; then
    (( CLEANUP_STARTED == 0 )) || return 0
    CLEANUP_STARTED=1
    : > "$MONITOR_STOP_FILE"
    : > "$GENERATION_STOP_FILE"
  elif [[ "$scope" != system-log ]]; then
    return 2
  fi
  local pid identity deadline active tree_text="" subtree child_rc response_artifact index
  local auxiliary_receipt root_frozen
  local system_log_cleanup_pid="$SYSTEM_LOG_JOB_PID"
  local owned=() frozen=()
  set +u
  if [[ "$scope" == all ]]; then
    owned=("${TRAFFIC_PIDS[@]}" "${AUXILIARY_PIDS[@]}")
    [[ -z "$MONITOR_JOB_PID" ]] || owned+=("$MONITOR_JOB_PID")
    [[ -z "$ABSENCE_MONITOR_JOB_PID" ]] || owned+=("$ABSENCE_MONITOR_JOB_PID")
    [[ -z "$GENERATION_MONITOR_JOB_PID" ]] || owned+=("$GENERATION_MONITOR_JOB_PID")
  fi
  [[ -z "$SYSTEM_LOG_JOB_PID" ]] || owned+=("$SYSTEM_LOG_JOB_PID")
  if [[ -n "$system_log_cleanup_pid" ]] \
    && owned_job_is_active "$system_log_cleanup_pid" \
    && [[ "$(pid_identity "$system_log_cleanup_pid" generation || true)" == "$SYSTEM_LOG_JOB_IDENTITY" ]]
  then
    SYSTEM_LOG_ALIVE_END=1
  fi
  # Freeze each direct worker before walking its descendants. This closes the
  # race where a worker starts another curl between a tree snapshot and TERM,
  # leaving that just-created process orphaned outside our cleanup authority.
  deadline=$((SECONDS + 5))
  for pid in "${owned[@]}"; do
    identity="$(pid_identity "$pid" generation || true)"
    if owned_job_is_active "$pid" \
      && [[ "$identity" =~ ^[0-9a-f]{64}$ ]] \
      && signal_owned_identity "$pid" "$identity" STOP
    then
      frozen+=("$pid" "$identity")
    elif ! owned_job_has_exited "$pid"; then
      CLEANUP_INCOMPLETE=1
    fi
  done
  for ((index=0; index<${#frozen[@]}; index+=2)); do
    pid="${frozen[index]}"
    identity="${frozen[index+1]}"
    subtree="$(collect_owned_tree "$pid" "$identity" "$deadline")" || CLEANUP_INCOMPLETE=1
    tree_text="${tree_text}${subtree}"$'\n'
  done
  while IFS=$'\t' read -r pid identity; do
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
    [[ "$identity" =~ ^[0-9a-f]{64}$ ]] || continue
    signal_owned_identity "$pid" "$identity" TERM || true
  done <<< "$tree_text"
  while IFS=$'\t' read -r pid identity; do
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
    [[ "$identity" =~ ^[0-9a-f]{64}$ ]] || continue
    signal_owned_identity "$pid" "$identity" CONT || true
  done <<< "$tree_text"
  while (( SECONDS < deadline )); do
    active=0
    for pid in "${owned[@]}"; do
      owned_job_has_exited "$pid" || { active=1; break; }
    done
    if (( ! active )) && owned_tree_has_exited "$tree_text"; then break; fi
    sleep 0.1
  done
  while IFS=$'\t' read -r pid identity; do
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
    [[ "$identity" =~ ^[0-9a-f]{64}$ ]] || continue
    signal_owned_identity "$pid" "$identity" KILL || true
  done <<< "$tree_text"
  deadline=$(( SECONDS + 2 ))
  while (( SECONDS < deadline )); do
    active=0
    for pid in "${owned[@]}"; do
      owned_job_has_exited "$pid" || { active=1; break; }
    done
    if (( ! active )) && owned_tree_has_exited "$tree_text"; then break; fi
    sleep 0.1
  done
  owned_tree_has_exited "$tree_text" || CLEANUP_INCOMPLETE=1
  for pid in "${owned[@]}"; do
    if ! owned_job_has_exited "$pid"; then
      CLEANUP_INCOMPLETE=1
      continue
    fi
    auxiliary_receipt="${AUXILIARY_DRAIN_RECEIPTS[pid]:-}"
    child_rc=0
    wait "$pid" 2>/dev/null || child_rc=$?
    for index in "${!AUXILIARY_PIDS[@]}"; do
      [[ "${AUXILIARY_PIDS[index]}" != "$pid" ]] || unset 'AUXILIARY_PIDS[index]'
    done
    unset 'AUXILIARY_DRAIN_RECEIPTS[pid]'
    if [[ -n "$auxiliary_receipt" ]]; then
      root_frozen=0
      for ((index=0; index<${#frozen[@]}; index+=2)); do
        [[ "${frozen[index]}" != "$pid" ]] || root_frozen=1
      done
      # An auxiliary supervisor may have exited just before EXIT cleanup. If
      # this cleanup did not own its stopped group, require its drain proof.
      if (( root_frozen == 0 )) \
        && ! capture_drain_receipt_valid "$auxiliary_receipt" "$child_rc"
      then
        CLEANUP_INCOMPLETE=1
      fi
      rm -f -- "$auxiliary_receipt"
    fi
    if [[ -n "$system_log_cleanup_pid" && "$pid" == "$system_log_cleanup_pid" ]]; then
      SYSTEM_LOG_CHILD_RC="$child_rc"
      SYSTEM_LOG_JOINED=1
      SYSTEM_LOG_JOB_PID=""
    fi
  done
  if [[ -d "$RESPONSE_TMP_DIR" ]]; then
    for response_artifact in "$RESPONSE_TMP_DIR"/post.*; do
      [[ -f "$response_artifact" ]] || continue
      rm -f -- "$response_artifact"
    done
  fi
  set -u
}

monitor_provider_absence() {
  while [[ ! -e "$MONITOR_STOP_FILE" ]]; do
    "$COMMON_EVIDENCE_HELPER" capture-provider-absence \
      --append "$LOG_DIR/provider-absence.tsv" >/dev/null || return 42
    sleep 1
  done
}

monitor_provider_generation() {
  while [[ ! -e "$GENERATION_STOP_FILE" ]]; do
    sleep 2
    [[ ! -e "$GENERATION_STOP_FILE" ]] || break
    "$COMMON_EVIDENCE_HELPER" capture-provider-generation \
      --identity "$LOG_DIR/provider-identity.tsv" \
      --append "$LOG_DIR/provider-generation-samples.tsv" >/dev/null || return 42
  done
}

# Invoked indirectly by the signal traps installed below.
# shellcheck disable=SC2329
handle_signal() {
  local exit_code="$1"
  trap - EXIT INT TERM
  if (( ! ANALYZE_ONLY && RUN_END_EPOCH == 0 )); then
    RUN_END_EPOCH="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  fi
  cleanup_owned_jobs
  write_terminal_status 0 0 "$exit_code" "stress run interrupted by signal"
  exit "$TERMINAL_EXIT_CODE"
}

# Invoked indirectly by the EXIT trap installed below.
# shellcheck disable=SC2329
handle_exit() {
  local exit_code=$?
  trap - EXIT INT TERM
  cleanup_owned_jobs
  if (( TERMINAL_STATUS_WRITTEN == 0 )); then
    if (( ! ANALYZE_ONLY && RUN_END_EPOCH == 0 )); then
      RUN_END_EPOCH="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
    fi
    write_terminal_status 0 0 2 "stress run exited before its terminal verdict"
    exit_code="$TERMINAL_EXIT_CODE"
  fi
  exit "$exit_code"
}

trap handle_exit EXIT
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

if (( ! ANALYZE_ONLY )) && [[ "$TRAFFIC_ROLE" == direct-baseline ]]; then
  ABSENCE_RESULT="$(
    "$COMMON_EVIDENCE_HELPER" capture-provider-absence \
      --cadence-ms 1000 --max-gap-ms 2500 \
      --output "$LOG_DIR/provider-absence.tsv"
  )" || DIRECT_ABSENCE_FAILED=1
  RUN_START_EPOCH="$(printf '%s\n' "$ABSENCE_RESULT" | awk -F '\t' '$1 == "epoch_ms" {print $2}')"
  if [[ ! "$RUN_START_EPOCH" =~ ^[1-9][0-9]*$ ]]; then
    RUN_START_EPOCH="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
    DIRECT_ABSENCE_FAILED=1
  fi
  if (( DIRECT_ABSENCE_FAILED == 0 )); then
    monitor_provider_absence &
    ABSENCE_MONITOR_JOB_PID="$!"
  fi
fi

if (( DIRECT_ABSENCE_FAILED )); then
  say "${RED}direct baseline found the development provider or could not prove its absence${RESET}"
  exit 2
fi

if (( ! ANALYZE_ONLY )); then
  REPO_ROOT="$(git -C "$(dirname "$EVIDENCE_HELPER")" rev-parse --show-toplevel 2>/dev/null || true)"
  [[ -n "$REPO_ROOT" ]] || {
    write_terminal_status 0 0 2 "could not resolve source repository identity"
    exit "$TERMINAL_EXIT_CODE"
  }
  cp "$0" "$LOG_DIR/source-stress_traffic.sh"
  cp "$EVIDENCE_HELPER" "$LOG_DIR/source-stress_evidence.py"
  cp "$COMMON_EVIDENCE_HELPER" "$LOG_DIR/source-signed_run_evidence.py"
  GIT_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)"
  GIT_STATUS_OUTPUT="$(
    git -C "$REPO_ROOT" status --porcelain --untracked-files=normal 2>/dev/null
  )"
  if [[ -n "$GIT_STATUS_OUTPUT" ]]; then
    printf 'source-tree-dirty\n' > "$LOG_DIR/git-status.txt"
  else
    : > "$LOG_DIR/git-status.txt"
  fi
  unset GIT_STATUS_OUTPUT
  printf '%s\n' "$GIT_HEAD" > "$LOG_DIR/git-head.txt"
  [[ -s "$LOG_DIR/git-status.txt" ]] && GIT_DIRTY=1 || GIT_DIRTY=0
  STRESS_SCRIPT_SHA256="$(shasum -a 256 "$LOG_DIR/source-stress_traffic.sh" | awk '{print $1}')"
  EVIDENCE_HELPER_SHA256="$(shasum -a 256 "$LOG_DIR/source-stress_evidence.py" | awk '{print $1}')"
  SIGNED_EVIDENCE_HELPER_SHA256="$(shasum -a 256 "$LOG_DIR/source-signed_run_evidence.py" | awk '{print $1}')"
fi

# ── Worker primitives ─────────────────────────────────────────────────

# Treat every non-2xx outcome as failure, including redirects and `000`
# transport errors.
http_status_is_ok() {
  local code="$1"
  case "$code" in
    2??) return 0 ;;
    *) return 1 ;;
  esac
}

transfer_matches_workload() {
  local label="$1" downloaded="$2" uploaded="$3" http_version="$4"
  [[ "$downloaded" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  [[ "$uploaded" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  case "$label" in
    large_get)
      [[ "$downloaded" == "$LARGE_BYTES" && "$uploaded" == 0 && "$http_version" == 2 ]]
      ;;
    post_large)
      [[ "$uploaded" == "$POST_BYTES" && "$downloaded" == "$POST_BYTES" \
        && "$http_version" == 2 ]]
      ;;
    head_only)
      [[ "$downloaded" == 0 && "$uploaded" == 0 && "$http_version" == 2 ]]
      ;;
    small_https|parallel_pool)
      (( downloaded > 0 && uploaded == 0 )) && [[ "$http_version" == 2 ]]
      ;;
    small_http1|plain_http|churn_close)
      (( downloaded > 0 && uploaded == 0 )) && [[ "$http_version" == 1.1 ]]
      ;;
    *) return 1 ;;
  esac
}

# Make curl behavior independent of user dotfiles and ambient proxy/TLS
# variables. `--disable` is deliberately curl's first argument.
run_hermetic_curl() (
  unset http_proxy https_proxy all_proxy no_proxy
  unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY
  unset CURL_HOME CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR
  exec "$CURL_TOOL" --disable --noproxy '*' --proxy '' "$@"
)

stress_request_id() {
  local label="$1" ordinal="$2" class_id ordinal_hex run_hex
  case "$label" in
    small_https) class_id=01 ;; small_http1) class_id=02 ;;
    plain_http) class_id=03 ;; large_get) class_id=04 ;;
    post_large) class_id=05 ;; head_only) class_id=06 ;;
    churn_close) class_id=07 ;; parallel_pool) class_id=08 ;;
    *) return 1 ;;
  esac
  [[ "$ordinal" =~ ^[1-9][0-9]*$ ]] || return 1
  printf -v ordinal_hex '%030x' "$ordinal" || return 1
  run_hex="${RUN_UUID//-/}"
  [[ "$run_hex" =~ ^[0-9a-f]{32}$ && "$ordinal_hex" =~ ^[0-9a-f]{30}$ ]] || return 1
  printf '%s%s%s\n' "$run_hex" "$class_id" "$ordinal_hex"
}

# Run one curl and return success only when the complete transfer succeeds with
# 2xx. A server can send a 200 header and then truncate the body; the HTTP
# code alone is therefore not an honest request outcome.
do_one_curl() {
  local label="$1" target="$2" ordinal="$3"; shift 3
  local metrics code downloaded uploaded http_version duration_seconds curl_rc=0 matched=1
  local response_file="" output_file=/dev/null request_id
  request_id="$(stress_request_id "$label" "$ordinal")" || return 1
  if [[ "$label" == post_large ]]; then
    response_file="$RESPONSE_TMP_DIR/post.${BASHPID:-$$}.$RANDOM"
    output_file="$response_file"
  fi
  local curl_args=(
    --silent --output "$output_file"
    --max-time 30
    --fail-with-body
    --write-out $'%{http_code}\t%{size_download}\t%{size_upload}\t%{http_version}\t%{time_total}'
  )
  if [[ "$TRAFFIC_ROLE" == proxy-candidate ]]; then
    curl_args+=(--header "X-Rama-Tproxy-Stress-Run: $RUN_UUID:$request_id")
  fi
  # The numeric transfer record is sufficient for the verdict. Curl's prose
  # errors can echo a configured private target, so never persist stderr.
  metrics=$(run_hermetic_curl "${curl_args[@]}" "$@" --url "$target" 2>/dev/null) || curl_rc=$?
  IFS=$'\t' read -r code downloaded uploaded http_version duration_seconds <<< "$metrics"
  [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
  printf 'request_id=%s status=%s curl_exit=%s downloaded=%s uploaded=%s http_version=%s duration_seconds=%s\n' \
    "$request_id" "$code" "$curl_rc" "${downloaded:-?}" "${uploaded:-?}" \
    "${http_version:-?}" "${duration_seconds:-?}" >>"$LOG_DIR/${label}.log"
  (( curl_rc == 0 )) \
    && http_status_is_ok "$code" \
    && transfer_matches_workload \
      "$label" "${downloaded:-}" "${uploaded:-}" "${http_version:-}" \
    && { [[ "$label" != post_large ]] || cmp -s "$POST_FILE" "$response_file"; } \
    || matched=0
  [[ -z "$response_file" ]] || rm -f -- "$response_file"
  (( matched == 1 ))
}

# Run sequential curls until DURATION elapses.
loop_http() {
  local label="$1" target="$2"; shift 2
  local end=$((SECONDS + DURATION)) iter=0 ok=0 fail=0
  while (( SECONDS < end )); do
    if do_one_curl "$label" "$target" "$((iter + 1))" "$@"; then
      ok=$((ok+1))
    else
      fail=$((fail+1))
    fi
    iter=$((iter+1))
  done
  printf '%s done: iters=%d ok=%d fail=%d\n' "$label" "$iter" "$ok" "$fail" \
    >"$LOG_DIR/${label}.summary"
  (( iter > 0 && fail == 0 ))
}

# Many curls in a bounded parallel batch, preserving each child's exit status.
loop_pool() {
  local label="$1" target="$2"; shift 2
  local end=$((SECONDS + DURATION)) iter=0 ok=0 fail=0
  while (( SECONDS < end )); do
    local batch_pids=() worker_pid worker
    for ((worker=0; worker<CONCURRENCY; worker++)); do
      do_one_curl "$label" "$target" "$((iter + worker + 1))" "$@" &
      batch_pids+=("$!")
    done
    for worker_pid in "${batch_pids[@]}"; do
      if wait "$worker_pid"; then
        ok=$((ok + 1))
      else
        fail=$((fail + 1))
      fi
    done
    iter=$((iter + CONCURRENCY))
  done
  printf '%s done: iters=%d ok=%d fail=%d\n' "$label" "$iter" "$ok" "$fail" \
    >"$LOG_DIR/${label}.summary"
  (( iter > 0 && fail == 0 ))
}

# A clean child exit is not sufficient evidence that the requested workload ran:
# a delayed worker can miss its deadline and exit after zero loop iterations.
verify_worker_progress() {
  local worker summary summary_line summary_pattern iters ok failed
  local progress_failed=0
  for worker in "${TRAFFIC_WORKERS[@]}"; do
    summary="$LOG_DIR/${worker}.summary"
    if [[ ! -r "$summary" ]]; then
      say "${RED}${worker}: missing worker summary${RESET}"
      progress_failed=1
      continue
    fi
    summary_line=$(<"$summary")
    summary_pattern="^${worker} done: iters=([0-9]+) ok=([0-9]+) fail=([0-9]+)$"
    if [[ ! "$summary_line" =~ $summary_pattern ]]; then
      say "${RED}${worker}: malformed worker summary${RESET}"
      progress_failed=1
      continue
    fi
    iters="${BASH_REMATCH[1]}"
    ok="${BASH_REMATCH[2]}"
    failed="${BASH_REMATCH[3]}"
    if (( iters == 0 || ok == 0 || failed != 0 || iters != ok + failed )); then
      say "${RED}${worker}: worker summary has no clean, internally consistent progress${RESET}"
      progress_failed=1
    fi
  done
  (( progress_failed == 0 ))
}

capture_traffic_clock() {
  # Python 3.9 on macOS gives monotonic_ns a per-process origin. Explicitly use
  # the shared kernel clock so separate start/end invocations are comparable.
  python3 -c 'import time; print(time.time_ns() // 1_000_000, time.clock_gettime_ns(time.CLOCK_MONOTONIC))'
}

run_bounded_capture() {
  local output="$1" timeout_seconds="$2"; shift 2
  local pid identity deadline child_rc=0 timed_out=0 tree_text="" tree_pid tree_identity
  local tree_incomplete=0 receipt index
  BOUNDED_CAPTURE_TIMED_OUT=0
  receipt="$(mktemp "$output.drain.XXXXXX")" || {
    CLEANUP_INCOMPLETE=1
    EVIDENCE_FAILED=1
    BOUNDED_CAPTURE_TIMED_OUT=1
    return 125
  }
  # Keep one owned group leader alive until the command AND its group members
  # exit. A wrapper exiting early cannot orphan a pipe holder outside the tree
  # observed at timeout. The leader ignores TERM so group KILL remains bound to
  # its live generation throughout shutdown; the command gets normal signals.
  python3 -c '
import os
import signal
import subprocess
import sys
import time

os.setsid()
signal.signal(signal.SIGTERM, signal.SIG_IGN)
leader = os.getpid()
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    try:
        os.execvp(sys.argv[2], sys.argv[2:])
    except OSError as error:
        print(error, file=sys.stderr)
        os._exit(127)
status = None
while True:
    if status is None:
        exited, observed = os.waitpid(child, os.WNOHANG)
        if exited:
            status = observed
    if status is not None:
        snapshot = subprocess.Popen(
            ["ps", "-axo", "pid=,pgid=,state="],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        output, _ = snapshot.communicate()
        if snapshot.returncode == 0:
            members = [row.split() for row in output.splitlines()]
            if not any(
                len(row) == 3 and row[1] == str(leader)
                and row[0] not in (str(leader), str(snapshot.pid))
                and not row[2].startswith("Z")
                for row in members
            ):
                break
    time.sleep(0.1)
result = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
with open(sys.argv[1], "w") as output:
    output.write(str(child) + "\t" + str(result) + "\n")
sys.exit(result)
' "$receipt" "$@" >"$output" 2>&1 &
  pid="$!"
  AUXILIARY_PIDS+=("$pid")
  AUXILIARY_DRAIN_RECEIPTS[pid]="$receipt"
  identity="$(pid_identity "$pid" generation || true)"
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )) && ! owned_job_has_exited "$pid"; do
    sleep 0.1
  done
  if ! owned_job_has_exited "$pid"; then
    timed_out=1
    # Discovery consumes the existing TERM grace; it must not delay escalation
    # by starting its own unbounded walk before this watchdog begins.
    deadline=$((SECONDS + 1))
    if [[ "$identity" =~ ^[0-9a-f]{64}$ ]] \
      && signal_owned_identity "$pid" "$identity" STOP
    then
      tree_text="$(collect_owned_tree "$pid" "$identity" "$deadline")" || tree_incomplete=1
    elif ! owned_job_has_exited "$pid"; then
      tree_incomplete=1
    fi
    while IFS=$'\t' read -r tree_pid tree_identity; do
      [[ "$tree_pid" =~ ^[1-9][0-9]*$ && "$tree_identity" =~ ^[0-9a-f]{64}$ ]] || continue
      signal_owned_identity "$tree_pid" "$tree_identity" TERM || true
    done <<< "$tree_text"
    while IFS=$'\t' read -r tree_pid tree_identity; do
      [[ "$tree_pid" =~ ^[1-9][0-9]*$ && "$tree_identity" =~ ^[0-9a-f]{64}$ ]] || continue
      signal_owned_identity "$tree_pid" "$tree_identity" CONT || true
    done <<< "$tree_text"
    while (( SECONDS < deadline )); do
      if owned_job_has_exited "$pid" && owned_tree_has_exited "$tree_text"; then break; fi
      sleep 0.1
    done
  fi
  if (( timed_out )); then
    while IFS=$'\t' read -r tree_pid tree_identity; do
      [[ "$tree_pid" =~ ^[1-9][0-9]*$ && "$tree_identity" =~ ^[0-9a-f]{64}$ ]] || continue
      signal_owned_identity "$tree_pid" "$tree_identity" KILL || true
    done <<< "$tree_text"
    deadline=$((SECONDS + 1))
    while (( SECONDS < deadline )); do
      if owned_job_has_exited "$pid" && owned_tree_has_exited "$tree_text"; then break; fi
      sleep 0.1
    done
  fi
  # Reap a direct child even when a descendant could not be stopped. A surviving
  # descendant must still fail capture after the direct job has disappeared.
  if owned_job_has_exited "$pid"; then
    wait "$pid" 2>/dev/null || child_rc=$?
    # Reaping retires all registry entries before any later artifact read or
    # cleanup can mistake the cached integer for a still-owned job.
    for index in "${!AUXILIARY_PIDS[@]}"; do
      [[ "${AUXILIARY_PIDS[index]}" != "$pid" ]] || unset 'AUXILIARY_PIDS[index]'
    done
    unset 'AUXILIARY_DRAIN_RECEIPTS[pid]'
    if [[ -z "$tree_text" ]]; then
      # A supervisor crash cannot certify that its former group has drained.
      # Only the supervisor writes this receipt after observing the command
      # exit and the absence of every other live process in its group.
      capture_drain_receipt_valid "$receipt" "$child_rc" || tree_incomplete=1
    fi
    rm -f -- "$receipt"
  else
    tree_incomplete=1
  fi
  if (( tree_incomplete )) || ! owned_tree_has_exited "$tree_text"; then
    CLEANUP_INCOMPLETE=1
    EVIDENCE_FAILED=1
    BOUNDED_CAPTURE_TIMED_OUT=1
    return 125
  fi
  if (( timed_out )); then
    EVIDENCE_FAILED=1
    BOUNDED_CAPTURE_TIMED_OUT=1
    return 124
  fi
  return "$child_rc"
}

capture_resource_sample() {
  local pid="$1" expected_runtime_identity="$2" generation_identity="$3" label="$4"
  local capture="$RESPONSE_TMP_DIR/resource.${label}.${BASHPID:-$$}"
  local observed_identity row sample_pid rss_kib vsz_kib cpu state epoch_ms
  observed_identity="$(pid_identity "$pid" || true)"
  [[ "$observed_identity" == "$expected_runtime_identity" \
    && "$generation_identity" =~ ^[0-9a-f]{64}$ ]] || return 1
  if ! run_bounded_capture "$capture" 3 \
    ps -o pid=,rss=,vsz=,%cpu=,state= -p "$pid"
  then
    rm -f -- "$capture"
    return 1
  fi
  row="$(<"$capture")"
  rm -f -- "$capture"
  read -r sample_pid rss_kib vsz_kib cpu state extra <<< "$row"
  [[ -z "${extra:-}" && "$sample_pid" == "$pid" \
    && "$rss_kib" =~ ^(0|[1-9][0-9]*)$ \
    && "$vsz_kib" =~ ^(0|[1-9][0-9]*)$ \
    && "$cpu" =~ ^[0-9]+([.][0-9]+)?$ \
    && "$state" =~ ^[^[:space:]]+$ ]] || return 1
  observed_identity="$(pid_identity "$pid" || true)"
  [[ "$observed_identity" == "$expected_runtime_identity" ]] || return 1
  epoch_ms="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  printf 'resource_sample\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$epoch_ms" "$generation_identity" "$sample_pid" "$rss_kib" \
    "$vsz_kib" "$cpu" "$state"
}

# One-shot snapshot of a target pid: rss/vsz, vmmap summary, heap totals.
snapshot_pid() {
  local pid="$1" label="$2" expected_identity="${3:-}" generation_identity="${4:-}"
  local observed_identity
  local out="$LOG_DIR/${label}.txt"
  local capture="$RESPONSE_TMP_DIR/snapshot.${label}.$$"
  if [[ -n "$expected_identity" ]]; then
    observed_identity="$(pid_identity "$pid" || true)"
    [[ "$observed_identity" == "$expected_identity" ]] || return 1
  fi
  {
    printf '=== %s @ %s ===\n' "$label" "$(date -u +%FT%TZ)"
    if [[ "$label" != preflight ]]; then
      capture_resource_sample "$pid" "$expected_identity" "$generation_identity" "$label" \
        || { echo "pid $pid gone or snapshot timed out"; return 1; }
    fi
    printf '\n--- vmmap --summary ---\n'
    if run_bounded_capture "$capture" 10 sudo -n vmmap --summary "$pid"; then
      cat "$capture"
    elif (( BOUNDED_CAPTURE_TIMED_OUT )); then
      echo "vmmap timed out"
      rm -f -- "$capture"
      return 1
    elif run_bounded_capture "$capture" 10 vmmap --summary "$pid"; then
      cat "$capture"
    else
      (( BOUNDED_CAPTURE_TIMED_OUT == 0 )) || { echo "vmmap timed out"; rm -f -- "$capture"; return 1; }
      echo "vmmap unavailable (need sudo; cache with 'sudo -v' before the run)"
    fi
    printf '\n--- heap totals ---\n'
    if run_bounded_capture "$capture" 10 sudo -n heap "$pid"; then
      grep -E 'All zones:|Total|Process [0-9]+:' "$capture" \
        || echo "heap returned no totals"
    elif (( BOUNDED_CAPTURE_TIMED_OUT )); then
      echo "heap timed out"
      rm -f -- "$capture"
      return 1
    elif run_bounded_capture "$capture" 10 heap "$pid"; then
      grep -E 'All zones:|Total|Process [0-9]+:' "$capture" \
        || echo "heap returned no totals"
    else
      (( BOUNDED_CAPTURE_TIMED_OUT == 0 )) || { echo "heap timed out"; rm -f -- "$capture"; return 1; }
      echo "heap unavailable (need sudo; cache with 'sudo -v' before the run)"
    fi
    rm -f -- "$capture"
    if [[ "$label" == preflight ]]; then
      capture_resource_sample "$pid" "$expected_identity" "$generation_identity" "$label" \
        || { echo "pid $pid gone or snapshot timed out"; return 1; }
    fi
    printf '\n'
  } >"$out"
  if [[ -n "$expected_identity" ]]; then
    observed_identity="$(pid_identity "$pid" || true)"
    [[ "$observed_identity" == "$expected_identity" ]] || return 1
  fi
}

# Pre-flight liveness probe.
liveness_probe() {
  local pid="$1"
  if [[ -n "$pid" ]] && ! ps -p "$pid" >/dev/null 2>&1; then
    say "${RED}liveness: pid $pid not running — sysext is gone${RESET}"
    return 1
  fi
  local code curl_rc=0
  code=$(run_hermetic_curl --silent --show-error --output /dev/null --max-time 10 \
      --write-out '%{http_code}' \
      --url "$HTTPS_TARGET" 2>/dev/null) || curl_rc=$?
  [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
  if (( curl_rc == 0 )) && [[ "$code" =~ ^2 ]]; then
    say "${GREEN}liveness: probe got $code (target reachable; interception is not attributed)${RESET}"
    return 0
  fi
  say "${RED}liveness: configured HTTPS probe got '$code' curl_exit=$curl_rc${RESET}"
  say "  proxy may not be intercepting, sysext may be down, or upstream is rate-limiting"
  say "  set STRESS_SKIP_LIVENESS=1 to run anyway"
  return 1
}

# Optional sampling of a target pid every 5s.
monitor_pid() {
  local pid="$1" expected_identity="$2" generation_identity="$3" observed_identity
  local out="$LOG_DIR/monitor.$pid.log"
  : >"$out"
  while [[ ! -e "$MONITOR_STOP_FILE" ]]; do
    observed_identity="$(pid_identity "$pid" || true)"
    if [[ "$observed_identity" != "$expected_identity" ]]; then
      printf '\n=== %s ===\nprovider identity changed or disappeared\n' \
        "$(date -u +%FT%TZ)" >> "$out"
      return 42
    fi
    capture_resource_sample "$pid" "$expected_identity" "$generation_identity" monitor \
      >>"$out" || return 43
    sleep 5
  done
  observed_identity="$(pid_identity "$pid" || true)"
  [[ "$observed_identity" == "$expected_identity" ]]
}

# ── Plan + launch ────────────────────────────────────────────────────

hdr "rama transparent proxy stress test"
say "duration:    ${DURATION}s"
say "concurrency: $CONCURRENCY"
say "log dir:     $LOG_DIR"
[[ -n "$MONITOR_PID" ]] && say "monitor pid: $MONITOR_PID"
(( ANALYZE_ONLY )) && say "analysis:    artifact-only (no workers)"
say "evidence:    $EVIDENCE_MODE"

POST_FILE="$LOG_DIR/post.body"
if (( ! ANALYZE_ONLY )); then
  dd if=/dev/zero of="$POST_FILE" bs=1048576 \
    count=$((POST_BYTES / 1048576)) 2>/dev/null
  POST_REMAINDER=$((POST_BYTES % 1048576))
  if (( POST_REMAINDER > 0 )); then
    dd if=/dev/zero bs="$POST_REMAINDER" count=1 \
      >> "$POST_FILE" 2>/dev/null
  fi
  mkdir -p "$RESPONSE_TMP_DIR"
  say "post body:   $(du -h "$POST_FILE" | cut -f1)"
fi

if (( ! ANALYZE_ONLY )); then
  if [[ "$SKIP_LIVENESS" == 0 ]]; then
    if ! liveness_probe "$MONITOR_PID"; then
      exit 1
    fi
  fi

  if [[ -n "$MONITOR_PID" ]]; then
    MONITOR_RUNTIME_IDENTITY="$(pid_identity "$MONITOR_PID" || true)"
    if [[ ! "$MONITOR_RUNTIME_IDENTITY" =~ ^[0-9a-f]{64}$ ]]; then
      say "${RED}monitor: pid $MONITOR_PID has no stable process identity${RESET}"
      exit 1
    fi
    if [[ "$TRAFFIC_ROLE" == proxy-candidate ]]; then
      "$COMMON_EVIDENCE_HELPER" capture-provider \
        --built-provider "$BUILT_PROVIDER" \
        --installed-provider "$INSTALLED_PROVIDER" \
        --pid "$MONITOR_PID" \
        --output "$LOG_DIR/provider-identity.tsv" \
        --source-root "$REPO_ROOT" >/dev/null || {
          say "${RED}monitor: signed provider identity capture failed${RESET}"
          exit 2
        }
      provider_identity_value() {
        awk -F '\t' -v key="$1" '$1 == key { print $2 }' \
          "$LOG_DIR/provider-identity.tsv"
      }
      PROVIDER_BUILD_IDENTITY="$(provider_identity_value provider_build_identity)"
      PROVIDER_GENERATION_IDENTITY="$(provider_identity_value provider_generation_identity)"
      MONITOR_IDENTITY="$PROVIDER_GENERATION_IDENTITY"
      PROVIDER_EXECUTABLE="$(provider_identity_value running_executable_path)"
      PROVIDER_EXECUTABLE_SHA256="$(provider_identity_value running_executable_sha256)"
      PROVIDER_SIGNING_IDENTIFIER="$(provider_identity_value running_bundle_id)"
      PROVIDER_SIGNING_TEAM="$(provider_identity_value running_team_id)"
      PROVIDER_SIGNING_CDHASH="$(provider_identity_value running_cdhash)"
      [[ "$PROVIDER_SIGNING_IDENTIFIER" == "$EXPECTED_PROVIDER_SUBSYSTEM" ]] || {
        say "${RED}monitor: provider subsystem is not the exact development identifier${RESET}"
        exit 2
      }
      {
        printf 'Identifier=%s\nTeamIdentifier=%s\nCDHash=%s\n' \
          "$PROVIDER_SIGNING_IDENTIFIER" "$PROVIDER_SIGNING_TEAM" \
          "$PROVIDER_SIGNING_CDHASH"
      } > "$LOG_DIR/provider-codesign.txt"
      GENERATION_RESULT="$(
        "$COMMON_EVIDENCE_HELPER" capture-provider-generation \
          --identity "$LOG_DIR/provider-identity.tsv" \
          --cadence-ms 2000 --max-gap-ms 5000 \
          --output "$LOG_DIR/provider-generation-samples.tsv"
      )" || {
        say "${RED}monitor: provider generation sampling could not start${RESET}"
        exit 2
      }
      RUN_START_EPOCH="$(printf '%s\n' "$GENERATION_RESULT" | awk -F '\t' '$1 == "epoch_ms" {print $2}')"
      [[ "$RUN_START_EPOCH" =~ ^[1-9][0-9]*$ ]] || {
        say "${RED}monitor: provider generation sampler returned no epoch${RESET}"
        exit 2
      }
      monitor_provider_generation &
      GENERATION_MONITOR_JOB_PID="$!"
    else
      MONITOR_IDENTITY="$MONITOR_RUNTIME_IDENTITY"
      PROVIDER_EXECUTABLE="$(ps -ww -o comm= -p "$MONITOR_PID" 2>/dev/null | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      [[ -f "$PROVIDER_EXECUTABLE" ]] || exit 1
      PROVIDER_EXECUTABLE_SHA256="$(shasum -a 256 "$PROVIDER_EXECUTABLE" | awk '{print $1}')"
      codesign -dvvv "$PROVIDER_EXECUTABLE" > "$LOG_DIR/provider-codesign.txt" 2>&1 || exit 1
      PROVIDER_SIGNING_IDENTIFIER="$(sed -n 's/^Identifier=//p' "$LOG_DIR/provider-codesign.txt" | head -1)"
      PROVIDER_SIGNING_TEAM="$(sed -n 's/^TeamIdentifier=//p' "$LOG_DIR/provider-codesign.txt" | head -1)"
      PROVIDER_SIGNING_CDHASH="$(sed -n 's/^CDHash=//p' "$LOG_DIR/provider-codesign.txt" | head -1)"
      # The verifier consumes the same exact three-field proof in both modes.
      # codesign's verbose prose also includes paths and platform detail.
      {
        printf 'Identifier=%s\nTeamIdentifier=%s\nCDHash=%s\n' \
          "$PROVIDER_SIGNING_IDENTIFIER" "$PROVIDER_SIGNING_TEAM" \
          "$PROVIDER_SIGNING_CDHASH"
      } > "$LOG_DIR/provider-codesign.txt"
      {
        printf 'pid\t%s\nidentity\t%s\nexecutable\t%s\n' \
          "$MONITOR_PID" "$MONITOR_IDENTITY" "$PROVIDER_EXECUTABLE"
        printf 'executable_sha256\t%s\nsigning_identifier\t%s\n' \
          "$PROVIDER_EXECUTABLE_SHA256" "$PROVIDER_SIGNING_IDENTIFIER"
        printf 'signing_team\t%s\nsigning_cdhash\t%s\n' \
          "$PROVIDER_SIGNING_TEAM" "$PROVIDER_SIGNING_CDHASH"
      } > "$LOG_DIR/provider-identity.tsv"
    fi
    printf '%s\n' "$MONITOR_IDENTITY" > "$LOG_DIR/monitor.identity.sha256"
    if snapshot_pid "$MONITOR_PID" preflight "$MONITOR_RUNTIME_IDENTITY" "$MONITOR_IDENTITY"; then
      say "preflight:   $LOG_DIR/preflight.txt"
    else
      say "${RED}preflight: monitored provider identity changed or disappeared${RESET}"
      exit 1
    fi
    NDJSON_PATH="$LOG_DIR/system.ndjson"
    SYSTEM_LOG_TOOL_SHA256="$(shasum -a 256 "$LOG_TOOL" | awk '{print $1}')"
    printf 'path\t%s\nsha256\t%s\n' "$LOG_TOOL" "$SYSTEM_LOG_TOOL_SHA256" \
      > "$LOG_DIR/system-log-tool.tsv"
    LOG_PREDICATE="processID == $MONITOR_PID AND subsystem == '$EXPECTED_PROVIDER_SUBSYSTEM'"
    if [[ "$TRAFFIC_ROLE" == proxy-candidate ]]; then
      LOG_PREDICATE="$LOG_PREDICATE AND eventMessage BEGINSWITH '$EXPECTED_STRESS_EVENT_PREFIX'"
    fi
    "$LOG_TOOL" stream --level debug --style ndjson \
      --predicate "$LOG_PREDICATE" \
      > "$NDJSON_PATH" 2> "$LOG_DIR/system-log-capture.err" &
    SYSTEM_LOG_JOB_PID="$!"
    SYSTEM_LOG_JOB_IDENTITY="$(pid_identity "$SYSTEM_LOG_JOB_PID" generation || true)"
    sleep 0.5
    if [[ "$SYSTEM_LOG_JOB_IDENTITY" =~ ^[0-9a-f]{64}$ ]] \
      && [[ "$(pid_identity "$SYSTEM_LOG_JOB_PID" generation || true)" == "$SYSTEM_LOG_JOB_IDENTITY" ]]
    then
      SYSTEM_LOG_STARTED=1
    else
      say "${RED}monitor: provider system log capture did not stay alive${RESET}"
      exit 2
    fi
  fi

  START_TS=$(date -u +%s)
  read -r TRAFFIC_START_EPOCH TRAFFIC_START_MONOTONIC_NS <<< \
    "$(capture_traffic_clock)"

  for worker_name in "${TRAFFIC_WORKERS[@]}"; do
    : > "$LOG_DIR/${worker_name}.log"
    : > "$LOG_DIR/${worker_name}.summary"
  done

  TRAFFIC_PIDS=()
  loop_http small_https "$HTTPS_TARGET" --http2 & TRAFFIC_PIDS+=("$!")
  loop_http small_http1 "$HTTPS_TARGET" --http1.1 & TRAFFIC_PIDS+=("$!")
  loop_http plain_http "$HTTP_TARGET" --http1.1 & TRAFFIC_PIDS+=("$!")
  loop_http large_get "$LARGE_TARGET" --http2 \
    --header 'Accept-Encoding: identity' & TRAFFIC_PIDS+=("$!")
  loop_http post_large "$POST_TARGET" --http2 --data-binary "@$POST_FILE" & TRAFFIC_PIDS+=("$!")
  loop_http head_only "$HTTPS_TARGET" --http2 --head & TRAFFIC_PIDS+=("$!")
  loop_http churn_close "$HTTPS_TARGET" --http1.1 --header 'Connection: close' & TRAFFIC_PIDS+=("$!")
  loop_pool parallel_pool "$HTTPS_TARGET" --http2 & TRAFFIC_PIDS+=("$!")

  MONITOR_JOB_PID=""
  if [[ -n "$MONITOR_PID" ]]; then
    monitor_pid "$MONITOR_PID" "$MONITOR_RUNTIME_IDENTITY" "$MONITOR_IDENTITY" &
    MONITOR_JOB_PID="$!"
  fi
  say "workers up:  ${#TRAFFIC_PIDS[@]}"

  while kill -0 "${TRAFFIC_PIDS[0]}" 2>/dev/null; do
    ELAPSED=$(( $(date -u +%s) - START_TS ))
    if (( ELAPSED > DURATION )); then break; fi
    printf '\r[stress] %ds elapsed' "$ELAPSED"
    sleep 1
  done
  printf '\n'

  TRAFFIC_FAILED=0
  for worker_pid in "${TRAFFIC_PIDS[@]}"; do
    wait "$worker_pid" || TRAFFIC_FAILED=1
  done
  read -r TRAFFIC_END_EPOCH TRAFFIC_END_MONOTONIC_NS <<< \
    "$(capture_traffic_clock)"
  {
    printf 'traffic_start_epoch_ms\t%s\ntraffic_end_epoch_ms\t%s\n' \
      "$TRAFFIC_START_EPOCH" "$TRAFFIC_END_EPOCH"
    printf 'traffic_start_monotonic_ns\t%s\ntraffic_end_monotonic_ns\t%s\n' \
      "$TRAFFIC_START_MONOTONIC_NS" "$TRAFFIC_END_MONOTONIC_NS"
    printf 'schema_complete\t1\n'
  } > "$LOG_DIR/stress-window.tsv"
  if [[ "$TRAFFIC_ROLE" != direct-baseline ]]; then
    : > "$MONITOR_STOP_FILE"
  fi
  if [[ -n "$MONITOR_JOB_PID" ]]; then
    if ! wait_proven_exited "$MONITOR_JOB_PID" 7; then
      say "${RED}monitored provider died or changed identity during traffic${RESET}"
      TRAFFIC_FAILED=1
      cleanup_owned_jobs
    fi
    MONITOR_JOB_PID=""
  fi
  if [[ -n "$SYSTEM_LOG_JOB_PID" ]]; then
    # Generation sampling must continue through postflight memory and crash
    # collection, then exit cooperatively after its final boundary sample.
    cleanup_owned_jobs system-log
    if [[ "$SYSTEM_LOG_ALIVE_END" != 1 || "$SYSTEM_LOG_JOINED" != 1 \
      || ( "$SYSTEM_LOG_CHILD_RC" != 0 && "$SYSTEM_LOG_CHILD_RC" != 143 ) ]]
    then
      say "${RED}provider system log capture failed or required a forced stop${RESET}"
      EVIDENCE_FAILED=1
    fi
  fi
  if (( CLEANUP_INCOMPLETE )); then
    say "${RED}one or more owned jobs could not be proven exited and reaped${RESET}"
    EVIDENCE_FAILED=1
  fi
  verify_worker_progress || TRAFFIC_FAILED=1
else
  if (( ! ANALYSIS_SOURCE_STATUS_OK )); then
    say "${RED}analysis: source stress-status.tsv is missing, invalid, or not a successful traffic run${RESET}"
    ANALYSIS_FAILED=1
  fi
  verify_worker_progress || ANALYSIS_FAILED=1
  for worker_name in "${TRAFFIC_WORKERS[@]}"; do
    if [[ ! -s "$LOG_DIR/${worker_name}.log" ]]; then
      say "${RED}analysis: ${worker_name}.log is missing or empty${RESET}"
      ANALYSIS_FAILED=1
    fi
  done
fi

# ── Summary ──────────────────────────────────────────────────────────

hdr "summary"
for f in "$LOG_DIR"/*.summary; do
  [[ -f "$f" ]] || continue
  cat "$f"
done
if [[ -f "$LOG_DIR/large_get.summary" ]] \
  && grep -qE 'ok=0 fail=[1-9][0-9]*' "$LOG_DIR/large_get.summary"
then
  say "note: large_get did not record a successful response; override STRESS_LARGE_TARGET if you need this worker to exercise large-response backpressure"
fi

if compgen -G "$LOG_DIR/*.log" >/dev/null; then
  hdr "errors per worker (top 5)"
  err_re='^(000|[45][0-9]{2})( |$)|curl_exit=[1-9][0-9]*|^curl: \([0-9]+\) '
  for f in "$LOG_DIR"/*.log; do
    name=$(basename "$f" .log)
    err_count=$(grep -cE "$err_re" "$f" 2>/dev/null)
    err_count=${err_count:-0}
    if (( err_count > 0 )); then
      printf '%s: %d non-2xx / curl errors\n' "$name" "$err_count"
      grep -E "$err_re" "$f" | head -5 | sed 's/^/  /'
    fi
  done
fi

# Truncation detector for partial-body curl failures.
if compgen -G "$LOG_DIR/*.log" >/dev/null; then
  hdr "partial-body events (truncation symptom)"
  trunc_re='[0-9]+ out of [0-9]+ bytes (received|sent)'
  trunc_total=0
  for f in "$LOG_DIR"/*.log; do
    name=$(basename "$f" .log)
    n=$(grep -cE "$trunc_re" "$f" 2>/dev/null)
    n=${n:-0}
    if (( n > 0 )); then
      printf '%s: %d partial-body lines\n' "$name" "$n"
      grep -oE "$trunc_re" "$f" | head -3 | sed 's/^/  /'
      trunc_total=$((trunc_total + n))
    fi
  done
  if (( trunc_total == 0 )); then
    printf '%snone%s — no partial-body events recorded across all workers\n' "$GREEN" "$RESET"
  else
    printf '%stotal:%s %d partial-body events across all workers\n' "$RED" "$RESET" "$trunc_total"
  fi
fi

# Post-flight memory snapshot.
if [[ -n "$MONITOR_PID" && $ANALYZE_ONLY -eq 0 ]]; then
  if snapshot_pid "$MONITOR_PID" postflight "$MONITOR_RUNTIME_IDENTITY" "$MONITOR_IDENTITY"; then
    hdr "memory snapshot"
    say "preflight  → $LOG_DIR/preflight.txt"
    say "postflight → $LOG_DIR/postflight.txt"
    say "diff       → diff $LOG_DIR/preflight.txt $LOG_DIR/postflight.txt"
  else
    say "${RED}postflight: monitored provider identity changed or disappeared${RESET}"
    TRAFFIC_FAILED=1
  fi
  if [[ -s "$LOG_DIR/system.ndjson" ]]; then
    NDJSON_INCLUDED=1
    NDJSON_PATH="$LOG_DIR/system.ndjson"
  else
    say "${RED}system log capture could not be included in the evidence${RESET}"
    EVIDENCE_FAILED=1
  fi
fi

if (( ! ANALYZE_ONLY )); then
  if [[ "$TRAFFIC_ROLE" == direct-baseline ]]; then
    : > "$MONITOR_STOP_FILE"
    if [[ -n "$ABSENCE_MONITOR_JOB_PID" ]]; then
      if ! wait_proven_exited "$ABSENCE_MONITOR_JOB_PID" 4; then
        say "${RED}development-provider absence changed during the direct run${RESET}"
        EVIDENCE_FAILED=1
        cleanup_owned_jobs
      fi
      ABSENCE_MONITOR_JOB_PID=""
    fi
    ABSENCE_RESULT="$(
      "$COMMON_EVIDENCE_HELPER" capture-provider-absence \
        --append "$LOG_DIR/provider-absence.tsv"
    )" || EVIDENCE_FAILED=1
    RUN_END_EPOCH="$(printf '%s\n' "$ABSENCE_RESULT" | awk -F '\t' '$1 == "epoch_ms" {print $2}')"
    if [[ ! "$RUN_END_EPOCH" =~ ^[1-9][0-9]*$ ]]; then
      RUN_END_EPOCH="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
      EVIDENCE_FAILED=1
    fi
  else
    RUN_END_EPOCH="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  fi
  if [[ "$TRAFFIC_ROLE" == direct-baseline || "$TRAFFIC_ROLE" == proxy-candidate ]]; then
    if ! "$COMMON_EVIDENCE_HELPER" snapshot-crashes \
      --since-epoch-ms "$RUN_START_EPOCH" --output-dir "$LOG_DIR/crashes" \
      --process "$CRASH_PROCESS" --process "$EXPECTED_PROVIDER_SUBSYSTEM" \
      --run-uuid "$RUN_UUID" \
      --provider-generation-identity "$PROVIDER_GENERATION_IDENTITY" \
      > "$LOG_DIR/crashes.stdout" 2> "$LOG_DIR/crashes.stderr"
    then
      say "${RED}provider crash snapshot could not be captured${RESET}"
      EVIDENCE_FAILED=1
    fi
  fi
  if [[ "$TRAFFIC_ROLE" == proxy-candidate ]]; then
    "$COMMON_EVIDENCE_HELPER" capture-provider-generation \
      --identity "$LOG_DIR/provider-identity.tsv" \
      --append "$LOG_DIR/provider-generation-samples.tsv" >/dev/null \
      || EVIDENCE_FAILED=1
    : > "$GENERATION_STOP_FILE"
    if [[ -n "$GENERATION_MONITOR_JOB_PID" ]]; then
      if ! wait_proven_exited "$GENERATION_MONITOR_JOB_PID" 4; then
        say "${RED}provider generation sampler did not exit cleanly${RESET}"
        EVIDENCE_FAILED=1
        cleanup_owned_jobs
      fi
      GENERATION_MONITOR_JOB_PID=""
    fi
  fi
  if (( EVIDENCE_FAILED )); then
    say "${RED}stress evidence capture or cleanup was incomplete${RESET}"
    write_terminal_status 0 0 2 "stress evidence capture or cleanup was incomplete"
    exit "$TERMINAL_EXIT_CODE"
  fi
  if (( TRAFFIC_FAILED )); then
    say "${RED}one or more traffic workers observed request failures${RESET}"
    write_terminal_status 1 0 1
    exit "$TERMINAL_EXIT_CODE"
  fi
  METRIC_RESULT="$(
    "$EVIDENCE_HELPER" metrics "$LOG_DIR" "$TRAFFIC_START_EPOCH" \
      "$TRAFFIC_END_EPOCH" "$MAX_P95_MS" "$MIN_THROUGHPUT_MILLI_RPS" \
      "$MAX_RSS_GROWTH_BYTES" "$MAX_CPU_PERCENT" "$EVIDENCE_MODE" \
      "${MONITOR_PID:-none}" "${MONITOR_IDENTITY:-none}"
  )" || {
    say "${RED}stress performance evidence is incomplete or malformed${RESET}"
    write_terminal_status 0 0 2 "stress performance evidence could not be measured"
    exit "$TERMINAL_EXIT_CODE"
  }
  IFS=$'\t' read -r METRIC_STATUS SUCCESSFUL_REQUESTS OBSERVED_P95_MS \
    METRIC_MAX_P95 OBSERVED_THROUGHPUT_MILLI_RPS METRIC_MIN_THROUGHPUT \
    OBSERVED_RSS_GROWTH_BYTES METRIC_MAX_RSS OBSERVED_MAX_CPU_PERCENT \
    METRIC_MAX_CPU <<< "$METRIC_RESULT"
  if [[ "$METRIC_MAX_P95" != "$MAX_P95_MS" \
    || "$METRIC_MIN_THROUGHPUT" != "$MIN_THROUGHPUT_MILLI_RPS" \
    || "$METRIC_MAX_RSS" != "$MAX_RSS_GROWTH_BYTES" \
    || "$METRIC_MAX_CPU" != "$MAX_CPU_PERCENT" \
    || ! "$SUCCESSFUL_REQUESTS" =~ ^[1-9][0-9]*$ \
    || ( "$METRIC_STATUS" != PASSED && "$METRIC_STATUS" != FAILED ) ]]
  then
    say "${RED}stress performance helper returned an invalid result${RESET}"
    write_terminal_status 0 0 2 "stress performance helper returned an invalid result"
    exit "$TERMINAL_EXIT_CODE"
  fi
  say "performance: p95=${OBSERVED_P95_MS}ms throughput=${OBSERVED_THROUGHPUT_MILLI_RPS} milli-rps"
  if [[ "$EVIDENCE_MODE" == provider-monitored-traffic-only ]]; then
    say "provider:    rss-growth=${OBSERVED_RSS_GROWTH_BYTES}B max-cpu=${OBSERVED_MAX_CPU_PERCENT}%"
  fi
  [[ "$METRIC_STATUS" == PASSED ]] || TRAFFIC_FAILED=1
  if [[ "$TRAFFIC_ROLE" == proxy-candidate ]]; then
    if [[ "$EVIDENCE_MODE" != provider-monitored-traffic-only ]]; then
      say "${RED}proxy candidate has no provider monitor for request attribution${RESET}"
      EVIDENCE_FAILED=1
    else
      ATTRIBUTED_REQUEST_COUNT="$(
        "$EVIDENCE_HELPER" attribution "$LOG_DIR" "$MONITOR_PID" \
          "$PROVIDER_SIGNING_IDENTIFIER" "$RUN_UUID" "$RUN_START_EPOCH" \
          "$RUN_END_EPOCH" "$TRAFFIC_START_EPOCH" "$TRAFFIC_END_EPOCH"
      )" || {
        say "${RED}provider request attribution evidence is invalid${RESET}"
        ATTRIBUTED_REQUEST_COUNT=0
        EVIDENCE_FAILED=1
      }
      if [[ "$ATTRIBUTED_REQUEST_COUNT" != "$SUCCESSFUL_REQUESTS" ]]; then
        say "${RED}provider request marker count does not match successful traffic${RESET}"
        EVIDENCE_FAILED=1
      else
        PROXY_ATTRIBUTED=1
      fi
    fi
  fi
fi

# Attribution is measured after the generic performance metrics, so preserve
# the evidence/product distinction for failures discovered in that last step.
if (( ! ANALYZE_ONLY && EVIDENCE_FAILED )); then
  say "${RED}stress request attribution evidence is incomplete${RESET}"
  write_terminal_status 0 0 2 "stress request attribution evidence is incomplete"
  exit "$TERMINAL_EXIT_CODE"
fi

# Close-reason histogram from a captured system log.
if [[ -n "$NDJSON_PATH" ]]; then
  hdr "close-reason histogram (from $NDJSON_PATH)"
  if [[ ! -r "$NDJSON_PATH" ]]; then
    say "${RED}cannot read $NDJSON_PATH${RESET}"
    (( ANALYZE_ONLY )) && ANALYSIS_FAILED=1
  else
    awk -v pid="${MONITOR_PID:-}" '
      /transparent proxy (tcp|udp) flow closed/ {
        if (pid != "" && index($0, "\"processID\":" pid) == 0) {
          next
        }
        if (match($0, /reason=[^" ,}]+/)) {
          r = substr($0, RSTART, RLENGTH)
          sub(/^reason=/, "", r)
          counts[r]++
          total++
        }
      }
      END {
        if (total == 0) {
          print "  no close events found in capture"
          exit
        }
        for (r in counts) {
          printf "  %-20s %6d  %5.1f%%\n", r, counts[r], 100.0 * counts[r] / total
        }
        printf "  %-20s %6d  100.0%%\n", "TOTAL", total
      }
    ' "$NDJSON_PATH" | sort
  fi
else
  hdr "close-reason histogram"
  say "  set STRESS_NDJSON=<path> to enable. Capture with:"
  say "    sudo log show --predicate 'subsystem == \"org.ramaproxy.example.tproxy\"' \\"
  say "      --start \"\$(date -u -v-10M '+%Y-%m-%d %H:%M:%S')\" --style ndjson \\"
  say "      > /tmp/system.ndjson"
fi

hdr "logs at $LOG_DIR"
say "done"
if (( ! ANALYZE_ONLY )); then
  ARTIFACT_MANIFEST_SHA256="$(
    "$EVIDENCE_HELPER" seal "$LOG_DIR" "$RUN_UUID" \
      "$RUN_START_EPOCH" "$RUN_END_EPOCH" "$EVIDENCE_MODE" \
      "${MONITOR_PID:-none}" "$TRAFFIC_ROLE" "$WORKLOAD_IDENTITY"
  )" || {
    say "${RED}could not seal the stress worker artifacts${RESET}"
    ARTIFACT_MANIFEST_SHA256=none
    write_terminal_status 0 0 2 "stress worker artifacts could not be sealed"
    exit "$TERMINAL_EXIT_CODE"
  }
fi
if (( ANALYZE_ONLY && ANALYSIS_FAILED )); then
  say "${RED}artifact analysis is incomplete or invalid${RESET}"
  write_terminal_status 0 0 2 "artifact analysis requires a successful source status and complete worker artifacts"
  exit "$TERMINAL_EXIT_CODE"
fi
if (( ! ANALYZE_ONLY && TRAFFIC_FAILED )); then
  say "${RED}one or more explicit stress performance thresholds failed${RESET}"
  write_terminal_status 1 0 1
  exit "$TERMINAL_EXIT_CODE"
fi
write_terminal_status 1 1 0
exit "$TERMINAL_EXIT_CODE"
