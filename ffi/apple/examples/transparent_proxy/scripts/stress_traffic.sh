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
#   STRESS_MONITOR_PID    if set, periodically `leaks` / `vmmap` the pid.
#                         Also enables before/after `vmmap`+`heap`
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
#
# Evidence scope is explicit: without STRESS_MONITOR_PID this is traffic-only.
# With a pid it additionally proves that one stable provider process stayed
# alive, but individual HTTP requests are still not attributed to proxy flows.
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
LOG_TOOL="${STRESS_LOG_TOOL:-/usr/bin/log}"

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
WORKLOAD_IDENTITY="$(python3 -c '
import hashlib, json, sys
print(hashlib.sha256(json.dumps(sys.argv[1:], separators=(",", ":")).encode()).hexdigest())
' "$DURATION" "$CONCURRENCY" "$LARGE_BYTES" "$POST_BYTES" \
  "$HTTP_TARGET" "$HTTPS_TARGET" "$LARGE_TARGET" "$POST_TARGET")"
[[ "$WORKLOAD_IDENTITY" =~ ^[0-9a-f]{64}$ ]] || {
  printf '[stress] could not derive the workload identity\n' >&2
  exit 2
}

LOG_DIR="${STRESS_LOG_DIR:-$(mktemp -d /tmp/rama-stress.XXXXXX)}"
mkdir -p "$LOG_DIR"
EVIDENCE_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stress_evidence.py"
RUN_UUID=none
RUN_START_EPOCH=0
RUN_END_EPOCH=0
TRAFFIC_START_EPOCH=0
TRAFFIC_END_EPOCH=0
ARTIFACT_MANIFEST_SHA256=none
OBSERVED_P95_MS=0
OBSERVED_THROUGHPUT_MILLI_RPS=0
OBSERVED_RSS_GROWTH_BYTES=not_applicable
OBSERVED_MAX_CPU_PERCENT=not_applicable
GIT_HEAD=none
GIT_DIRTY=none
STRESS_SCRIPT_SHA256=none
EVIDENCE_HELPER_SHA256=none
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

ANALYZE_ONLY=0
TRAFFIC_FAILED=0
ANALYSIS_FAILED=0
if [[ "$DURATION" == 0 ]]; then
  ANALYZE_ONLY=1
fi

EVIDENCE_MODE=traffic-only
[[ -n "$MONITOR_PID" ]] && EVIDENCE_MODE=provider-monitored-traffic-only
(( ANALYZE_ONLY )) && EVIDENCE_MODE=artifact-analysis-only
STATUS_PATH="$LOG_DIR/stress-status.tsv"
(( ANALYZE_ONLY )) && STATUS_PATH="$LOG_DIR/stress-analysis-status.tsv"
if (( ! ANALYZE_ONLY )) && [[ -n "$(find "$LOG_DIR" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  printf '[stress] STRESS_LOG_DIR must be empty for a new source run\n' >&2
  exit 2
fi
TRAFFIC_PIDS=()
MONITOR_JOB_PID=""
SYSTEM_LOG_JOB_PID=""
MONITOR_STOP_FILE="$LOG_DIR/.monitor.stop"
CLEANUP_STARTED=0
rm -f -- "$MONITOR_STOP_FILE"

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
  RUN_START_EPOCH="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
fi

write_stress_status() {
  local complete="$1" passed="$2" exit_code="$3" issue="${4:-}"
  local tmp="$STATUS_PATH.tmp.$$"
  {
    printf 'complete\t%s\npassed\t%s\nexit_code\t%s\n' \
      "$complete" "$passed" "$exit_code"
    printf 'evidence_mode\t%s\nproxy_attributed\t0\n' "$EVIDENCE_MODE"
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
    [[ -z "$issue" ]] || printf 'issue\t%s\n' "$issue"
    printf 'schema_complete\t1\n'
  } > "$tmp"
  mv "$tmp" "$STATUS_PATH"
}

write_stress_status 0 0 2 "stress run did not reach its terminal verdict"

if (( ! ANALYZE_ONLY )); then
  REPO_ROOT="$(git -C "$(dirname "$EVIDENCE_HELPER")" rev-parse --show-toplevel 2>/dev/null || true)"
  [[ -n "$REPO_ROOT" ]] || {
    write_stress_status 0 0 2 "could not resolve source repository identity"
    exit 2
  }
  cp "$0" "$LOG_DIR/source-stress_traffic.sh"
  cp "$EVIDENCE_HELPER" "$LOG_DIR/source-stress_evidence.py"
  GIT_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)"
  git -C "$REPO_ROOT" status --porcelain --untracked-files=normal \
    > "$LOG_DIR/git-status.txt"
  printf '%s\n' "$GIT_HEAD" > "$LOG_DIR/git-head.txt"
  [[ -s "$LOG_DIR/git-status.txt" ]] && GIT_DIRTY=1 || GIT_DIRTY=0
  STRESS_SCRIPT_SHA256="$(shasum -a 256 "$LOG_DIR/source-stress_traffic.sh" | awk '{print $1}')"
  EVIDENCE_HELPER_SHA256="$(shasum -a 256 "$LOG_DIR/source-stress_evidence.py" | awk '{print $1}')"
fi

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

# Fingerprint pid + kernel start time + complete command. A reused pid cannot
# silently retain cleanup authority merely because the replacement is alive.
pid_identity() {
  local pid="$1" snapshot digest
  snapshot="$(ps -ww -o pid= -o lstart= -o command= -p "$pid" 2>/dev/null)"
  [[ -n "$snapshot" ]] || return 1
  digest="$(printf '%s' "$snapshot" | shasum -a 256 | awk 'NR == 1 { print $1 }')"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

owned_job_is_active() {
  jobs -p | grep -Fqx -- "$1"
}

collect_owned_tree() {
  local pid="$1" expected_identity="$2" child child_identity observed_identity
  while IFS= read -r child; do
    [[ "$child" =~ ^[1-9][0-9]*$ ]] || continue
    child_identity="$(pid_identity "$child" || true)"
    [[ "$child_identity" =~ ^[0-9a-f]{64}$ ]] || continue
    if kill -STOP "$child" 2>/dev/null; then
      observed_identity="$(pid_identity "$child" || true)"
      if [[ "$observed_identity" == "$child_identity" ]]; then
        collect_owned_tree "$child" "$child_identity"
      else
        # We may have raced process exit/reuse while acquiring authority. Never
        # retain or signal the replacement; undo our best-effort STOP only when
        # it is still the same observed process.
        [[ "$observed_identity" =~ ^[0-9a-f]{64}$ ]] \
          && kill -CONT "$child" 2>/dev/null || true
      fi
    fi
  done < <(pgrep -P "$pid" 2>/dev/null || true)
  printf '%s\t%s\n' "$pid" "$expected_identity"
}

signal_owned_identity() {
  local pid="$1" expected_identity="$2" signal="$3" observed_identity
  observed_identity="$(pid_identity "$pid" || true)"
  [[ "$observed_identity" == "$expected_identity" ]] || return 1
  kill "-$signal" "$pid" 2>/dev/null
}

cleanup_owned_jobs() {
  (( CLEANUP_STARTED == 0 )) || return 0
  CLEANUP_STARTED=1
  : > "$MONITOR_STOP_FILE"
  local pid identity observed_identity deadline active tree_text=""
  local owned=() frozen=()
  set +u
  owned=("${TRAFFIC_PIDS[@]}")
  [[ -z "$MONITOR_JOB_PID" ]] || owned+=("$MONITOR_JOB_PID")
  [[ -z "$SYSTEM_LOG_JOB_PID" ]] || owned+=("$SYSTEM_LOG_JOB_PID")
  # Freeze each direct worker before walking its descendants. This closes the
  # race where a worker starts another curl between a tree snapshot and TERM,
  # leaving that just-created process orphaned outside our cleanup authority.
  for pid in "${owned[@]}"; do
    identity="$(pid_identity "$pid" || true)"
    if owned_job_is_active "$pid" \
      && [[ "$identity" =~ ^[0-9a-f]{64}$ ]] \
      && kill -STOP "$pid" 2>/dev/null
    then
      observed_identity="$(pid_identity "$pid" || true)"
      if [[ "$observed_identity" == "$identity" ]]; then
        frozen+=("$pid" "$identity")
      else
        [[ "$observed_identity" =~ ^[0-9a-f]{64}$ ]] \
          && kill -CONT "$pid" 2>/dev/null || true
      fi
    fi
  done
  for ((index=0; index<${#frozen[@]}; index+=2)); do
    pid="${frozen[index]}"
    identity="${frozen[index+1]}"
    tree_text="${tree_text}$(collect_owned_tree "$pid" "$identity")"$'\n'
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
  deadline=$(( SECONDS + 5 ))
  while (( SECONDS < deadline )); do
    active=0
    for pid in "${owned[@]}"; do
      owned_job_is_active "$pid" && { active=1; break; }
    done
    (( active )) || break
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
      owned_job_is_active "$pid" && { active=1; break; }
    done
    (( active )) || break
    sleep 0.1
  done
  for pid in "${owned[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  set -u
}

handle_signal() {
  local exit_code="$1"
  trap - EXIT INT TERM
  cleanup_owned_jobs
  write_stress_status 0 0 2 "stress run interrupted by signal"
  exit "$exit_code"
}

handle_exit() {
  local exit_code=$?
  trap - EXIT INT TERM
  cleanup_owned_jobs
  exit "$exit_code"
}

trap handle_exit EXIT
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

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
      [[ "$downloaded" == "$LARGE_BYTES" && "$http_version" == 2 ]]
      ;;
    post_large)
      [[ "$uploaded" == "$POST_BYTES" && "$downloaded" == "$POST_BYTES" ]]
      ;;
    small_https)
      [[ "$http_version" == 2 ]]
      ;;
    small_http1)
      [[ "$http_version" == 1.1 ]]
      ;;
    *) return 0 ;;
  esac
}

# Run one curl and return success only when the complete transfer succeeds with
# 2xx. A server can send a 200 header and then truncate the body; the HTTP
# code alone is therefore not an honest request outcome.
do_one_curl() {
  local label="$1" target="$2"; shift 2
  local metrics code downloaded uploaded http_version duration_seconds curl_rc=0 matched=1
  local response_file="" output_file=/dev/null
  if [[ "$label" == post_large ]]; then
    response_file="$LOG_DIR/.post-response.${BASHPID:-$$}.$RANDOM"
    output_file="$response_file"
  fi
  metrics=$(curl --silent --show-error --output "$output_file" \
      --max-time 30 \
      --fail-with-body \
      --write-out $'%{http_code}\t%{size_download}\t%{size_upload}\t%{http_version}\t%{time_total}' \
      "$@" "$target" 2>>"$LOG_DIR/${label}.log") || curl_rc=$?
  IFS=$'\t' read -r code downloaded uploaded http_version duration_seconds <<< "$metrics"
  [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
  printf '%s curl_exit=%s downloaded=%s uploaded=%s http_version=%s duration_seconds=%s\n' \
    "$code" "$curl_rc" "${downloaded:-?}" "${uploaded:-?}" \
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
    if do_one_curl "$label" "$target" "$@"; then
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
      do_one_curl "$label" "$target" "$@" &
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

# One-shot snapshot of a target pid: rss/vsz, vmmap summary, heap totals.
snapshot_pid() {
  local pid="$1" label="$2" expected_identity="${3:-}" observed_identity
  local out="$LOG_DIR/${label}.txt"
  if [[ -n "$expected_identity" ]]; then
    observed_identity="$(pid_identity "$pid" || true)"
    [[ "$observed_identity" == "$expected_identity" ]] || return 1
  fi
  {
    printf '=== %s @ %s ===\n' "$label" "$(date -u +%FT%TZ)"
    ps -o pid,rss,vsz,%cpu,state -p "$pid" 2>/dev/null \
      || { echo "pid $pid gone"; return 1; }
    printf '\n--- vmmap --summary ---\n'
    sudo -n vmmap --summary "$pid" 2>/dev/null \
      || vmmap --summary "$pid" 2>/dev/null \
      || echo "vmmap unavailable (need sudo; cache with 'sudo -v' before the run)"
    printf '\n--- heap totals ---\n'
    sudo -n heap "$pid" 2>/dev/null \
      | grep -E 'All zones:|Total|Process [0-9]+:' \
      || heap "$pid" 2>/dev/null \
      | grep -E 'All zones:|Total|Process [0-9]+:' \
      || echo "heap unavailable (need sudo; cache with 'sudo -v' before the run)"
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
  code=$(curl --silent --show-error --output /dev/null --max-time 10 \
      --write-out '%{http_code}' \
      "$HTTPS_TARGET" 2>/dev/null) || curl_rc=$?
  [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
  if (( curl_rc == 0 )) && [[ "$code" =~ ^2 ]]; then
    say "${GREEN}liveness: probe got $code (target reachable; interception is not attributed)${RESET}"
    return 0
  fi
  say "${RED}liveness: probe got '$code' curl_exit=$curl_rc against $HTTPS_TARGET${RESET}"
  say "  proxy may not be intercepting, sysext may be down, or upstream is rate-limiting"
  say "  set STRESS_SKIP_LIVENESS=1 to run anyway"
  return 1
}

# Optional sampling of a target pid every 5s.
monitor_pid() {
  local pid="$1" expected_identity="$2" observed_identity
  local out="$LOG_DIR/monitor.$pid.log"
  echo "monitoring pid=$pid -> $out" >"$out"
  while [[ ! -e "$MONITOR_STOP_FILE" ]]; do
    observed_identity="$(pid_identity "$pid" || true)"
    if [[ "$observed_identity" != "$expected_identity" ]]; then
      printf '\n=== %s ===\nprovider identity changed or disappeared\n' \
        "$(date -u +%FT%TZ)" >> "$out"
      return 42
    fi
    {
      printf '\n=== %s ===\n' "$(date -u +%FT%TZ)"
      ps -o pid,rss,vsz,%cpu,state -p "$pid" 2>/dev/null \
        || { echo "pid $pid gone"; break; }
      vmmap --summary "$pid" 2>/dev/null | head -40 \
        || echo "vmmap unavailable (try sudo)"
      # `leaks` is sudo on a sysext; only run if available without it.
      leaks --quiet "$pid" 2>/dev/null \
        | grep -E '(Total|Process)' \
        || echo "leaks unavailable (try sudo)"
    } >>"$out"
    sleep 5
  done
  observed_identity="$(pid_identity "$pid" || true)"
  [[ "$observed_identity" == "$expected_identity" ]]
}

stop_system_log_capture() {
  local child_rc
  [[ -n "$SYSTEM_LOG_JOB_PID" ]] || return 0
  if kill -0 "$SYSTEM_LOG_JOB_PID" 2>/dev/null; then
    SYSTEM_LOG_ALIVE_END=1
    kill -TERM "$SYSTEM_LOG_JOB_PID" 2>/dev/null || true
  else
    say "${RED}system log capture exited before the stress window ended${RESET}"
  fi
  wait "$SYSTEM_LOG_JOB_PID" 2>/dev/null
  child_rc=$?
  SYSTEM_LOG_CHILD_RC="$child_rc"
  SYSTEM_LOG_JOINED=1
  SYSTEM_LOG_JOB_PID=""
  case "$child_rc" in
    0|143) return 0 ;;
    *) return 1 ;;
  esac
}

# ── Plan + launch ────────────────────────────────────────────────────

hdr "rama transparent proxy stress test"
say "duration:    ${DURATION}s"
say "concurrency: $CONCURRENCY"
say "log dir:     $LOG_DIR"
[[ -n "$MONITOR_PID" ]] && say "monitor pid: $MONITOR_PID"
(( ANALYZE_ONLY )) && say "analysis:    artifact-only (no workers)"
say "evidence:    $EVIDENCE_MODE (individual requests are not proxy-attributed)"

POST_FILE="$LOG_DIR/post.body"
if (( ! ANALYZE_ONLY )); then
  dd if=/dev/zero of="$POST_FILE" bs=1048576 \
    count=$((POST_BYTES / 1048576)) 2>/dev/null
  POST_REMAINDER=$((POST_BYTES % 1048576))
  if (( POST_REMAINDER > 0 )); then
    dd if=/dev/zero bs="$POST_REMAINDER" count=1 \
      >> "$POST_FILE" 2>/dev/null
  fi
  say "post body:   $(du -h "$POST_FILE" | cut -f1)"
fi

if (( ! ANALYZE_ONLY )); then
  if [[ "$SKIP_LIVENESS" == 0 ]]; then
    if ! liveness_probe "$MONITOR_PID"; then
      exit 1
    fi
  fi

  if [[ -n "$MONITOR_PID" ]]; then
    MONITOR_IDENTITY="$(pid_identity "$MONITOR_PID" || true)"
    if [[ ! "$MONITOR_IDENTITY" =~ ^[0-9a-f]{64}$ ]]; then
      say "${RED}monitor: pid $MONITOR_PID has no stable process identity${RESET}"
      exit 1
    fi
    printf '%s\n' "$MONITOR_IDENTITY" > "$LOG_DIR/monitor.identity.sha256"
    PROVIDER_EXECUTABLE="$(ps -ww -o comm= -p "$MONITOR_PID" 2>/dev/null | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [[ ! -f "$PROVIDER_EXECUTABLE" ]]; then
      say "${RED}monitor: provider executable path is unavailable${RESET}"
      exit 1
    fi
    PROVIDER_EXECUTABLE_SHA256="$(shasum -a 256 "$PROVIDER_EXECUTABLE" | awk '{print $1}')"
    codesign -dvvv "$PROVIDER_EXECUTABLE" > "$LOG_DIR/provider-codesign.txt" 2>&1 || {
      say "${RED}monitor: provider signing identity is unavailable${RESET}"
      exit 1
    }
    PROVIDER_SIGNING_IDENTIFIER="$(sed -n 's/^Identifier=//p' "$LOG_DIR/provider-codesign.txt" | head -1)"
    PROVIDER_SIGNING_TEAM="$(sed -n 's/^TeamIdentifier=//p' "$LOG_DIR/provider-codesign.txt" | head -1)"
    PROVIDER_SIGNING_CDHASH="$(sed -n 's/^CDHash=//p' "$LOG_DIR/provider-codesign.txt" | head -1)"
    if [[ -z "$PROVIDER_SIGNING_IDENTIFIER" || -z "$PROVIDER_SIGNING_TEAM" \
      || ! "$PROVIDER_SIGNING_CDHASH" =~ ^[0-9a-fA-F]+$ ]]
    then
      say "${RED}monitor: provider signing fields are incomplete${RESET}"
      exit 1
    fi
    {
      printf 'pid\t%s\nidentity\t%s\nexecutable\t%s\n' \
        "$MONITOR_PID" "$MONITOR_IDENTITY" "$PROVIDER_EXECUTABLE"
      printf 'executable_sha256\t%s\nsigning_identifier\t%s\n' \
        "$PROVIDER_EXECUTABLE_SHA256" "$PROVIDER_SIGNING_IDENTIFIER"
      printf 'signing_team\t%s\nsigning_cdhash\t%s\n' \
        "$PROVIDER_SIGNING_TEAM" "$PROVIDER_SIGNING_CDHASH"
    } > "$LOG_DIR/provider-identity.tsv"
    if snapshot_pid "$MONITOR_PID" preflight "$MONITOR_IDENTITY"; then
      say "preflight:   $LOG_DIR/preflight.txt"
    else
      say "${RED}preflight: monitored provider identity changed or disappeared${RESET}"
      exit 1
    fi
    NDJSON_PATH="$LOG_DIR/system.ndjson"
    SYSTEM_LOG_TOOL_SHA256="$(shasum -a 256 "$LOG_TOOL" | awk '{print $1}')"
    printf 'path\t%s\nsha256\t%s\n' "$LOG_TOOL" "$SYSTEM_LOG_TOOL_SHA256" \
      > "$LOG_DIR/system-log-tool.tsv"
    "$LOG_TOOL" stream --level debug --style ndjson \
      --predicate "processIdentifier == $MONITOR_PID AND subsystem BEGINSWITH 'org.ramaproxy.example.tproxy'" \
      > "$NDJSON_PATH" 2> "$LOG_DIR/system-log-capture.err" &
    SYSTEM_LOG_JOB_PID="$!"
    sleep 0.5
    if kill -0 "$SYSTEM_LOG_JOB_PID" 2>/dev/null; then
      SYSTEM_LOG_STARTED=1
    else
      say "${RED}monitor: provider system log capture did not stay alive${RESET}"
      exit 2
    fi
  fi

  START_TS=$(date -u +%s)
  TRAFFIC_START_EPOCH="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"

  for worker_name in "${TRAFFIC_WORKERS[@]}"; do
    : > "$LOG_DIR/${worker_name}.log"
    : > "$LOG_DIR/${worker_name}.summary"
  done

  TRAFFIC_PIDS=()
  loop_http small_https "$HTTPS_TARGET" --http2 & TRAFFIC_PIDS+=("$!")
  loop_http small_http1 "$HTTPS_TARGET" --http1.1 & TRAFFIC_PIDS+=("$!")
  loop_http plain_http "$HTTP_TARGET" & TRAFFIC_PIDS+=("$!")
  loop_http large_get "$LARGE_TARGET" --http2 \
    --header 'Accept-Encoding: identity' & TRAFFIC_PIDS+=("$!")
  loop_http post_large "$POST_TARGET" --data-binary "@$POST_FILE" & TRAFFIC_PIDS+=("$!")
  loop_http head_only "$HTTPS_TARGET" --head & TRAFFIC_PIDS+=("$!")
  loop_http churn_close "$HTTPS_TARGET" --header 'Connection: close' & TRAFFIC_PIDS+=("$!")
  loop_pool parallel_pool "$HTTPS_TARGET" & TRAFFIC_PIDS+=("$!")

  MONITOR_JOB_PID=""
  if [[ -n "$MONITOR_PID" ]]; then
    monitor_pid "$MONITOR_PID" "$MONITOR_IDENTITY" &
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
  TRAFFIC_END_EPOCH="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  : > "$MONITOR_STOP_FILE"
  if [[ -n "$MONITOR_JOB_PID" ]]; then
    if ! wait "$MONITOR_JOB_PID"; then
      say "${RED}monitored provider died or changed identity during traffic${RESET}"
      TRAFFIC_FAILED=1
    fi
    MONITOR_JOB_PID=""
  fi
  if [[ -n "$SYSTEM_LOG_JOB_PID" ]] && ! stop_system_log_capture; then
    say "${RED}provider system log capture failed${RESET}"
    TRAFFIC_FAILED=1
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
  if snapshot_pid "$MONITOR_PID" postflight "$MONITOR_IDENTITY"; then
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
    TRAFFIC_FAILED=1
  fi
fi

if (( ! ANALYZE_ONLY )); then
  RUN_END_EPOCH="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  if (( TRAFFIC_FAILED )); then
    say "${RED}one or more traffic workers observed request failures${RESET}"
    write_stress_status 1 0 1
    exit 1
  fi
  METRIC_RESULT="$(
    "$EVIDENCE_HELPER" metrics "$LOG_DIR" "$TRAFFIC_START_EPOCH" \
      "$TRAFFIC_END_EPOCH" "$MAX_P95_MS" "$MIN_THROUGHPUT_MILLI_RPS" \
      "$MAX_RSS_GROWTH_BYTES" "$MAX_CPU_PERCENT" "$EVIDENCE_MODE" \
      "${MONITOR_PID:-none}"
  )" || {
    say "${RED}stress performance evidence is incomplete or malformed${RESET}"
    write_stress_status 0 0 2 "stress performance evidence could not be measured"
    exit 2
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
    write_stress_status 0 0 2 "stress performance helper returned an invalid result"
    exit 2
  fi
  say "performance: p95=${OBSERVED_P95_MS}ms throughput=${OBSERVED_THROUGHPUT_MILLI_RPS} milli-rps"
  if [[ "$EVIDENCE_MODE" == provider-monitored-traffic-only ]]; then
    say "provider:    rss-growth=${OBSERVED_RSS_GROWTH_BYTES}B max-cpu=${OBSERVED_MAX_CPU_PERCENT}%"
  fi
  [[ "$METRIC_STATUS" == PASSED ]] || TRAFFIC_FAILED=1
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
    write_stress_status 0 0 2 "stress worker artifacts could not be sealed"
    exit 2
  }
fi
if (( ANALYZE_ONLY && ANALYSIS_FAILED )); then
  say "${RED}artifact analysis is incomplete or invalid${RESET}"
  write_stress_status 0 0 2 "artifact analysis requires a successful source status and complete worker artifacts"
  exit 2
fi
if (( ! ANALYZE_ONLY && TRAFFIC_FAILED )); then
  say "${RED}one or more explicit stress performance thresholds failed${RESET}"
  write_stress_status 1 0 1
  exit 1
fi
write_stress_status 1 1 0
