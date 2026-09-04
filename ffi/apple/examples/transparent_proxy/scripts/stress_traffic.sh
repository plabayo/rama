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
#                         file. When set, the summary parses it to
#                         produce a close-reason histogram. Collect with:
#                           sudo log show \
#                             --predicate 'subsystem == "org.ramaproxy.example.tproxy"' \
#                             --start "$(date -u -v-10M '+%Y-%m-%d %H:%M:%S')" \
#                             --style ndjson > /tmp/system.ndjson
#   STRESS_SKIP_LIVENESS  set to 1 to skip the pre-flight liveness
#                         probe. Default off — without the probe we
#                         can spend 180s pounding nothing if the
#                         sysext crashed or is uninstalled.
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
if [[ -n "$MONITOR_PID" ]]; then
  require_bounded_uint STRESS_MONITOR_PID "$MONITOR_PID" 2147483647
  [[ "$MONITOR_PID" != 0 ]] || {
    printf '[stress] STRESS_MONITOR_PID must be greater than zero\n' >&2
    exit 2
  }
fi
[[ "$CONCURRENCY" != 0 ]] || {
  printf '[stress] STRESS_CONCURRENCY must be greater than zero\n' >&2
  exit 2
}

HTTP_TARGET="${STRESS_HTTP_TARGET:-http://http-test.ramaproxy.org/method}"
HTTPS_TARGET="${STRESS_HTTPS_TARGET:-https://http-test.ramaproxy.org/method}"
POST_TARGET="${STRESS_POST_TARGET:-https://http-test.ramaproxy.org/octet-stream}"
LARGE_TARGET="${STRESS_LARGE_TARGET:-https://http-test.ramaproxy.org/bytes?size=${LARGE_BYTES}}"

LOG_DIR="${STRESS_LOG_DIR:-$(mktemp -d /tmp/rama-stress.XXXXXX)}"
mkdir -p "$LOG_DIR"

ANALYZE_ONLY=0
TRAFFIC_FAILED=0
if [[ "$DURATION" == 0 ]]; then
  ANALYZE_ONLY=1
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

trap 'kill $(jobs -p) 2>/dev/null || true' EXIT INT TERM

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
      [[ "$uploaded" == "$POST_BYTES" ]]
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
  local metrics code downloaded uploaded http_version curl_rc=0
  metrics=$(curl --silent --show-error --output /dev/null \
      --max-time 30 \
      --fail-with-body \
      --write-out $'%{http_code}\t%{size_download}\t%{size_upload}\t%{http_version}' \
      "$@" "$target" 2>>"$LOG_DIR/${label}.log") || curl_rc=$?
  IFS=$'\t' read -r code downloaded uploaded http_version <<< "$metrics"
  [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
  printf '%s curl_exit=%s downloaded=%s uploaded=%s http_version=%s\n' \
    "$code" "$curl_rc" "${downloaded:-?}" "${uploaded:-?}" \
    "${http_version:-?}" >>"$LOG_DIR/${label}.log"
  (( curl_rc == 0 )) \
    && http_status_is_ok "$code" \
    && transfer_matches_workload \
      "$label" "${downloaded:-}" "${uploaded:-}" "${http_version:-}"
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
  local worker summary summary_line summary_pattern
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
    if [[ "${BASH_REMATCH[1]}" == 0 ]]; then
      say "${RED}${worker}: worker reported iters=0${RESET}"
      progress_failed=1
    fi
  done
  (( progress_failed == 0 ))
}

# One-shot snapshot of a target pid: rss/vsz, vmmap summary, heap totals.
snapshot_pid() {
  local pid="$1" label="$2"
  local out="$LOG_DIR/${label}.txt"
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
    say "${GREEN}liveness: probe got $code (proxy reachable, traffic flowing)${RESET}"
    return 0
  fi
  say "${RED}liveness: probe got '$code' curl_exit=$curl_rc against $HTTPS_TARGET${RESET}"
  say "  proxy may not be intercepting, sysext may be down, or upstream is rate-limiting"
  say "  set STRESS_SKIP_LIVENESS=1 to run anyway"
  return 1
}

# Optional sampling of a target pid every 5s.
monitor_pid() {
  local pid="$1"
  local end=$((SECONDS + DURATION))
  local out="$LOG_DIR/monitor.$pid.log"
  echo "monitoring pid=$pid -> $out" >>"$out"
  while (( SECONDS < end )); do
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
}

# ── Plan + launch ────────────────────────────────────────────────────

hdr "rama transparent proxy stress test"
say "duration:    ${DURATION}s"
say "concurrency: $CONCURRENCY"
say "log dir:     $LOG_DIR"
[[ -n "$MONITOR_PID" ]] && say "monitor pid: $MONITOR_PID"
(( ANALYZE_ONLY )) && say "analysis:    artifact-only (no workers)"

POST_FILE="$LOG_DIR/post.body"
if (( ! ANALYZE_ONLY )); then
  dd if=/dev/zero of="$POST_FILE" bs=1024 \
     count=$((POST_BYTES / 1024)) 2>/dev/null
  say "post body:   $(du -h "$POST_FILE" | cut -f1)"
fi

if (( ! ANALYZE_ONLY )); then
  if [[ "$SKIP_LIVENESS" == 0 ]]; then
    if ! liveness_probe "$MONITOR_PID"; then
      exit 1
    fi
  fi

  if [[ -n "$MONITOR_PID" ]]; then
    if snapshot_pid "$MONITOR_PID" preflight; then
      say "preflight:   $LOG_DIR/preflight.txt"
    fi
  fi

  START_TS=$(date -u +%s)

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
    monitor_pid "$MONITOR_PID" &
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
  [[ -n "$MONITOR_JOB_PID" ]] && wait "$MONITOR_JOB_PID" || true
  verify_worker_progress || TRAFFIC_FAILED=1
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
  if snapshot_pid "$MONITOR_PID" postflight; then
    hdr "memory snapshot"
    say "preflight  → $LOG_DIR/preflight.txt"
    say "postflight → $LOG_DIR/postflight.txt"
    say "diff       → diff $LOG_DIR/preflight.txt $LOG_DIR/postflight.txt"
  fi
fi

# Close-reason histogram from a captured system log.
if [[ -n "$NDJSON_PATH" ]]; then
  hdr "close-reason histogram (from $NDJSON_PATH)"
  if [[ ! -r "$NDJSON_PATH" ]]; then
    say "${RED}cannot read $NDJSON_PATH${RESET}"
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
if (( ! ANALYZE_ONLY && TRAFFIC_FAILED )); then
  say "${RED}one or more traffic workers observed request failures${RESET}"
  exit 1
fi
