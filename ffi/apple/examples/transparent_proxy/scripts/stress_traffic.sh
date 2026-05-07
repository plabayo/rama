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
#   STRESS_DURATION       wall-clock seconds, per worker. Default 60.
#   STRESS_CONCURRENCY    parallel curls in the pool worker. Default 16.
#   STRESS_LARGE_BYTES    bytes for the large-GET worker. Default 16 MiB.
#   STRESS_POST_BYTES     bytes for the POST-body worker. Default 8 MiB.
#   STRESS_HTTP_TARGET    plain-HTTP target. Default http://httpbin.org/get
#   STRESS_HTTPS_TARGET   HTTPS target. Default https://httpbin.org/get
#   STRESS_LARGE_TARGET   large-download target. Default speed.cloudflare.com.
#   STRESS_POST_TARGET    POST echo target. Default https://httpbin.org/post
#   STRESS_LOG_DIR        where per-worker logs go. Default mktemp.
#   STRESS_MONITOR_PID    if set, periodically `leaks` / `vmmap` the pid.
#
# All workers run in parallel for STRESS_DURATION seconds. The script
# prints a one-line per-worker summary at the end.

set -uo pipefail

DURATION="${STRESS_DURATION:-60}"
CONCURRENCY="${STRESS_CONCURRENCY:-16}"
LARGE_BYTES="${STRESS_LARGE_BYTES:-16777216}"   # 16 MiB
POST_BYTES="${STRESS_POST_BYTES:-8388608}"      # 8 MiB

HTTP_TARGET="${STRESS_HTTP_TARGET:-http://httpbin.org/get}"
HTTPS_TARGET="${STRESS_HTTPS_TARGET:-https://httpbin.org/get}"
POST_TARGET="${STRESS_POST_TARGET:-https://httpbin.org/post}"
LARGE_TARGET="${STRESS_LARGE_TARGET:-https://speed.cloudflare.com/__down?bytes=${LARGE_BYTES}}"

LOG_DIR="${STRESS_LOG_DIR:-$(mktemp -d /tmp/rama-stress.XXXXXX)}"
mkdir -p "$LOG_DIR"

MONITOR_PID="${STRESS_MONITOR_PID:-}"

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

# Run `curl_args …` against `target` until DURATION elapses.
# stdout: one numeric http_code (or `--`) per request.
loop_http() {
  local label="$1" target="$2"; shift 2
  local end=$((SECONDS + DURATION)) iter=0 ok=0 fail=0
  while (( SECONDS < end )); do
    if curl --silent --show-error --output /dev/null \
        --max-time 30 \
        --write-out '%{http_code}\n' \
        "$@" "$target" >>"$LOG_DIR/${label}.log" 2>&1
    then
      ok=$((ok+1))
    else
      fail=$((fail+1))
    fi
    iter=$((iter+1))
  done
  printf '%s done: iters=%d ok=%d fail=%d\n' "$label" "$iter" "$ok" "$fail" \
    >"$LOG_DIR/${label}.summary"
}

# Many curls in parallel via xargs. Each sub-curl logs its result line.
loop_pool() {
  local label="$1" target="$2"; shift 2
  local end=$((SECONDS + DURATION)) iter=0
  while (( SECONDS < end )); do
    seq 1 "$CONCURRENCY" \
      | xargs -P "$CONCURRENCY" -I{} \
        curl --silent --show-error --output /dev/null \
          --max-time 30 \
          --write-out '%{http_code} %{time_total}s\n' \
          "$@" "$target" \
          >>"$LOG_DIR/${label}.log" 2>&1
    iter=$((iter + CONCURRENCY))
  done
  printf '%s done: total_requests=%d\n' "$label" "$iter" \
    >"$LOG_DIR/${label}.summary"
}

# Optional sampling of a target pid: vmmap regions, leaks count,
# resident set size — captured every 5s.
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

# Generate the POST body once (a stream of zeros).
POST_FILE="$LOG_DIR/post.body"
dd if=/dev/zero of="$POST_FILE" bs=1024 \
   count=$((POST_BYTES / 1024)) 2>/dev/null
say "post body:   $(du -h "$POST_FILE" | cut -f1)"

START_TS=$(date -u +%s)

# Worker pool — each runs in the background.
loop_http      small_https     "$HTTPS_TARGET"   --http2 &
loop_http      small_http1     "$HTTPS_TARGET"   --http1.1 &
loop_http      plain_http      "$HTTP_TARGET" &
loop_http      large_get       "$LARGE_TARGET"  --http2 &
loop_http      post_large      "$POST_TARGET"   --data-binary "@$POST_FILE" &
loop_http      head_only       "$HTTPS_TARGET"  --head &
loop_http      churn_close     "$HTTPS_TARGET"  --header 'Connection: close' &
loop_pool      parallel_pool   "$HTTPS_TARGET" &

if [[ -n "$MONITOR_PID" ]]; then
  monitor_pid "$MONITOR_PID" &
fi

WORKER_PIDS=$(jobs -p)
say "workers up:  $(echo "$WORKER_PIDS" | wc -w | tr -d ' ')"

# Live progress while we wait. `START_TS` is an epoch-second
# timestamp; subtract a fresh epoch read to get elapsed seconds.
# Using bash's built-in `$SECONDS` (which counts from shell start,
# not from epoch) here underflows into a wildly negative "elapsed"
# display — that was the broken counter in the v2 stress audit.
while kill -0 $(echo "$WORKER_PIDS" | head -1) 2>/dev/null; do
  ELAPSED=$(( $(date -u +%s) - START_TS ))
  if (( ELAPSED > DURATION )); then break; fi
  printf '\r[stress] %ds elapsed' "$ELAPSED"
  sleep 1
done
printf '\n'

wait

# ── Summary ──────────────────────────────────────────────────────────

hdr "summary"
for f in "$LOG_DIR"/*.summary; do
  [[ -f "$f" ]] || continue
  cat "$f"
done

if compgen -G "$LOG_DIR/*.log" >/dev/null; then
  hdr "errors per worker (top 5)"
  for f in "$LOG_DIR"/*.log; do
    name=$(basename "$f" .log)
    err_count=$(grep -cE '^(curl: |[045][0-9]{2}|0$)' "$f" 2>/dev/null || echo 0)
    if (( err_count > 0 )); then
      printf '%s: %d non-2xx / curl errors\n' "$name" "$err_count"
      grep -E '^(curl: |[045][0-9]{2}|0$)' "$f" | head -5 | sed 's/^/  /'
    fi
  done
fi

hdr "logs at $LOG_DIR"
say "  hand to $LOG_DIR/system.ndjson alongside the offline-bundle script in the README"
say "done"
