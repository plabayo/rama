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
#                         Also enables before/after `vmmap`+`heap`
#                         snapshots (`preflight.txt`, `postflight.txt`)
#                         in the log dir for self-contained diff.
#   STRESS_NDJSON         path to a captured `log show … --style ndjson`
#                         file. When set, the post-run summary parses
#                         it to produce a close-reason histogram, the
#                         single strongest signal that the truncation
#                         fix is working (pre-fix: ~89% `shutdown`
#                         for curl flows; post-fix: dominantly
#                         `peer_eof_*`). Collect with:
#                           sudo log show \
#                             --predicate 'subsystem == "org.ramaproxy.example.tproxy"' \
#                             --start "$(date -u -v-10M '+%Y-%m-%d %H:%M:%S')" \
#                             --style ndjson > /tmp/system.ndjson
#   STRESS_SKIP_LIVENESS  set to 1 to skip the pre-flight liveness
#                         probe. Default off — without the probe we
#                         can spend 180s pounding nothing if the
#                         sysext crashed or is uninstalled.
#
# All workers run in parallel for STRESS_DURATION seconds. The script
# prints a one-line per-worker summary at the end, plus a truncation
# scan and (with STRESS_NDJSON set) a close-reason histogram.

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
NDJSON_PATH="${STRESS_NDJSON:-}"
SKIP_LIVENESS="${STRESS_SKIP_LIVENESS:-}"

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

# `curl` exits 0 on HTTP 4xx/5xx by default and on a `000` connect
# failure when you set `--write-out` without `--fail`. The harness
# is a stress sentinel — every non-2xx outcome is a real signal,
# not a "soft" success. Pass `--fail-with-body` everywhere so curl
# exits non-zero on >= 400, and check the captured status code
# explicitly so we count `000` (connection refused / TLS failure /
# upstream timeout — all of which `--fail-with-body` does NOT
# catch) as fail too.
http_status_is_ok() {
  # Empty / `000` / 4xx / 5xx → fail. Otherwise → ok.
  local code="$1"
  case "$code" in
    "" | 000 | 4?? | 5??) return 1 ;;
    *) return 0 ;;
  esac
}

# Run a single curl + classify. Echos the `%{http_code}` to the
# log and returns 0 only when the response was a 2xx/3xx.
do_one_curl() {
  local label="$1" target="$2"; shift 2
  # `--max-time` covers transport hangs; `--fail-with-body` makes
  # curl exit non-zero on 4xx/5xx (and still capture the body).
  local code
  code=$(curl --silent --show-error --output /dev/null \
      --max-time 30 \
      --fail-with-body \
      --write-out '%{http_code}' \
      "$@" "$target" 2>>"$LOG_DIR/${label}.log") || true
  printf '%s\n' "$code" >>"$LOG_DIR/${label}.log"
  http_status_is_ok "$code"
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
}

# Many curls in parallel via xargs. Each sub-curl logs its result
# line and exits non-zero on failure. We count fails by grepping
# the per-worker log for failure markers at summary time, so the
# pool worker matches `loop_http`'s ok/fail accounting.
loop_pool() {
  local label="$1" target="$2"; shift 2
  local end=$((SECONDS + DURATION)) iter=0
  # Per-request lines look like: `<http_code> <time>s`. Failures
  # have code `000` / 4xx / 5xx, or curl prints `curl: (NN)` to
  # stderr (which `2>&1` redirects into the same log).
  while (( SECONDS < end )); do
    seq 1 "$CONCURRENCY" \
      | xargs -P "$CONCURRENCY" -I{} \
        curl --silent --show-error --output /dev/null \
          --max-time 30 \
          --fail-with-body \
          --write-out '%{http_code} %{time_total}s\n' \
          "$@" "$target" \
          >>"$LOG_DIR/${label}.log" 2>&1 || true
    iter=$((iter + CONCURRENCY))
  done
  # Count any line whose first token is empty / 000 / 4xx / 5xx,
  # plus any `curl: (NN)` stderr line. Same predicate as the
  # final-summary scan below.
  local fail
  fail=$(grep -cE '^(000|[45][0-9]{2})( |$)|^curl: \([0-9]+\) ' \
    "$LOG_DIR/${label}.log" 2>/dev/null)
  fail=${fail:-0}
  local ok=$((iter - fail))
  printf '%s done: iters=%d ok=%d fail=%d\n' "$label" "$iter" "$ok" "$fail" \
    >"$LOG_DIR/${label}.summary"
}

# One-shot snapshot of a target pid: rss/vsz, vmmap summary, heap
# totals. Lands in `$LOG_DIR/$label.txt` so before/after diffs can
# be done with a single `diff` invocation post-run.
#
# `vmmap` and `heap` need `sudo` against a root-owned sysext —
# we use `sudo -n` (non-interactive) so the snapshot doesn't
# silently hang the script waiting for a password prompt
# millennia later. If the user hasn't cached a sudo timestamp
# we fall back to running unprivileged and the file records
# the failure inline, which is still better than silent partial
# capture.
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

# Pre-flight liveness probe. Confirms basic transport works (a
# 2xx round-trip against $HTTPS_TARGET) before we kick off
# DURATION seconds of work — no point pounding upstream if the
# sysext crashed or DNS is broken. Cheap, ~10s worst case.
#
# When MONITOR_PID is set we also confirm the process exists so a
# stale PID (sysext was unloaded between runs) fails fast with a
# specific message instead of bottoming out at "all curls timing
# out". Use `ps -p` rather than `kill -0`: the sysext runs as
# root, and `kill -0` from a regular user returns EPERM
# indistinguishable from ESRCH — would false-flag a healthy
# sysext as gone.
liveness_probe() {
  local pid="$1"
  if [[ -n "$pid" ]] && ! ps -p "$pid" >/dev/null 2>&1; then
    say "${RED}liveness: pid $pid not running — sysext is gone${RESET}"
    return 1
  fi
  local code
  code=$(curl --silent --output /dev/null --max-time 10 \
      --write-out '%{http_code}' \
      "$HTTPS_TARGET" 2>/dev/null) || true
  if [[ "$code" =~ ^2 ]]; then
    say "${GREEN}liveness: probe got $code (proxy reachable, traffic flowing)${RESET}"
    return 0
  fi
  say "${RED}liveness: probe got '$code' against $HTTPS_TARGET${RESET}"
  say "  proxy may not be intercepting, sysext may be down, or upstream is rate-limiting"
  say "  set STRESS_SKIP_LIVENESS=1 to run anyway"
  return 1
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

# Pre-flight: confirm the sysext is intercepting BEFORE we waste
# DURATION seconds on a dead proxy. Failing the probe here saves
# hours of "why are all my flows timing out" head-scratching.
if [[ -z "$SKIP_LIVENESS" ]]; then
  if ! liveness_probe "$MONITOR_PID"; then
    exit 1
  fi
fi

# Pre-flight memory snapshot. Pairs with the post-flight snapshot
# at run end so the diff is self-contained in $LOG_DIR.
if [[ -n "$MONITOR_PID" ]]; then
  if snapshot_pid "$MONITOR_PID" preflight; then
    say "preflight:   $LOG_DIR/preflight.txt"
  fi
fi

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
# not from epoch) here underflows the diff into a large negative
# number.
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
  # Match: `000` (transport failure, no HTTP layer reached), any
  # 4xx/5xx, or a `curl: (NN)` stderr line. The previous regex
  # `0$` matched a literal "0" only and silently dropped `000`
  # codes from the count.
  err_re='^(000|[45][0-9]{2})( |$)|^curl: \([0-9]+\) '
  for f in "$LOG_DIR"/*.log; do
    name=$(basename "$f" .log)
    # `grep -c` prints "0" on no-match AND exits 1, so the
    # naive `|| echo 0` form duplicates the count into the
    # variable ("0\n0"). Capture stdout directly and default
    # any error to 0.
    err_count=$(grep -cE "$err_re" "$f" 2>/dev/null)
    err_count=${err_count:-0}
    if (( err_count > 0 )); then
      printf '%s: %d non-2xx / curl errors\n' "$name" "$err_count"
      grep -E "$err_re" "$f" | head -5 | sed 's/^/  /'
    fi
  done
fi

# Truncation detector. The customer-visible symptom from the
# stress-test root cause was curl reporting `N out of M bytes
# received` on `--max-time` aborts and connection drops mid-body.
# A clean post-fix run should show zero of these for the
# response-side workers (`large_get`, `parallel_pool`, `post_large`).
# Any hit here points at the bridge dropping queued bytes — the
# exact failure mode the close-sink + dispatcher fix was supposed
# to close.
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

# Post-flight memory snapshot. Pair with `preflight.txt` for a
# self-contained delta — `diff $LOG_DIR/preflight.txt $LOG_DIR/postflight.txt`
# shows physical-footprint and vmmap-region drift across the run.
if [[ -n "$MONITOR_PID" ]]; then
  if snapshot_pid "$MONITOR_PID" postflight; then
    hdr "memory snapshot"
    say "preflight  → $LOG_DIR/preflight.txt"
    say "postflight → $LOG_DIR/postflight.txt"
    say "diff       → diff $LOG_DIR/preflight.txt $LOG_DIR/postflight.txt"
  fi
fi

# Close-reason histogram. The audit's smoking-gun signal was the
# fraction of TCP flow closes that recorded `reason=shutdown`
# vs `peer_eof_*`. Pre-fix: ~89% shutdown for curl flows because
# the production dispatcher routed natural EOF through `cancel()`.
# Post-fix: should be dominantly `peer_eof_left`. We parse
# whatever ndjson the operator captured (see STRESS_NDJSON in the
# header docs) and bucket by reason; the absolute numbers don't
# matter, the proportion does.
if [[ -n "$NDJSON_PATH" ]]; then
  hdr "close-reason histogram (from $NDJSON_PATH)"
  if [[ ! -r "$NDJSON_PATH" ]]; then
    say "${RED}cannot read $NDJSON_PATH${RESET}"
  else
    # Each system.ndjson line is a JSON object; the close-event
    # message is `transparent proxy tcp flow closed` with a
    # `reason` field. We avoid jq dependency and use awk + a
    # narrow regex: `reason":"…"`.
    awk '
      /transparent proxy (tcp|udp) flow closed/ {
        if (match($0, /"reason"\s*:\s*"[^"]+"/)) {
          r = substr($0, RSTART, RLENGTH)
          sub(/.*"reason"\s*:\s*"/, "", r)
          sub(/".*/, "", r)
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
