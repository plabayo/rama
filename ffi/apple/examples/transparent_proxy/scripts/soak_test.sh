#!/usr/bin/env bash
# soak_test.sh — one comprehensive live session for the rama Apple NE
# transparent proxy. Drives a battery of phases back-to-back and bundles
# everything that tells us whether the lifetime / leak / wake / flow-pressure
# fixes hold, into a single artifact dir (+ tarball) to hand back.
#
# It AUTO-DETECTS the running build's flow-pressure soft cap from the gauge
# log line ("… softCap=N") and adapts safely:
#   softCap > MAX_SAFE_FLOWS → CAP-TOO-HIGH-TO-CROSS: the cap cannot be exceeded
#       without nearing the (~600) kernel nexus ceiling, which would risk the
#       very machine freeze the cap prevents. The session runs at a SAFE
#       concurrency (under the cap) and validates leak/freeze/wake/keepalive
#       only; it tells you to use a LOW-CAP build to validate eviction.
#   0 < softCap ≤ MAX_SAFE_FLOWS → CAP-VALIDATE: safe to cross the (low) cap;
#       drive occupancy past it and prove the reaper invariants hold.
#   softCap == 0 → (only with FIND_CEILING=1) CEILING-FINDER: carefully ramp
#       until the nexus allocation is exhausted, report the gauge peak, back off.
#
# To VALIDATE the pressure reaper on-device, configure the Rust builder in
# tproxy_rs/src/lib.rs before installing the app:
#   .with_flow_pressure_soft_cap(80)
#   .with_flow_pressure_low_water(60)
#   .with_flow_pressure_idle_floor_ms(10_000)
# Keep the live-flow hard cap enabled. Ceiling-finder runs additionally require
# `.with_live_flow_hard_cap(0)` and are intentionally unsafe.
#
# Phases (default giant session):
#   0  baseline      detect softCap + baseline flow count + mem
#   1  stress        the mixed stress_traffic.sh burst (connect/relay churn)
#   2  fanout        sustained pool of ACTIVE (slow-drip) flows
#                    (→ peak, admit-and-ride, active-not-evicted)
#   3  idle-holders  sustained pool of SILENT (no-data) flows
#                    (→ idle-eviction reaper, on a short-floor build)
#   4  real-download steady transfer
#   5  sleep/wake    the original wake-bug scenario (TTY only)
#   6  idle-tail     quiesce so the gauge can settle back toward baseline
#   then: final mem snapshot, leaks pass, dial9 traces, signal extraction.
#
# What it captures (in OUT/):
#   system.ndjson        full debug-level os_log stream for the sysext
#   flow-counts.txt      the 60s "live-flow counts" gauge timeline
#   phases.tsv           wall-clock start/end of every phase (epoch + iso)
#   run-meta.tsv         softCap, mode, baseline flow count
#   timeline.txt         lifecycle / sleep / wake / reaper / relay / error lines
#   extract-summary.txt  peak vs cap, reaper tallies (keyed on the human log
#                        lines that actually reach os_log), body-relay errors,
#                        freeze verdict, per-phase gauge, baseline-relative leak
#   stress/              per-worker logs + preflight/postflight vmmap+heap
#   fanout.txt           per-worker outcomes of the active pool
#   holders.log          flow-pool live/gauge timeline
#   probe-timeline.txt    periodic liveness probe (freeze detector)
#   final-mem.txt        ps/vmmap/heap AFTER the idle tail
#   leaks.txt            `leaks` pass on the live sysext
#   dial9-traces/        per-flow egress dial traces
#
# Usage (run from anywhere):
#   bash scripts/soak_test.sh
#   FIND_CEILING=1 bash scripts/soak_test.sh      # only when both caps are 0!
#
# Requires: the dev proxy already enabled in the container app (or DO_INSTALL=1
# to build+install+open it first), and sudo.
#
# Env knobs (all optional):
#   REPO            repo root. Default: /Users/glendc/code/github.com/plabayo/rama
#   OUT             artifact dir. Default: ~/rama-tproxy-soak/<timestamp>
#   DO_INSTALL      1 = `just install-tproxy-dev` first. Default 0.
#   STRESS_SECONDS  phase-1 stress duration. Default 180.
#   CONCURRENCY     phase-1 stress pool size. Default 24.
#   DL_HOST         download/holder host (rama http-test). Default http-test.ramaproxy.org.
#   FANOUT_TARGET   phase-2 concurrent active flows. Default auto
#                   (min(softCap+25%, MAX_SAFE_FLOWS), floored at 40).
#   FANOUT_HOLD     phase-2 sustain seconds. Default 90.
#   MAX_SAFE_FLOWS  max concurrency the AUTO target will request, to stay well
#                   under the ~600 nexus ceiling. Default 300.
#   ALLOW_UNSAFE_LOAD 1 = let an explicit FANOUT_TARGET/IDLE_TARGET exceed
#                   MAX_SAFE_FLOWS on a high-cap build (freeze risk!). Default 0.
#   IDLE_TARGET     phase-3 concurrent silent holders. Default = FANOUT_TARGET.
#   IDLE_HOLD       phase-3 sustain seconds. Default 150.
#   SKIP_STRESS / SKIP_FANOUT / SKIP_IDLE   1 = skip that phase. Default 0.
#   SKIP_SLEEP      1 = skip sleep/wake. Default 0.
#   IDLE_TAIL       trailing quiesce seconds (≥2 gauge ticks). Default 135.
#   FIND_CEILING    1 = ceiling-finder (DANGEROUS; softCap=0/hardCap=0 only). Default 0.
#   CEIL_STEP / CEIL_SETTLE   ceiling-finder ramp step / settle. Default 40 / 8.
#   ASSUME_YES      1 = skip the ceiling-finder confirmation. Default 0.

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────────
REPO="${REPO:-/Users/glendc/code/github.com/plabayo/rama}"
EXAMPLE_DIR="$REPO/ffi/apple/examples/transparent_proxy"
STRESS_SH="$EXAMPLE_DIR/scripts/stress_traffic.sh"
PROVIDER_BUNDLE="org.ramaproxy.example.tproxy.dev.provider"
SUBSYSTEM_PREFIX="org.ramaproxy.example.tproxy"
HTTPS_PROBE="https://http-test.ramaproxy.org/method"
DL_HOST="${DL_HOST:-http-test.ramaproxy.org}"
DL_MAX_BYTES=$(( 32 * 1024 * 1024 ))   # http-test /bytes server cap (MAX_BYTES)
DIAL9_DIR="/var/root/Library/Application Support/rama/tproxy/dial9-traces"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-$HOME/rama-tproxy-soak/$STAMP}"
DO_INSTALL="${DO_INSTALL:-0}"
STRESS_SECONDS="${STRESS_SECONDS:-180}"
CONCURRENCY="${CONCURRENCY:-24}"
FANOUT_TARGET="${FANOUT_TARGET:-0}"      # 0 = auto from softCap
FANOUT_HOLD="${FANOUT_HOLD:-90}"
MAX_SAFE_FLOWS="${MAX_SAFE_FLOWS:-300}"
ALLOW_UNSAFE_LOAD="${ALLOW_UNSAFE_LOAD:-0}"
IDLE_TARGET="${IDLE_TARGET:-0}"          # 0 = auto (= FANOUT_TARGET)
IDLE_HOLD="${IDLE_HOLD:-150}"
SKIP_STRESS="${SKIP_STRESS:-0}"
SKIP_FANOUT="${SKIP_FANOUT:-0}"
SKIP_IDLE="${SKIP_IDLE:-0}"
SKIP_SLEEP="${SKIP_SLEEP:-0}"
IDLE_TAIL="${IDLE_TAIL:-135}"
FIND_CEILING="${FIND_CEILING:-0}"
CEIL_STEP="${CEIL_STEP:-40}"
CEIL_SETTLE="${CEIL_SETTLE:-8}"
ASSUME_YES="${ASSUME_YES:-0}"

LOGBUF=""; command -v stdbuf >/dev/null 2>&1 && LOGBUF="stdbuf -oL"
PYTHON_BIN="$(command -v python3 || true)"

# ── Pretty output ─────────────────────────────────────────────────────
if [[ -t 1 ]] && tput colors >/dev/null 2>&1; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; RESET=$'\e[0m'; RED=$'\e[31m'; GREEN=$'\e[32m'; YEL=$'\e[33m'
else
  BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""; YEL=""
fi
say()  { printf '%s[soak]%s %s\n' "$DIM" "$RESET" "$*"; }
hdr()  { printf '\n%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$BOLD" "$*" "$RESET"; }
warn() { printf '%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$YEL" "$*" "$RESET" >&2; }
die()  { printf '%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$RED" "$*" "$RESET" >&2; exit 1; }

for _n in STRESS_SECONDS CONCURRENCY FANOUT_TARGET FANOUT_HOLD MAX_SAFE_FLOWS \
          IDLE_TARGET IDLE_HOLD IDLE_TAIL CEIL_STEP CEIL_SETTLE; do
  _v="${!_n}"
  [[ "$_v" =~ ^[0-9]+$ ]] || die "$_n must be a non-negative integer (got '$_v')"
done

# ── Teardown ──────────────────────────────────────────────────────────
LOG_STREAM_STARTED=0
LOG_STREAM_PID=""
SUDO_KEEPALIVE_PID=""
PROBE_MON_PID=""
HOLDER_PIDFILE=""
FLOW_POOL_ATTAINED=0
FLOW_POOL_MAX_LIVE=0
kill_holders() {
  # Kill every flow-pool worker we launched (pidfile is the source of truth;
  # the pattern kill is a scoped backup for the drip curls).
  if [[ -n "$HOLDER_PIDFILE" && -f "$HOLDER_PIDFILE" ]]; then
    while read -r _p; do [[ -n "$_p" ]] && kill "$_p" 2>/dev/null || true; done < "$HOLDER_PIDFILE"
    : > "$HOLDER_PIDFILE"
  fi
  pkill -f "$DL_HOST/bytes" 2>/dev/null || true
}
cleanup() {
  [[ -n "$PROBE_MON_PID" ]] && kill "$PROBE_MON_PID" 2>/dev/null || true
  kill_holders
  [[ -n "$SUDO_KEEPALIVE_PID" ]] && kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
  if (( LOG_STREAM_STARTED )) && [[ -n "$LOG_STREAM_PID" ]]; then
    sudo -n kill "$LOG_STREAM_PID" 2>/dev/null || true
  fi
  local _j; _j="$(jobs -p 2>/dev/null)"
  [[ -n "$_j" ]] && kill $_j 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Helpers ───────────────────────────────────────────────────────────
probe_once() { curl -s -o /dev/null --max-time 12 -w '%{http_code}' "$HTTPS_PROBE" 2>/dev/null || true; }
probe_ok() { [[ "$(probe_once)" =~ ^2 ]]; }

epoch_now() {
  if [[ -n "$PYTHON_BIN" ]]; then
    "$PYTHON_BIN" -c 'import time; print(f"{time.time():.6f}")'
  else
    printf '%s.000000\n' "$(date +%s)"
  fi
}

# Build a rama /bytes URL that streams `size` bytes in `chunk` pieces with
# `delay_ms` between chunks (server-side drip). size clamped to the 32 MiB cap,
# delay to the 60s server cap.
dl_url() {
  local size="$1" chunk="${2:-16384}" delay="${3:-0}"
  (( size > DL_MAX_BYTES )) && size=$DL_MAX_BYTES
  (( delay > 60000 )) && delay=60000
  printf 'https://%s/bytes?size=%s&chunk=%s&delay_ms=%s' "$DL_HOST" "$size" "$chunk" "$delay"
}

phase_mark() {
  local epoch
  epoch="$(epoch_now)"
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$epoch" "$(date -u +%FT%TZ)" >> "$OUT/phases.tsv"
}

# Latest gauge sample → "softcap hardcap tcp udp total" (or "" if no tick yet).
read_gauge() {
  grep -oE 'live-flow counts tcp=[0-9]+ udp=[0-9]+ total=[0-9]+ peak=[0-9]+ softCap=[0-9]+ hardCap=[0-9]+' \
    "$OUT/system.ndjson" 2>/dev/null | tail -1 \
    | sed -E 's/.*tcp=([0-9]+) udp=([0-9]+) total=([0-9]+) peak=[0-9]+ softCap=([0-9]+) hardCap=([0-9]+)/\4 \5 \1 \2 \3/'
}
wait_for_gauge() {
  local deadline=$(( $(date +%s) + $1 )) g
  while (( $(date +%s) < deadline )); do
    g="$(read_gauge)"; [[ -n "$g" ]] && { echo "$g"; return 0; }
    sleep 3
  done
  echo ""
}

start_probe_monitor() {
  ( while true; do
      printf '%s\t%s\t%s\n' "$(epoch_now)" "$(date -u +%FT%TZ)" "$(probe_once)" >> "$OUT/probe-timeline.txt"
      sleep 5
    done ) &
  PROBE_MON_PID=$!
}

# Count live (kill -0) pids in the pidfile, rewriting it to survivors only.
recount_holders() {
  local live=0 tmp="$OUT/.pids.tmp"; : > "$tmp"
  while read -r p; do
    [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null && { echo "$p" >> "$tmp"; live=$((live+1)); }
  done < "$HOLDER_PIDFILE"
  mv "$tmp" "$HOLDER_PIDFILE"
  echo "$live"
}

# spawn one ACTIVE flow: a slow server-side drip (~45s, refilled by top-up as
# the server's ~60s connection timeout cuts it). Holds an established flow.
spawn_active() {
  local delay=22   # 2048 chunks * 22ms ≈ 45s drip, under the 60s server cut
  curl -s -o /dev/null --max-time 70 \
    -w '%{http_code} %{size_download} %{time_total}\n' \
    "$(dl_url "$DL_MAX_BYTES" 16384 "$delay")" >> "$OUT/fanout.txt" 2>&1 &
  echo $! >> "$HOLDER_PIDFILE"
}

# spawn one SILENT flow: raw TCP connect that sends nothing, exits on EOF
# (server close) or after IDLE_HOLD. The proxy peeks for 8s, sees no
# ClientHello, then passes it through → an established silent flow that ages
# toward the idle floor. (On a long-floor build the server's ~60s timeout cuts
# it before the floor → admit-and-ride; on a short-floor build it gets evicted.)
spawn_silent() {
  ( exec 3<>/dev/tcp/"$DL_HOST"/443 2>/dev/null && IFS= read -r -t "$IDLE_HOLD" -u 3 _ ) \
    >/dev/null 2>&1 &
  echo $! >> "$HOLDER_PIDFILE"
}

# Sustain a pool of `target` flows for `hold` seconds via top-up, logging the
# gauge each tick.  run_flow_pool LABEL TARGET HOLD SPAWN_FN
run_flow_pool() {
  local label="$1" target="$2" hold="$3" spawn_fn="$4"
  : > "$HOLDER_PIDFILE"
  local end=$(( $(date +%s) + hold )) live need g
  FLOW_POOL_ATTAINED=0
  FLOW_POOL_MAX_LIVE=0
  while (( $(date +%s) < end )); do
    live="$(recount_holders)"
    need=$(( target - live ))
    (( need > 0 )) && { local k; for ((k=0; k<need; k++)); do "$spawn_fn"; done; }
    sleep 1
    live="$(recount_holders)"   # settle, then report survivors honestly
    (( live > FLOW_POOL_MAX_LIVE )) && FLOW_POOL_MAX_LIVE=$live
    (( live >= target )) && FLOW_POOL_ATTAINED=1
    g="$(read_gauge)"
    printf '%s\t%s\tlive=%s\tgauge_total=%s\n' "$(date -u +%FT%TZ)" "$label" "$live" "${g##* }" >> "$OUT/holders.log"
    printf '\r[soak] %s live=%s gauge_total=%s  %ds left   ' "$label" "$live" "${g##* }" "$(( end - $(date +%s) ))"
    probe_ok || warn "probe failed during $label (gauge_total=${g##* }) — watch for freeze"
    sleep 5
  done
  printf '\r%-70s\r' ' '
  kill_holders
  sleep 3
}

# ── Preconditions ─────────────────────────────────────────────────────
hdr "rama transparent proxy soak — comprehensive single session"
[[ -x "$(command -v curl)" ]] || die "curl not found"
[[ -f "$STRESS_SH" ]] || die "stress script not found at $STRESS_SH (is REPO correct?)"
mkdir -p "$OUT" || die "cannot create OUT=$OUT"
: > "$OUT/phases.tsv"; : > "$OUT/run-meta.tsv"
HOLDER_PIDFILE="$OUT/holders.pids"; : > "$HOLDER_PIDFILE"
ulimit -n 16384 2>/dev/null || true

say "artifacts:   $OUT"
say "stress:      ${STRESS_SECONDS}s @ concurrency $CONCURRENCY"
say "fanout:      target $([[ "$FANOUT_TARGET" == 0 ]] && echo auto || echo "$FANOUT_TARGET"), hold ${FANOUT_HOLD}s (active drip via $DL_HOST)"
say "idle hold:   target $([[ "$IDLE_TARGET" == 0 ]] && echo auto || echo "$IDLE_TARGET") silent flows, sustain ${IDLE_HOLD}s"
say "sleep/wake:  $([[ "$SKIP_SLEEP" == 1 ]] && echo skipped || echo enabled)"
say "idle tail:   ${IDLE_TAIL}s"
(( FIND_CEILING )) && warn "FIND_CEILING=1 — ceiling-finder ARMED (only valid when softCap=0 and hardCap=0)"

say "caching sudo (you may be prompted once)..."
sudo -v || die "sudo is required"
( while true; do sudo -n -v 2>/dev/null || exit 0; sleep 30; done ) &
SUDO_KEEPALIVE_PID=$!

# ── Optional install ──────────────────────────────────────────────────
if [[ "$DO_INSTALL" == 1 ]]; then
  hdr "building + installing the dev proxy"
  ( cd "$EXAMPLE_DIR" && just install-tproxy-dev ) || die "install failed"
  warn "enable the system extension + toggle the proxy ON in the app, then press Enter"
  if [[ -t 0 ]]; then read -r _; else sleep 10; fi
fi

# ── Liveness ──────────────────────────────────────────────────────────
hdr "liveness check"
PROBE_CODE="$(probe_once)"
[[ "$PROBE_CODE" =~ ^2 ]] || die "probe got '$PROBE_CODE' against $HTTPS_PROBE — proxy not intercepting, sysext down, or no network. Enable the proxy (or DO_INSTALL=1) and retry."
say "${GREEN}probe ok ($PROBE_CODE) — traffic is flowing through the proxy${RESET}"
# Sanity-check the download host actually serves through the proxy (Cloudflare
# 403s under MITM; the rama host does not).
DL_CHECK="$(curl -s -o /dev/null --max-time 20 -w '%{http_code}' "$(dl_url 65536 16384 0)" 2>/dev/null || true)"
if [[ "$DL_CHECK" =~ ^2 ]]; then
  DOWNLOAD_HOST_PREFLIGHT_OK=1
  say "${GREEN}download host ok ($DL_CHECK via $DL_HOST/bytes)${RESET}"
else
  DOWNLOAD_HOST_PREFLIGHT_OK=0
  warn "download host probe got '$DL_CHECK' against $DL_HOST/bytes — fanout/holders may be starved"
fi
printf 'download_host_preflight_ok\t%s\n' "$DOWNLOAD_HOST_PREFLIGHT_OK" >> "$OUT/run-meta.tsv"

PID="$(pgrep -f "$PROVIDER_BUNDLE" | head -1 || true)"
[[ -n "$PID" ]] || die "could not find the sysext process ($PROVIDER_BUNDLE). Is it enabled?"
PROVIDER_START_TIME="$(ps -o lstart= -p "$PID" 2>/dev/null | sed -E 's/^[[:space:]]+//')"
[[ -n "$PROVIDER_START_TIME" ]] || die "could not read sysext process identity for pid $PID"
say "sysext pid:  $PID"
printf 'provider_start_pid\t%s\nprovider_start_time\t%s\n' \
  "$PID" "$PROVIDER_START_TIME" >> "$OUT/run-meta.tsv"

# ── Start live log capture (debug — the gauge is debug) ────────────────
hdr "starting log capture"
sudo $LOGBUF log stream --level debug --style ndjson \
  --predicate "subsystem BEGINSWITH \"$SUBSYSTEM_PREFIX\"" \
  > "$OUT/system.ndjson" 2>/dev/null &
LOG_STREAM_PID=$!
LOG_STREAM_STARTED=1
sleep 2
if sudo -n kill -0 "$LOG_STREAM_PID" 2>/dev/null; then
  printf 'log_stream_started\t1\nlog_stream_pid\t%s\n' "$LOG_STREAM_PID" >> "$OUT/run-meta.tsv"
else
  printf 'log_stream_started\t0\nlog_stream_pid\t%s\n' "$LOG_STREAM_PID" >> "$OUT/run-meta.tsv"
  warn "log stream did not stay alive — evidence verdicts will be inconclusive"
fi
say "streaming → $OUT/system.ndjson"
start_probe_monitor
printf 'probe_monitor_pid\t%s\n' "$PROBE_MON_PID" >> "$OUT/run-meta.tsv"
say "probe monitor → $OUT/probe-timeline.txt (freeze detector)"

# ── Phase 0: baseline + softCap detection ─────────────────────────────
phase_mark baseline start
hdr "phase 0 — baseline (detecting softCap from the gauge; ≤65s)"
G0="$(wait_for_gauge 65)"
if [[ -z "$G0" ]]; then
  warn "no gauge tick seen in 65s — evidence verdicts will be inconclusive"
  SOFTCAP_KNOWN=0; SOFTCAP=0; HARDCAP=0; BASELINE_TOTAL=0
else
  SOFTCAP_KNOWN=1
  read -r SOFTCAP HARDCAP _ _ BASELINE_TOTAL <<< "$G0"
  say "detected ${BOLD}softCap=$SOFTCAP hardCap=$HARDCAP${RESET}, baseline live flows=$BASELINE_TOTAL"
fi
printf 'softcap\t%s\nhardcap\t%s\nbaseline_total\t%s\n' \
  "$SOFTCAP" "$HARDCAP" "$BASELINE_TOTAL" >> "$OUT/run-meta.tsv"
printf 'baseline_gauge_seen\t%s\n' "$SOFTCAP_KNOWN" >> "$OUT/run-meta.tsv"

# Resolve mode.
MODE="cap-validate"
if (( FIND_CEILING )); then
  (( SOFTCAP_KNOWN )) || die "FIND_CEILING=1 requires a current gauge proving both caps are disabled."
  (( SOFTCAP == 0 )) || die "FIND_CEILING=1 but softCap=$SOFTCAP — rebuild with both flow caps set to 0."
  (( HARDCAP == 0 )) || die "FIND_CEILING=1 but hardCap=$HARDCAP — rebuild with both flow caps set to 0."
  MODE="find-ceiling"
elif (( SOFTCAP_KNOWN )) && (( SOFTCAP == 0 )); then
  warn "softCap=0 (cap DISABLED) but FIND_CEILING!=1 — running stress only; pass FIND_CEILING=1 to ramp to the ceiling."
  MODE="stress-only"
elif (( SOFTCAP_KNOWN )) && (( HARDCAP > 0 )) && (( HARDCAP <= SOFTCAP )); then
  warn "hardCap=$HARDCAP prevents crossing softCap=$SOFTCAP; pressure validation is configuration-limited"
  MODE="cap-hard-limited"
elif (( SOFTCAP_KNOWN )) && (( SOFTCAP > MAX_SAFE_FLOWS )); then
  MODE="cap-too-high"
fi
say "mode:        ${BOLD}$MODE${RESET}"
printf 'mode\t%s\n' "$MODE" >> "$OUT/run-meta.tsv"

# Derive auto target. AUTO never exceeds MAX_SAFE_FLOWS — on a high-cap build
# crossing the cap means nearing the ~600 nexus ceiling = the freeze we test
# against. To validate eviction, use a LOW-CAP build (then auto safely crosses).
auto_target() {
  local base=$MAX_SAFE_FLOWS
  (( SOFTCAP_KNOWN )) && (( SOFTCAP > 0 )) && base=$(( SOFTCAP + SOFTCAP / 4 ))
  (( base > MAX_SAFE_FLOWS )) && base=$MAX_SAFE_FLOWS
  (( base < 40 )) && base=40
  echo "$base"
}
clamp_safe() {  # clamp an explicit target unless ALLOW_UNSAFE_LOAD on a high-cap build
  local v="$1" name="$2"
  if (( v > MAX_SAFE_FLOWS )) && (( SOFTCAP >= MAX_SAFE_FLOWS )) && (( ALLOW_UNSAFE_LOAD != 1 )); then
    warn "$name=$v exceeds MAX_SAFE_FLOWS=$MAX_SAFE_FLOWS on a softCap=$SOFTCAP build — clamping to avoid"
    warn "  nearing the ~600 nexus ceiling (machine-freeze risk). Set ALLOW_UNSAFE_LOAD=1 to override,"
    warn "  or use a low-cap build to validate eviction safely."
    echo "$MAX_SAFE_FLOWS"
  else
    echo "$v"
  fi
}
if (( FANOUT_TARGET == 0 )); then FANOUT_TARGET="$(auto_target)"; else FANOUT_TARGET="$(clamp_safe "$FANOUT_TARGET" FANOUT_TARGET)"; fi
if (( IDLE_TARGET == 0 )); then IDLE_TARGET=$FANOUT_TARGET; else IDLE_TARGET="$(clamp_safe "$IDLE_TARGET" IDLE_TARGET)"; fi
say "resolved targets: fanout=$FANOUT_TARGET idle=$IDLE_TARGET (MAX_SAFE_FLOWS=$MAX_SAFE_FLOWS)"
[[ "$MODE" == "cap-too-high" ]] && warn "softCap=$SOFTCAP > MAX_SAFE_FLOWS=$MAX_SAFE_FLOWS: this run validates leak/freeze/wake only, NOT cap eviction. Use a low-cap build to exercise the reaper."

{
  printf '=== baseline @ %s ===\n' "$(date -u +%FT%TZ)"
  printf 'softCap=%s baseline_total=%s mode=%s fanout=%s idle=%s\n\n' "$SOFTCAP" "$BASELINE_TOTAL" "$MODE" "$FANOUT_TARGET" "$IDLE_TARGET"
  ps -o pid,rss,vsz,%cpu,state -p "$PID" 2>/dev/null || echo "pid gone"
  printf '\n--- vmmap --summary ---\n'
  sudo -n vmmap --summary "$PID" 2>/dev/null || echo "vmmap unavailable"
} > "$OUT/baseline-mem.txt" 2>&1
phase_mark baseline end

# ════════════════ CEILING-FINDER (opt-in, softCap=0 only) ═════════════
if [[ "$MODE" == "find-ceiling" ]]; then
  phase_mark ceiling start
  hdr "CEILING-FINDER"
  warn "This deliberately exhausts the kernel nexus-flow allocation and can"
  warn "briefly FREEZE ALL networking on this Mac. It backs off + kills load the"
  warn "instant the probe fails. NOTE: against a 60s-timeout server it may"
  warn "plateau BELOW the true ceiling (flows die before enough accumulate)."
  if [[ -t 0 && "$ASSUME_YES" != 1 ]]; then
    printf '%s[soak]%s type CEILING to proceed: ' "$DIM" "$RESET"; read -r _ans
    [[ "$_ans" == "CEILING" ]] || die "aborted"
  fi
  launched=0; last_good=0; ceiling=""; CEILING_FOUND=0
  while (( launched < MAX_SAFE_FLOWS * 3 )); do
    for ((i=0; i<CEIL_STEP; i++)); do spawn_active; launched=$((launched+1)); done
    sleep "$CEIL_SETTLE"
    g="$(read_gauge)"; occ="${g##* }"; [[ -z "$occ" ]] && occ="?"
    if probe_ok; then
      last_good="$occ"; say "ramp: launched=$launched gauge_total=$occ probe=OK"
    else
      ceiling="$occ"; CEILING_FOUND=1
      warn "probe FAILED at gauge_total=$occ — likely the ceiling. Backing off."; break
    fi
  done
  (( CEILING_FOUND )) || warn "ceiling was not found before the configured ramp limit"
  say "killing load to recover the machine..."
  kill_holders
  CEILING_RECOVERED=0
  for i in $(seq 1 20); do
    if probe_ok; then
      CEILING_RECOVERED=1
      say "${GREEN}recovered${RESET}"
      break
    fi
    sleep 3
  done
  (( CEILING_RECOVERED )) || warn "network did not recover within the ceiling-finder budget"
  {
    printf 'ceiling-finder result\n'
    printf 'last gauge_total with probe OK: %s\n' "$last_good"
    printf 'gauge_total at first probe FAIL: %s\n' "${ceiling:-none}"
    printf 'set softCap ~70%% and lowWater ~55%% of the ceiling.\n'
  } | tee "$OUT/ceiling.txt"
  printf 'ceiling_found\t%s\nceiling_recovered\t%s\n' \
    "$CEILING_FOUND" "$CEILING_RECOVERED" >> "$OUT/run-meta.tsv"
  phase_mark ceiling end
else

# ════════════════ CAP-VALIDATE / STRESS battery ══════════════════════

if [[ "$SKIP_STRESS" != 1 ]]; then
  phase_mark stress start
  hdr "phase 1 — stress traffic (${STRESS_SECONDS}s @ $CONCURRENCY)"
  if STRESS_DURATION="$STRESS_SECONDS" STRESS_CONCURRENCY="$CONCURRENCY" \
    STRESS_MONITOR_PID="$PID" STRESS_LOG_DIR="$OUT/stress" STRESS_SKIP_LIVENESS=1 \
      bash "$STRESS_SH" | tee "$OUT/stress-run.txt"; then
    STRESS_OK=1
  else
    STRESS_OK=0
    warn "stress run returned nonzero"
  fi
  phase_mark stress end
else
  STRESS_OK=skipped
fi
printf 'stress_ok\t%s\n' "$STRESS_OK" >> "$OUT/run-meta.tsv"

if [[ "$SKIP_FANOUT" != 1 ]]; then
  phase_mark fanout start
  hdr "phase 2 — fanout: sustain $FANOUT_TARGET active flows for ${FANOUT_HOLD}s"
  say "active slow-drip flows via $DL_HOST/bytes → peak / admit-and-ride / active-not-evicted"
  : > "$OUT/fanout.txt"
  run_flow_pool fanout "$FANOUT_TARGET" "$FANOUT_HOLD" spawn_active
  FANOUT_OK=$FLOW_POOL_ATTAINED
  printf 'fanout_max_live\t%s\n' "$FLOW_POOL_MAX_LIVE" >> "$OUT/run-meta.tsv"
  phase_mark fanout end
else
  FANOUT_OK=skipped
fi
printf 'fanout_ok\t%s\n' "$FANOUT_OK" >> "$OUT/run-meta.tsv"

if [[ "$SKIP_IDLE" != 1 ]]; then
  phase_mark idle-holders start
  hdr "phase 3 — idle holders: sustain $IDLE_TARGET silent flows for ${IDLE_HOLD}s"
  say "raw silent TCP flows (no data) → ages toward the idle floor → eviction reaper"
  warn "NOTE: the rama test host cuts idle conns at ~60s, and the prod idle floor"
  warn "is 120s, so on a PROD build expect admit-and-ride (no eviction). Build with"
  warn "a short Rust flow-pressure idle floor (≈10s) to see evictions."
  run_flow_pool idle-holders "$IDLE_TARGET" "$IDLE_HOLD" spawn_silent
  IDLE_HOLDERS_OK=$FLOW_POOL_ATTAINED
  printf 'idle_holders_max_live\t%s\n' "$FLOW_POOL_MAX_LIVE" >> "$OUT/run-meta.tsv"
  phase_mark idle-holders end
else
  IDLE_HOLDERS_OK=skipped
fi
printf 'idle_holders_ok\t%s\n' "$IDLE_HOLDERS_OK" >> "$OUT/run-meta.tsv"

phase_mark real-download start
hdr "phase 4 — real-world download (32 MiB steady stream)"
if curl -L -f -s -o /dev/null --max-time 120 \
    -w 'real-download: code=%{http_code} size=%{size_download} avg=%{speed_download}B/s time=%{time_total}s\n' \
    "$(dl_url "$DL_MAX_BYTES" 32768 5)" 2>&1 | tee "$OUT/real-download.txt"; then
  REAL_DOWNLOAD_OK=1
else
  REAL_DOWNLOAD_OK=0
  warn "real download failed"
fi
printf 'real_download_ok\t%s\n' "$REAL_DOWNLOAD_OK" >> "$OUT/run-meta.tsv"
phase_mark real-download end

if [[ "$SKIP_SLEEP" == 1 || ! -t 0 ]]; then
  hdr "phase 5 — sleep/wake (SKIPPED)"
  [[ ! -t 0 && "$SKIP_SLEEP" != 1 ]] && warn "no TTY — skipping sleep/wake (needs a manual wake)"
  POST_WAKE_OK=skipped
else
  phase_mark sleep-wake start
  hdr "phase 5 — sleep/wake"
  warn "This will put the Mac to SLEEP. A download will be in flight."
  warn "WAKE THE MAC MANUALLY (keypress / lid) ~45s after it sleeps."
  printf '%s[soak]%s press Enter to start (or Ctrl-C to abort)... ' "$DIM" "$RESET"
  read -r _
  say "starting a long server-drip download in the background (in flight across sleep)..."
  # Long drip so a transfer is genuinely mid-stream across sleep/wake (bounded
  # by --max-time; the server's ~60s timeout may cut the SAME flow — this proves
  # post-wake RECOVERY, not that one flow survives the gap).
  ( curl -L -s -o /dev/null --max-time 600 \
      -w 'wake-download: code=%{http_code} size=%{size_download} time=%{time_total}s\n' \
      "$(dl_url "$DL_MAX_BYTES" 16384 250)" > "$OUT/wake-download.txt" 2>&1 ) &
  WAKE_DL_PID=$!
  sleep 8
  warn ">>> SLEEPING NOW — wake the Mac manually in ~45s <<<"
  sudo pmset sleepnow || warn "pmset sleepnow failed"
  sleep 5
  sudo -v 2>/dev/null || true
  say "awake — probing connectivity..."
  for i in 1 2 3; do
    WCODE="$(probe_once)"
    printf 'post-wake probe %d: %s\n' "$i" "$WCODE" | tee -a "$OUT/post-wake.txt"
    [[ "$WCODE" =~ ^2 ]] && break
    sleep 3
  done
  if [[ "${WCODE:-}" =~ ^2 ]]; then
    POST_WAKE_OK=1
    say "${GREEN}post-wake: traffic recovered ($WCODE)${RESET}"
  else
    POST_WAKE_OK=0
    warn "post-wake: traffic did NOT recover (last code '$WCODE') — this is the bug we're hunting"
  fi
  sleep 5
  kill "$WAKE_DL_PID" 2>/dev/null || true
  [[ -f "$OUT/wake-download.txt" ]] && cat "$OUT/wake-download.txt"
  phase_mark sleep-wake end
fi
printf 'post_wake_ok\t%s\n' "$POST_WAKE_OK" >> "$OUT/run-meta.tsv"

phase_mark idle-tail start
hdr "phase 6 — idle ${IDLE_TAIL}s (quiesce; keep the machine idle for a clean leak read)"
for ((t=IDLE_TAIL; t>0; t-=5)); do printf '\r[soak] idle %3ds remaining' "$t"; sleep 5; done
printf '\r%-40s\r' ' '
phase_mark idle-tail end

fi  # end cap-validate vs ceiling-finder

# ── Final memory snapshot (re-resolve pid; detect a restart) ──────────
hdr "final memory snapshot"
PID2=""
if kill -0 "$PID" 2>/dev/null; then
  PID2="$PID"
else
  PID2="$(pgrep -f "$PROVIDER_BUNDLE" | head -1 || true)"
fi
PROVIDER_END_TIME=""
[[ -n "$PID2" ]] && PROVIDER_END_TIME="$(ps -o lstart= -p "$PID2" 2>/dev/null | sed -E 's/^[[:space:]]+//')"
PROVIDER_CONTINUOUS=1
if [[ -z "$PID2" ]]; then
  warn "sysext process is GONE after the run (crashed or uninstalled)"
  PROVIDER_CONTINUOUS=0
elif [[ "$PID2" != "$PID" || "$PROVIDER_END_TIME" != "$PROVIDER_START_TIME" ]]; then
  warn "sysext RESTARTED during the run: $PID → $PID2 (watchdog churn / crash — itself a signal)"
  PROVIDER_CONTINUOUS=0
fi
printf 'provider_end_pid\t%s\nprovider_end_time\t%s\nprovider_continuous\t%s\n' \
  "${PID2:-gone}" "${PROVIDER_END_TIME:-gone}" "$PROVIDER_CONTINUOUS" >> "$OUT/run-meta.tsv"
SNAP_PID="${PID2:-$PID}"
{
  printf '=== final snapshot @ %s ===\n' "$(date -u +%FT%TZ)"
  printf 'start pid=%s  final pid=%s  restarted=%s\n\n' \
    "$PID" "${PID2:-gone}" "$([[ "${PID2:-}" != "$PID" ]] && echo YES || echo no)"
  ps -o pid,rss,vsz,%cpu,state -p "$SNAP_PID" 2>/dev/null || echo "pid $SNAP_PID gone"
  printf '\n--- vmmap --summary ---\n'
  sudo -n vmmap --summary "$SNAP_PID" 2>/dev/null || echo "vmmap unavailable"
  printf '\n--- heap totals ---\n'
  sudo -n heap "$SNAP_PID" 2>/dev/null | grep -E 'All zones:|Total|Process [0-9]+:' || echo "heap unavailable"
} > "$OUT/final-mem.txt" 2>&1
say "→ $OUT/final-mem.txt"

# ── leaks pass ────────────────────────────────────────────────────────
hdr "leaks pass"
sudo leaks "$SNAP_PID" > "$OUT/leaks.txt" 2>&1 || true
LEAK_LINE="$(grep -E 'leaks for|total leaked|Process .* leaks' "$OUT/leaks.txt" 2>/dev/null | head -1)"
say "${LEAK_LINE:-(see leaks.txt)}"

# ── Stop log capture ──────────────────────────────────────────────────
hdr "stopping log capture"
PROBE_MONITOR_ALIVE=0
[[ -n "$PROBE_MON_PID" ]] && kill -0 "$PROBE_MON_PID" 2>/dev/null && PROBE_MONITOR_ALIVE=1
printf 'probe_monitor_alive_end\t%s\n' "$PROBE_MONITOR_ALIVE" >> "$OUT/run-meta.tsv"
[[ -n "$PROBE_MON_PID" ]] && kill "$PROBE_MON_PID" 2>/dev/null || true; PROBE_MON_PID=""
LOG_STREAM_ALIVE=0
[[ -n "$LOG_STREAM_PID" ]] && sudo -n kill -0 "$LOG_STREAM_PID" 2>/dev/null && LOG_STREAM_ALIVE=1
printf 'log_stream_alive_end\t%s\n' "$LOG_STREAM_ALIVE" >> "$OUT/run-meta.tsv"
[[ -n "$LOG_STREAM_PID" ]] && sudo -n kill "$LOG_STREAM_PID" 2>/dev/null || true
LOG_STREAM_STARTED=0
LOG_STREAM_PID=""
sleep 1
NDJSON_LINES="$(wc -l < "$OUT/system.ndjson" 2>/dev/null | tr -d ' ' || echo 0)"
say "captured $NDJSON_LINES ndjson lines"

# ── dial9 traces ──────────────────────────────────────────────────────
hdr "collecting dial9 traces"
if sudo -n test -d "$DIAL9_DIR" 2>/dev/null; then
  sudo cp -R "$DIAL9_DIR" "$OUT/dial9-traces" 2>/dev/null \
    && sudo chown -R "$(whoami)" "$OUT/dial9-traces" 2>/dev/null \
    && say "→ $OUT/dial9-traces ($(find "$OUT/dial9-traces" -type f | wc -l | tr -d ' ') files)" \
    || warn "could not copy dial9 traces"
else
  say "(no dial9 traces present)"
fi

# ── Extract the signals that matter from the ndjson ───────────────────
hdr "extracting signals"
PYX="$(command -v python3 || true)"
if [[ -n "$PYX" ]]; then
  "$PYX" - "$OUT" "$EXAMPLE_DIR/scripts" <<'PYEOF'
import os, re, sys
from decimal import Decimal
from datetime import datetime, timezone

sys.path.insert(0, sys.argv[2])
from soak_pressure_log import (
    classify_soak_result,
    flow_gauge,
    no_headroom_event,
    parse_epoch,
    parse_ndjson_lines,
    phase_for_epoch,
    pressure_reaper_status,
    selection_event,
    settled_final_flow_gauge,
    soak_evidence_issues,
    summarize_pressure_rows,
)

out = sys.argv[1]
nd = os.path.join(out, "system.ndjson")

meta = {}
mf = os.path.join(out, "run-meta.tsv")
if os.path.exists(mf):
    for ln in open(mf):
        p = ln.rstrip("\n").split("\t")
        if len(p) == 2:
            meta[p[0]] = p[1]

phases = []
pf = os.path.join(out, "phases.tsv")
starts = {}
ended_phases = set()
if os.path.exists(pf):
    phase_starts_us = {}
    phase_ends_us = {}
    for ln in open(pf):
        p = ln.rstrip("\n").split("\t")
        if len(p) < 3:
            continue
        name, kind, epoch = p[0], p[1], p[2]
        try:
            epoch_decimal = Decimal(epoch)
            e = epoch_decimal
            e_us = int(epoch_decimal * 1_000_000)
        except (ValueError, ArithmeticError):
            continue
        if kind == "start":
            starts[name] = e
            phase_starts_us[name] = e_us
        elif kind == "end" and name in starts:
            phases.append([name, starts[name], e])
            phase_ends_us[name] = e_us
            ended_phases.add(name)

def phase_of(ep):
    return phase_for_epoch(ep, phases)

def to_epoch(ts):
    if not ts:
        return None
    try:
        parsed = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f%z").timestamp()
        return parse_epoch(f"{parsed:.6f}")
    except Exception:
        try:
            parsed = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc).timestamp()
            return parse_epoch(f"{parsed:.6f}")
        except Exception:
            return None

baseline_end_epoch = next(
    (end for name, _, end in phases if name == "baseline"), None)
baseline_end_epoch_us = phase_ends_us.get("baseline")

def is_in_run(ep):
    return baseline_end_epoch is None or (
        ep is not None and ep > baseline_end_epoch)

rows = []
ndjson_issues = []
try:
    with open(nd, "r", errors="replace") as f:
        decoded, ndjson_issues = parse_ndjson_lines(f)
        rows = [
            (o.get("timestamp", ""), o.get("eventMessage", ""), o.get("messageType", ""))
            for o in decoded
        ]
except FileNotFoundError:
    pass

# Reaper signals are summarized separately below. Periodic deltas and episode
# totals overlap, so they are evidence channels rather than additive counters.
wd_idle_re = re.compile(r"watchdog: force-tearing down (\d+) idle promoted flow")
wd_wedged_re = re.compile(r"watchdog: force-tearing down (\d+) wedged closing flow")
wd_prerdy_re = re.compile(r"watchdog: force-tearing down (\d+) stale pre-ready flow")
drain_re = re.compile(r"drain backstop fired")
# Body-relay / egress-health signals — the Firefox "authenticity could not be
# verified" maps to these (decode-aborted/truncated client streams).
body_err_re = re.compile(r"brotli error|gzip error|zstd error|deflate error|send body user stream error|User\(Body\)")
egress_fail_re = re.compile(r"egress NWConnection failed after flow opened.*rawValue: (\d+)")
relay_drop_re = re.compile(r"drop MITM relay")
life_re = re.compile(r"(startProxy|stopProxy|system sleep|system wake|engine created|engine detached|"
                     r"watchdog:|drain backstop|force-drop|force-tear|flow pressure|not satisfied|"
                     r"Network is down|reset by peer|brotli error|drop MITM relay)", re.I)

peak_tcp = peak_udp = peak_total = 0
softcap_seen = set()
hardcap_seen = set()
missing_hardcap_gauges = 0
n_gauge = 0
c = dict(admit_and_ride=0, wd_idle=0,
         wd_wedged=0, wd_prerdy=0, drain_backstop=0, body_err=0,
         relay_drop=0, sleep=0, wake=0, err=0)
egress_fail = {}   # posix code -> count
per_phase = {}
gauge_epochs_per_phase = {}

pressure = summarize_pressure_rows(
    ((to_epoch(ts), msg) for ts, msg, _ in rows),
    baseline_end_epoch=baseline_end_epoch,
    baseline_end_epoch_us=baseline_end_epoch_us)

idle_tail = next(
    ((start, end) for name, start, end in phases if name == "idle-tail"),
    (None, None))
final_gauge = settled_final_flow_gauge(
    ((to_epoch(ts), msg) for ts, msg, _ in rows),
    settle_start_epoch=idle_tail[0],
    settle_end_epoch=idle_tail[1])

def ph(n):
    return per_phase.setdefault(n, dict(peak_total=0, ride=0, body_err=0, gauge=0))

with open(os.path.join(out, "flow-counts.txt"), "w") as g, \
     open(os.path.join(out, "timeline.txt"), "w") as t:
    for ts, msg, mtype in rows:
        ep = to_epoch(ts); pname = phase_of(ep)
        gauge = flow_gauge(msg)
        if gauge:
            tcp = gauge["tcp"]; udp = gauge["udp"]; total = gauge["total"]
            pk = gauge["peak"]; sc = gauge["soft_cap"]; hc = gauge["hard_cap"]
            g.write(
                f"{ts}  [{pname}]  tcp={tcp} udp={udp} total={total} "
                f"peak={pk} softCap={sc} hardCap={hc if hc is not None else 'missing'}\n"
            )
            peak_tcp = max(peak_tcp, tcp); peak_udp = max(peak_udp, udp); peak_total = max(peak_total, total)
            softcap_seen.add(sc); n_gauge += 1
            if hc is not None:
                hardcap_seen.add(hc)
            else:
                missing_hardcap_gauges += 1
            p = ph(pname); p["peak_total"] = max(p["peak_total"], total); p["gauge"] += 1
            if ep is not None:
                gauge_epochs_per_phase.setdefault(pname, []).append(ep)
        selection = selection_event(msg)
        if selection is not None and is_in_run(ep):
            ph(pname)["peak_total"] = max(
                ph(pname)["peak_total"], selection["occupancy"])
        no_headroom = no_headroom_event(msg)
        if no_headroom is not None and is_in_run(ep):
            c["admit_and_ride"] += 1; ph(pname)["ride"] += 1
            ph(pname)["peak_total"] = max(
                ph(pname)["peak_total"], no_headroom["occupancy"])
        for rx, key in ((wd_idle_re, "wd_idle"), (wd_wedged_re, "wd_wedged"), (wd_prerdy_re, "wd_prerdy")):
            mm = rx.search(msg)
            if mm:
                c[key] += int(mm.group(1))
        if drain_re.search(msg):
            c["drain_backstop"] += 1
        if body_err_re.search(msg):
            c["body_err"] += 1; ph(pname)["body_err"] += 1
        if relay_drop_re.search(msg):
            c["relay_drop"] += 1
        ef = egress_fail_re.search(msg)
        if ef:
            egress_fail[ef.group(1)] = egress_fail.get(ef.group(1), 0) + 1
        if mtype in ("Error", "Fault") or life_re.search(msg):
            t.write(f"{ts}  [{pname}] [{mtype or 'Default'}]  {msg}\n")
            ml = msg.lower()
            if mtype in ("Error", "Fault"):
                c["err"] += 1
            if "system sleep" in ml:
                c["sleep"] += 1
            if "system wake" in ml:
                c["wake"] += 1

# Freeze detector (probe-timeline epoch \t iso \t code); exclude sleep-wake.
probe_fail = probe_total = max_fail_run = probe_skipped = 0
probe_per_phase = {}
ptl = os.path.join(out, "probe-timeline.txt")
if os.path.exists(ptl):
    run = 0
    for ln in open(ptl):
        p = ln.rstrip("\n").split("\t")
        if len(p) < 3:
            continue
        ep = parse_epoch(p[0])
        code = p[-1]
        if phase_of(ep) == "sleep-wake":
            probe_skipped += 1; run = 0; continue
        probe_total += 1
        probe_phase = phase_of(ep)
        if ep is not None:
            probe_per_phase.setdefault(probe_phase, []).append(ep)
        if not code.startswith("2"):
            probe_fail += 1; run += 1; max_fail_run = max(max_fail_run, run)
        else:
            run = 0

# Fanout active-flow outcomes (descriptive; killed-by-topup pollutes codes).
fo_ok = fo_bad = 0
fof = os.path.join(out, "fanout.txt")
if os.path.exists(fof):
    for ln in open(fof, errors="replace"):
        mm = re.match(r"\s*(\d{3})\s", ln)
        if mm:
            if mm.group(1)[0] in "23":
                fo_ok += 1
            else:
                fo_bad += 1

def meta_true(key):
    return meta.get(key) == "1"

capture_issues = list(ndjson_issues)
if missing_hardcap_gauges:
    capture_issues.append(
        f"{missing_hardcap_gauges} flow-gauge sample(s) omitted hardCap")
if len(softcap_seen) > 1:
    capture_issues.append("flow-pressure soft cap changed during the run")
if len(hardcap_seen) > 1:
    capture_issues.append("live-flow hard cap changed during the run")
if softcap_seen and meta.get("softcap") not in {str(value) for value in softcap_seen}:
    capture_issues.append("baseline soft cap does not match captured gauges")
if hardcap_seen and meta.get("hardcap") not in {str(value) for value in hardcap_seen}:
    capture_issues.append("baseline hard cap does not match captured gauges")

if meta.get("mode") == "find-ceiling":
    required_phases = {"baseline", "ceiling"}
else:
    required_phases = {"baseline", "real-download", "idle-tail"}
    for outcome, phase in (
        ("stress_ok", "stress"),
        ("fanout_ok", "fanout"),
        ("idle_holders_ok", "idle-holders"),
        ("post_wake_ok", "sleep-wake"),
    ):
        if meta.get(outcome) != "skipped":
            required_phases.add(phase)

evidence_issues = soak_evidence_issues(
    meta,
    rows_count=len(rows),
    gauge_count=n_gauge,
    probe_count=probe_total,
    incomplete_phases=set(starts) - ended_phases,
    phase_coverage=(
        (
            name, start, end,
            probe_per_phase.get(name, []),
            gauge_epochs_per_phase.get(name, []),
        )
        for name, start, end in phases
    ),
    required_phases=required_phases,
    capture_issues=capture_issues,
    final_gauge_required=meta.get("mode") != "find-ceiling",
    final_gauge_present=final_gauge is not None,
)
baseline_total = int(meta.get("baseline_total", "0") or "0")
final_total = final_gauge["total"] if final_gauge else None
softcap_seen.update(pressure["soft_caps"])
sc = max(softcap_seen) if softcap_seen else int(meta.get("softcap", "0") or "0")
observed_peak = pressure["observed_peak"]
periodic = pressure["periodic"]
episode = pressure["episode"]
reaper_status = pressure_reaper_status(pressure, sc, not evidence_issues)
run_result = classify_soak_result(
    meta,
    evidence_issues,
    probe_failures=probe_fail,
    body_errors=c["body_err"],
    reaper_status=reaper_status,
)
evidence_issues = run_result["evidence_issues"]
evidence_complete = run_result["complete"]
run_passed = run_result["passed"]
run_failures = run_result["failures"]

with open(os.path.join(out, "extract-summary.txt"), "w") as s:
    def w(line=""):
        print(line); s.write(line + "\n")
    w("=== soak extract summary ===")
    w(f"mode:                     {meta.get('mode','?')}")
    w(f"ndjson rows parsed:       {len(rows)}")
    w(f"phases:                   {', '.join(p[0] for p in phases) or '(none)'}")
    w(f"softCap (gauge):          {sorted(softcap_seen) or sc}")
    w(f"hardCap (gauge):          {sorted(hardcap_seen) or meta.get('hardcap', '?')}")
    w(f"gauge ticks:              {n_gauge}")
    w(f"sampled peak flows:       tcp={peak_tcp} udp={peak_udp} total={peak_total}")
    w(f"observed event peak:      total={observed_peak}")
    w(f"provider continuity:      {'GOOD' if meta_true('provider_continuous') else 'FAIL'}")
    w(f"evidence completeness:    {'GOOD' if evidence_complete else 'INCONCLUSIVE'}")
    for issue in evidence_issues:
        w(f"  missing: {issue}")
    w(f"run verdict:              {'GOOD' if run_passed else 'FAIL'}")
    for failure in run_failures:
        w(f"  failure: {failure}")
    w("")
    w("--- leak (baseline-relative; assumes a quiet idle tail) ---")
    w(f"baseline live flows:      {baseline_total}")
    w(f"final live flows:         {final_total if final_total is not None else 'n/a'}")
    if not evidence_complete:
        w("leak verdict:             INCONCLUSIVE — evidence or provider continuity is incomplete")
    elif final_total <= baseline_total + 5:
        w(f"leak verdict:             GOOD — settled to ≈baseline ({final_total} ≤ {baseline_total}+5)")
    else:
        w(f"leak verdict:             INFO — final {final_total} above baseline {baseline_total} by "
          f"{final_total-baseline_total}; a transparent proxy counts ALL machine traffic, so this is")
        w("                          likely live ambient traffic, not a leak. Re-check with a quiet,")
        w("                          longer idle tail + cross-check leaks.txt before suspecting a leak.")
    w("")
    w("--- flow-pressure reaper (keyed on emitted log lines) ---")
    w(f"pressure selections:      {pressure['selection_events']}  "
      f"(flows selected: {pressure['selected']})")
    w(f"periodic outcome deltas:  evicted={periodic['evicted']} spared={periodic['spared']} "
      f"canceled={periodic['canceled']} expired={periodic['expired']} "
      f"(intervals: {pressure['periodic_intervals']})")
    w(f"finalized episode totals: evicted={episode['evicted']} spared={episode['spared']} "
      f"canceled={episode['canceled']} expired={episode['expired']} "
      f"(episodes: {pressure['episodes']})")
    w("                          channels overlap and are NOT summed")
    w(f"admit-and-ride (no idle): {c['admit_and_ride']}")
    if sc > 0:
        head = sc - observed_peak
        w(f"peak vs softCap:          observed_peak={observed_peak} softCap={sc} "
          f"({'UNDER by %d' % head if head >= 0 else 'OVER by %d (rode)' % (-head)})")
        if not evidence_complete:
            w("reaper verdict:           INCONCLUSIVE — evidence or provider continuity is incomplete")
        elif reaper_status == "good":
            w("reaper verdict:           GOOD — cap crossed and reaper evicted idle flows.")
        elif reaper_status == "crossed-without-attributable-eviction":
            w("reaper verdict:           cap crossed with no post-boundary finalized eviction episode;")
            w("                          periodic deltas alone are not attributable to this run.")
        else:
            w("reaper verdict:           cap crossing NOT OBSERVED. A between-tick burst can evade sampled")
            w("                          gauges; use a LOW-CAP build and require event/episode evidence.")
    w("")
    w("--- watchdog / drain teardowns ---")
    w(f"drain-backstop fires:     {c['drain_backstop']}")
    w(f"watchdog idle teardowns:  {c['wd_idle']}")
    w(f"watchdog wedged-close:    {c['wd_wedged']}")
    w(f"watchdog stale pre-ready: {c['wd_prerdy']}")
    w("")
    w("--- body-relay / egress health (Firefox 'authenticity' bug detector) ---")
    w(f"body decode/relay errors: {c['body_err']}")
    w(f"MITM relay drops:         {c['relay_drop']}")
    if egress_fail:
        codes = {"50": "Network down", "54": "reset by peer", "60": "timed out", "61": "conn refused"}
        w("egress NWConnection fails: " + ", ".join(
            f"{n}x POSIX {k}({codes.get(k,'?')})" for k, n in sorted(egress_fail.items())))
    if c["body_err"] > 0:
        w("body verdict:             !! response-body decode/relay errors — clients can see truncated/")
        w("                          aborted streams ('authenticity could not be verified'). See timeline.txt.")
    elif not evidence_complete:
        w("body verdict:             INCONCLUSIVE — log coverage or provider continuity is incomplete")
    else:
        w("body verdict:             GOOD — no body decode/relay errors")
    w("")
    w("--- freeze detector (liveness probe; sleep-wake excluded) ---")
    w(f"probes:                   {probe_total} (failures {probe_fail}, longest run {max_fail_run}, sleep-wake skipped {probe_skipped})")
    if probe_fail > 0:
        w(f"freeze verdict:           !! {probe_fail} probe failures — investigate nexus exhaustion / network blip")
    elif not evidence_complete:
        w("freeze verdict:           INCONCLUSIVE — probe coverage or provider continuity is incomplete")
    else:
        w("freeze verdict:           GOOD — proxy stayed live (no freeze)")
    w("")
    w(f"sleep markers: {c['sleep']}   wake markers: {c['wake']}   error/fault lines: {c['err']}")
    w(f"fanout active outcomes:   ok={fo_ok} non-2xx/err={fo_bad} (descriptive; top-up kills pollute codes)")
    w("")
    if phases:
        w("--- per-phase ---")
        w(f"{'phase':<14} {'peak_total':>10} {'ride':>5} {'bodyErr':>8} {'ticks':>6}")
        for name, sp, epe in phases:
            p = ph(name)
            w(f"{name:<14} {p['peak_total']:>10} {p['ride']:>5} "
              f"{p['body_err']:>8} {p['gauge']:>6}")
        w("(eviction deltas are intentionally not phase-attributed: reporting ticks can cross phases)")
    w("")
    w("see flow-counts.txt, timeline.txt, probe-timeline.txt, holders.log, leaks.txt")

with open(os.path.join(out, "evidence-status.tsv"), "w") as status:
    status.write(f"complete\t{1 if evidence_complete else 0}\n")
    status.write(f"passed\t{1 if run_passed else 0}\n")
    status.write(f"exit_code\t{run_result['exit_code']}\n")
    for issue in evidence_issues:
        status.write(f"issue\t{issue}\n")
    for failure in run_failures:
        status.write(f"failure\t{failure}\n")
PYEOF
else
  warn "python3 not found — falling back to grep"
  grep -oE 'live-flow counts[^"]*' "$OUT/system.ndjson" > "$OUT/flow-counts.txt" 2>/dev/null || true
  grep -iE 'flow pressure|drain backstop|force-tear|brotli error|drop MITM relay|system sleep|system wake' \
    "$OUT/system.ndjson" > "$OUT/timeline.txt" 2>/dev/null || true
  printf 'complete\t0\npassed\t0\nexit_code\t2\nissue\tpython3 unavailable\n' > "$OUT/evidence-status.tsv"
fi

# ── Bundle ────────────────────────────────────────────────────────────
hdr "done"
TARBALL="$OUT.tgz"
tar -czf "$TARBALL" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null \
  && say "tarball:   $TARBALL" || warn "could not create tarball"
say "dir:       $OUT"
echo
[[ -f "$OUT/extract-summary.txt" ]] && cat "$OUT/extract-summary.txt"
echo
hdr "hand me: $OUT  (or the tarball)"
EVIDENCE_COMPLETE="$(awk -F '\t' '$1 == "complete" { print $2; exit }' "$OUT/evidence-status.tsv" 2>/dev/null)"
RUN_PASSED="$(awk -F '\t' '$1 == "passed" { print $2; exit }' "$OUT/evidence-status.tsv" 2>/dev/null)"
if [[ "$EVIDENCE_COMPLETE" != 1 ]]; then
  warn "soak completed, but evidence is incomplete; see evidence-status.tsv"
  exit 2
fi
if [[ "$RUN_PASSED" != 1 ]]; then
  warn "soak evidence is complete, but one or more validation checks failed; see evidence-status.tsv"
  exit 1
fi
