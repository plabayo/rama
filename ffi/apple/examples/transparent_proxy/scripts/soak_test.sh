#!/usr/bin/env bash
# soak_test.sh — one-shot live soak for the rama Apple NE transparent proxy.
#
# Drives the stress traffic generator + real-world downloads + an optional
# sleep/wake cycle, captures everything that actually tells us whether the
# lifetime/leak/wake fixes hold, and bundles it into a single artifact dir
# (+ tarball) to hand back for inspection.
#
# What it captures:
#   - system.ndjson        full debug-level os_log stream for the sysext
#   - flow-counts.txt       the 60s "live-flow counts tcp=N udp=M" gauge
#                           timeline — the PRIMARY leak signal (must trend
#                           back toward 0 after the idle tail)
#   - timeline.txt          lifecycle / sleep / wake / watchdog / error lines
#   - extract-summary.txt   peak vs final flow counts, watchdog/backstop/error
#                           tallies, sleep+wake markers
#   - stress/               per-worker logs + preflight/postflight vmmap+heap
#   - final-mem.txt         ps/vmmap/heap snapshot AFTER the idle tail (did
#                           memory actually settle back down?)
#   - leaks.txt             `leaks` pass on the live sysext process
#   - dial9-traces/         per-flow egress dial traces
#
# Usage (run from anywhere):
#   bash scripts/soak_test.sh
#
# Requires: the dev proxy already enabled in the container app (or pass
# DO_INSTALL=1 to build+install+open it first), and sudo.
#
# Env knobs (all optional):
#   REPO            repo root. Default: /Users/glendc/code/github.com/plabayo/rama
#   OUT             artifact dir. Default: ~/rama-tproxy-soak/<timestamp>
#   DO_INSTALL      1 = `just install-tproxy-dev` first (rebuild+reinstall+open).
#                   Default 0 (assume already enabled).
#   STRESS_SECONDS  stress duration. Default 300.
#   CONCURRENCY     parallel-pool size. Default 24.
#   SKIP_SLEEP      1 = skip the sleep/wake phase. Default 0 (runs it).
#   IDLE_TAIL       idle seconds after traffic so the 60s gauge ticks at least
#                   once with no live flows. Default 95.
#   WAKE_DL_BYTES   bytes for the sleep/wake mid-flight download. Default 1 GiB.
#   REAL_DL_BYTES   bytes for the steady real-world download. Default 256 MiB.

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────────
REPO="${REPO:-/Users/glendc/code/github.com/plabayo/rama}"
EXAMPLE_DIR="$REPO/ffi/apple/examples/transparent_proxy"
STRESS_SH="$EXAMPLE_DIR/scripts/stress_traffic.sh"
PROVIDER_BUNDLE="org.ramaproxy.example.tproxy.dev.provider"
SUBSYSTEM_PREFIX="org.ramaproxy.example.tproxy"
HTTPS_PROBE="https://http-test.ramaproxy.org/method"
DIAL9_DIR="/var/root/Library/Application Support/rama/tproxy/dial9-traces"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-$HOME/rama-tproxy-soak/$STAMP}"
DO_INSTALL="${DO_INSTALL:-0}"
STRESS_SECONDS="${STRESS_SECONDS:-300}"
CONCURRENCY="${CONCURRENCY:-24}"
SKIP_SLEEP="${SKIP_SLEEP:-0}"
IDLE_TAIL="${IDLE_TAIL:-95}"
WAKE_DL_BYTES="${WAKE_DL_BYTES:-1073741824}"   # 1 GiB
REAL_DL_BYTES="${REAL_DL_BYTES:-268435456}"    # 256 MiB

# Pattern that uniquely identifies THIS run's log-stream process (includes the
# subsystem so pkill can't collateral-hit an unrelated `log stream`). The
# stdbuf prefix forces line-buffering as cheap insurance against a low-volume
# tail sitting in an unflushed block buffer (`log` flushes per-event here, but
# stdbuf costs nothing); empty when stdbuf is absent.
LOG_MATCH='log stream --level debug.*ramaproxy'
LOGBUF=""; command -v stdbuf >/dev/null 2>&1 && LOGBUF="stdbuf -oL"

# ── Pretty output ─────────────────────────────────────────────────────
if [[ -t 1 ]] && tput colors >/dev/null 2>&1; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; RESET=$'\e[0m'; RED=$'\e[31m'; GREEN=$'\e[32m'; YEL=$'\e[33m'
else
  BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""; YEL=""
fi
say()  { printf '%s[soak]%s %s\n' "$DIM" "$RESET" "$*"; }
hdr()  { printf '\n%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$BOLD" "$*" "$RESET"; }
warn() { printf '%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$YEL" "$*" "$RESET"; }
die()  { printf '%s[soak]%s %s%s%s\n' "$DIM" "$RESET" "$RED" "$*" "$RESET" >&2; exit 1; }

# Fail loud on a non-numeric knob rather than a confusing partial run.
for _n in STRESS_SECONDS CONCURRENCY IDLE_TAIL WAKE_DL_BYTES REAL_DL_BYTES; do
  _v="${!_n}"
  [[ "$_v" =~ ^[0-9]+$ ]] || die "$_n must be a non-negative integer (got '$_v')"
done

# ── Teardown ──────────────────────────────────────────────────────────
LOG_STREAM_STARTED=0
SUDO_KEEPALIVE_PID=""
cleanup() {
  [[ -n "$SUDO_KEEPALIVE_PID" ]] && kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
  if (( LOG_STREAM_STARTED )); then
    sudo pkill -f "$LOG_MATCH" 2>/dev/null || true
  fi
  # Any stray curl background workers from this script (BSD xargs has no -r,
  # so guard the empty case ourselves).
  local _j; _j="$(jobs -p 2>/dev/null)"
  [[ -n "$_j" ]] && kill $_j 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Preconditions ─────────────────────────────────────────────────────
hdr "rama transparent proxy soak"
[[ -x "$(command -v curl)" ]] || die "curl not found"
[[ -f "$STRESS_SH" ]] || die "stress script not found at $STRESS_SH (is REPO correct?)"
mkdir -p "$OUT" || die "cannot create OUT=$OUT"
say "artifacts:   $OUT"
say "stress:      ${STRESS_SECONDS}s @ concurrency $CONCURRENCY"
say "sleep/wake:  $([[ "$SKIP_SLEEP" == 1 ]] && echo skipped || echo enabled)"
say "idle tail:   ${IDLE_TAIL}s"

# Cache sudo once, then keep it warm in the background (the run + the
# 5s monitor + post-wake leaks all need it non-interactively).
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
PROBE_CODE="$(curl -s -o /dev/null --max-time 15 -w '%{http_code}' "$HTTPS_PROBE" 2>/dev/null || true)"
if [[ ! "$PROBE_CODE" =~ ^2 ]]; then
  die "probe got '$PROBE_CODE' against $HTTPS_PROBE — proxy not intercepting, sysext down, or no network. Enable the proxy (or DO_INSTALL=1) and retry."
fi
say "${GREEN}probe ok ($PROBE_CODE) — traffic is flowing through the proxy${RESET}"

PID="$(pgrep -f "$PROVIDER_BUNDLE" | head -1 || true)"
[[ -n "$PID" ]] || die "could not find the sysext process ($PROVIDER_BUNDLE). Is it enabled?"
say "sysext pid:  $PID"

# ── Start live log capture (debug level — the gauge is debug) ──────────
hdr "starting log capture"
sudo $LOGBUF log stream --level debug --style ndjson \
  --predicate "subsystem BEGINSWITH \"$SUBSYSTEM_PREFIX\"" \
  > "$OUT/system.ndjson" 2>/dev/null &
LOG_STREAM_STARTED=1
sleep 2
if ! pgrep -f "$LOG_MATCH" >/dev/null; then
  warn "log stream may not have started — continuing, but system.ndjson could be empty"
fi
say "streaming → $OUT/system.ndjson"

# ── Phase 1: stress traffic (preflight/postflight + 5s monitor) ───────
hdr "phase 1/4 — stress traffic (${STRESS_SECONDS}s)"
STRESS_DURATION="$STRESS_SECONDS" \
STRESS_CONCURRENCY="$CONCURRENCY" \
STRESS_MONITOR_PID="$PID" \
STRESS_LOG_DIR="$OUT/stress" \
STRESS_SKIP_LIVENESS=1 \
  bash "$STRESS_SH" | tee "$OUT/stress-run.txt" || warn "stress run returned nonzero"

# ── Phase 2: steady real-world download ───────────────────────────────
hdr "phase 2/4 — real-world download (${REAL_DL_BYTES} bytes)"
curl -L -s -o /dev/null --max-time 240 \
  -w 'real-download: code=%{http_code} size=%{size_download} avg=%{speed_download}B/s time=%{time_total}s\n' \
  "https://speed.cloudflare.com/__down?bytes=$REAL_DL_BYTES" 2>&1 \
  | tee "$OUT/real-download.txt" || warn "real download failed (non-fatal)"

# ── Phase 3: sleep / wake (the original-bug scenario) ─────────────────
if [[ "$SKIP_SLEEP" == 1 || ! -t 0 ]]; then
  hdr "phase 3/4 — sleep/wake (SKIPPED)"
  [[ ! -t 0 && "$SKIP_SLEEP" != 1 ]] && warn "no TTY — skipping sleep/wake (needs a manual wake)"
else
  hdr "phase 3/4 — sleep/wake"
  warn "This will put the Mac to SLEEP. A download will be in flight."
  warn "WAKE THE MAC MANUALLY (keypress / lid) ~45s after it sleeps."
  printf '%s[soak]%s press Enter to start (or Ctrl-C to abort)... ' "$DIM" "$RESET"
  read -r _

  say "starting 1 GiB download in the background..."
  ( curl -L -s -o /dev/null --max-time 600 \
      -w 'wake-download: code=%{http_code} size=%{size_download} time=%{time_total}s\n' \
      "https://speed.cloudflare.com/__down?bytes=$WAKE_DL_BYTES" \
      > "$OUT/wake-download.txt" 2>&1 ) &
  WAKE_DL_PID=$!
  sleep 8

  warn ">>> SLEEPING NOW — wake the Mac manually in ~45s <<<"
  sudo pmset sleepnow || warn "pmset sleepnow failed"

  # Execution resumes here once the Mac is awake again.
  sleep 5
  sudo -v 2>/dev/null || true   # refresh sudo after the sleep gap
  say "awake — probing connectivity..."
  for i in 1 2 3; do
    WCODE="$(curl -s -o /dev/null --max-time 15 -w '%{http_code}' "$HTTPS_PROBE" 2>/dev/null || true)"
    printf 'post-wake probe %d: %s\n' "$i" "$WCODE" | tee -a "$OUT/post-wake.txt"
    [[ "$WCODE" =~ ^2 ]] && break
    sleep 3
  done
  if [[ "${WCODE:-}" =~ ^2 ]]; then
    say "${GREEN}post-wake: traffic recovered ($WCODE)${RESET}"
  else
    warn "post-wake: traffic did NOT recover (last code '$WCODE') — this is the bug we're hunting"
  fi
  # Give the in-flight download a moment to resume/finish/fail, then reap.
  sleep 5
  kill "$WAKE_DL_PID" 2>/dev/null || true
  [[ -f "$OUT/wake-download.txt" ]] && cat "$OUT/wake-download.txt"
fi

# ── Phase 4: idle tail (let the 60s gauge tick empty) ─────────────────
hdr "phase 4/4 — idle ${IDLE_TAIL}s (waiting for flows to drain to 0)"
for ((t=IDLE_TAIL; t>0; t-=5)); do printf '\r[soak] idle %3ds remaining' "$t"; sleep 5; done
printf '\r%-40s\r' ' '

# ── Final memory snapshot (re-resolve pid; detect a restart) ──────────
hdr "final memory snapshot"
PID2="$(pgrep -f "$PROVIDER_BUNDLE" | head -1 || true)"
if [[ -z "$PID2" ]]; then
  warn "sysext process is GONE after the run (crashed or uninstalled)"
elif [[ "$PID2" != "$PID" ]]; then
  warn "sysext RESTARTED during the run: $PID → $PID2 (watchdog churn / crash — itself a signal)"
fi
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
sudo pkill -f "$LOG_MATCH" 2>/dev/null || true
LOG_STREAM_STARTED=0
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
  "$PYX" - "$OUT" <<'PYEOF'
import json, os, re, sys
out = sys.argv[1]
nd = os.path.join(out, "system.ndjson")
rows = []
try:
    with open(nd, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            rows.append((o.get("timestamp", ""), o.get("eventMessage", ""), o.get("messageType", "")))
except FileNotFoundError:
    print("no system.ndjson")
    sys.exit(0)

gauge_re = re.compile(r"live-flow counts tcp=(\d+) udp=(\d+)")
life_re = re.compile(
    r"(startProxy|stopProxy|system sleep|system wake|engine created|engine detached|"
    r"wake|watchdog:|stuck|drain backstop|force-dropped|force-tearing|timed out|"
    r"not viable|not satisfied|reset)", re.I)

with open(os.path.join(out, "flow-counts.txt"), "w") as g, \
     open(os.path.join(out, "timeline.txt"), "w") as t:
    peak_tcp = peak_udp = 0
    last_tcp = last_udp = None
    n_gauge = 0
    n_watchdog = n_backstop = n_err = n_sleep = n_wake = 0
    for ts, msg, mtype in rows:
        m = gauge_re.search(msg)
        if m:
            tcp, udp = int(m.group(1)), int(m.group(2))
            g.write(f"{ts}  tcp={tcp} udp={udp}\n")
            peak_tcp = max(peak_tcp, tcp); peak_udp = max(peak_udp, udp)
            last_tcp, last_udp = tcp, udp
            n_gauge += 1
        if mtype in ("Error", "Fault") or life_re.search(msg):
            t.write(f"{ts}  [{mtype or 'Default'}]  {msg}\n")
            ml = msg.lower()
            if "watchdog:" in ml: n_watchdog += 1
            if "backstop" in ml: n_backstop += 1
            if mtype in ("Error", "Fault"): n_err += 1
            if "system sleep" in ml: n_sleep += 1
            if "system wake" in ml: n_wake += 1

    with open(os.path.join(out, "extract-summary.txt"), "w") as s:
        def w(line=""):
            print(line); s.write(line + "\n")
        w("=== soak extract summary ===")
        w(f"ndjson rows parsed:     {len(rows)}")
        w(f"flow-count gauge ticks: {n_gauge}")
        w(f"peak flows:             tcp={peak_tcp} udp={peak_udp}")
        if last_tcp is None:
            w("final flows:            (no gauge tick captured — was capture running 60s+?)")
        else:
            w(f"final flows:            tcp={last_tcp} udp={last_udp}")
            verdict = "GOOD — drained to 0" if (last_tcp == 0 and last_udp == 0) \
                else "!! flows did NOT drain to 0 — possible leak"
            w(f"leak verdict:           {verdict}")
        w(f"sleep markers:          {n_sleep}")
        w(f"wake markers:           {n_wake}")
        w(f"watchdog force-teardowns: {n_watchdog}")
        w(f"drain-backstop fires:   {n_backstop}")
        w(f"error/fault lines:      {n_err}")
        w("")
        w("see flow-counts.txt (gauge timeline) and timeline.txt (lifecycle/errors)")
PYEOF
else
  warn "python3 not found — falling back to grep (no timestamps/summary)"
  grep -oE 'live-flow counts tcp=[0-9]+ udp=[0-9]+' "$OUT/system.ndjson" > "$OUT/flow-counts.txt" 2>/dev/null || true
  grep -iE 'startProxy|stopProxy|system sleep|system wake|watchdog:|backstop|force-|timed out|not viable|not satisfied' \
    "$OUT/system.ndjson" > "$OUT/timeline.txt" 2>/dev/null || true
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
