#!/usr/bin/env bash
#
# geoip_sync.sh — fetch the free IP-geolocation databases used by the rama
# ip/echo/fp services and roll them out onto each service's persistent Fly.io
# volume.
#
# The databases are an *enrichment*: the services run fine without them. They
# are MaxMind GeoLite2 (City + ASN) and IP2Location LITE (DB11), both in MMDB
# format, served side-by-side so each lookup can be compared per source.
#
# ---------------------------------------------------------------------------
# Required credentials (free accounts — see rama-fp/infra/README.md)
#
#   MAXMIND_ACCOUNT_ID    MaxMind account id    } https://www.maxmind.com/en/geolite2/signup
#   MAXMIND_LICENSE_KEY   MaxMind license key   }  -> "Manage License Keys"
#
#   IP2LOCATION_TOKEN     IP2Location download token  https://lite.ip2location.com
#                                                      -> account "Download" page
#
# Fly commands additionally need `fly auth login` (or FLY_API_TOKEN set).
#
# ---------------------------------------------------------------------------
# Usage
#
#   geoip_sync.sh download [DIR]   download + extract the .mmdb files into DIR
#                                  (default: ./.geoip) — use this for local testing
#
#   geoip_sync.sh rollout          first-time / full rollout: per app, in
#                                  parallel — ensure one 'geoip' volume per
#                                  machine, deploy the mount, then push the DBs
#
#   geoip_sync.sh sync             data refresh: push the DBs to every machine of
#                                  every app, in parallel (mount must already be
#                                  deployed — use `rollout` first)
#
# Every Fly operation is retried with jittered backoff, because flyctl shares a
# local agent that can crash ("concurrent map writes") under heavy parallelism.
#
# Optional overrides (env):
#   GEOIP_DIR             staging dir                    (default: ./.geoip)
#   GEOIP_SKIP_DOWNLOAD   reuse existing files in DIR    (default: unset = download)
#   FLY_APPS              space-separated app list       (default: the 5 geo apps)
#   FLY_VOLUME            volume name                    (default: geoip)
#   FLY_REGION           region for created volumes      (default: fra)
#   FLY_VOLUME_SIZE_GB   size of created volumes         (default: 1)
#   VOLUME_MOUNT         mount path on the machine       (default: /geoip)
#   IP2LOCATION_CODE     IP2Location LITE file code      (default: DB11LITEMMDB)
#                        ^ the MMDB file already covers IPv4 + IPv6; confirm the
#                          exact code on your IP2Location Download page
#   RETRY_MAX            attempts per Fly op             (default: 8)
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$SCRIPT_DIR/../deployments"

GEOIP_DIR="${GEOIP_DIR:-./.geoip}"
FLY_APPS="${FLY_APPS:-rama-ipv4 rama-ipv6 rama-fp rama-fp-h1 rama-echo}"
FLY_VOLUME="${FLY_VOLUME:-geoip}"
FLY_REGION="${FLY_REGION:-fra}"
FLY_VOLUME_SIZE_GB="${FLY_VOLUME_SIZE_GB:-1}"
VOLUME_MOUNT="${VOLUME_MOUNT:-/geoip}"
IP2LOCATION_CODE="${IP2LOCATION_CODE:-DB11LITEMMDB}"
RETRY_MAX="${RETRY_MAX:-8}"

# stable on-disk names the services reference via RAMA_IP_GEO_DB
GEOLITE2_CITY="GeoLite2-City.mmdb"
GEOLITE2_ASN="GeoLite2-ASN.mmdb"
IP2LOCATION_DB="IP2Location-LITE-DB11.mmdb"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() { local c; for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "missing required command: $c"; done; }

# retry CMD... up to RETRY_MAX times with jittered backoff; absorbs flyctl's
# shared-agent crashes under parallelism and transient SSH-readiness lag
retry() {
  local n=1
  while true; do
    "$@" && return 0
    if [ "$n" -ge "$RETRY_MAX" ]; then return 1; fi
    sleep $(( n * 3 + (RANDOM % 6) ))
    n=$((n + 1))
  done
}

# ---------------------------------------------------------------------------
# download
# ---------------------------------------------------------------------------

# extract the single .mmdb out of an archive ($1) into $GEOIP_DIR/$2
extract_mmdb() {
  local archive="$1" dest="$2" tmp found
  tmp="$(mktemp -d)"
  case "$archive" in
    *.tar.gz|*.tgz) tar -xzf "$archive" -C "$tmp" ;;
    *.zip)          unzip -q -o "$archive" -d "$tmp" ;;
    *)              die "unknown archive type: $archive" ;;
  esac
  found="$(find "$tmp" -type f -iname '*.mmdb' | head -n1)"
  [ -n "$found" ] || die "no .mmdb found inside $archive"
  mv "$found" "$GEOIP_DIR/$dest"
  rm -rf "$tmp"
}

download_maxmind() {
  : "${MAXMIND_ACCOUNT_ID:?set MAXMIND_ACCOUNT_ID (see header)}"
  : "${MAXMIND_LICENSE_KEY:?set MAXMIND_LICENSE_KEY (see header)}"
  local base="https://download.maxmind.com/geoip/databases"
  local spec edition dest archive
  for spec in "GeoLite2-City:$GEOLITE2_CITY" "GeoLite2-ASN:$GEOLITE2_ASN"; do
    edition="${spec%%:*}"
    dest="${spec#*:}"
    archive="$(mktemp).tar.gz"
    log "downloading MaxMind $edition"
    # since 2024 MaxMind authenticates downloads with account id + license key
    if curl -fsSL -u "${MAXMIND_ACCOUNT_ID}:${MAXMIND_LICENSE_KEY}" \
         "${base}/${edition}/download?suffix=tar.gz" -o "$archive"; then
      extract_mmdb "$archive" "$dest"
    elif [ -f "$GEOIP_DIR/$dest" ]; then
      warn "MaxMind $edition download failed; reusing existing $dest"
    else
      die "MaxMind download failed for $edition (check credentials)"
    fi
    rm -f "$archive"
  done
}

download_ip2location() {
  : "${IP2LOCATION_TOKEN:?set IP2LOCATION_TOKEN (see header)}"
  local archive
  archive="$(mktemp).zip"
  log "downloading IP2Location LITE ${IP2LOCATION_CODE}"
  # the endpoint returns a short text error (not a zip) on a bad token/code or
  # when the per-token rate limit (5 downloads / 24h) is hit
  if curl -fsSL "https://www.ip2location.com/download?token=${IP2LOCATION_TOKEN}&file=${IP2LOCATION_CODE}" \
       -o "$archive" && unzip -tq "$archive" >/dev/null 2>&1; then
    extract_mmdb "$archive" "$IP2LOCATION_DB"
  elif [ -f "$GEOIP_DIR/$IP2LOCATION_DB" ]; then
    warn "IP2Location download failed ('$(head -c 120 "$archive" 2>/dev/null)'); reusing existing $IP2LOCATION_DB"
  else
    die "IP2Location download failed ('$(head -c 120 "$archive" 2>/dev/null)') — verify IP2LOCATION_TOKEN/IP2LOCATION_CODE"
  fi
  rm -f "$archive"
}

ensure_downloaded() {
  require_cmd curl tar unzip
  mkdir -p "$GEOIP_DIR"
  if [ -n "${GEOIP_SKIP_DOWNLOAD:-}" ] \
     && [ -f "$GEOIP_DIR/$GEOLITE2_CITY" ] \
     && [ -f "$GEOIP_DIR/$GEOLITE2_ASN" ] \
     && [ -f "$GEOIP_DIR/$IP2LOCATION_DB" ]; then
    log "reusing existing databases in $GEOIP_DIR (GEOIP_SKIP_DOWNLOAD set)"
    return
  fi
  download_maxmind
  download_ip2location
}

cmd_download() {
  GEOIP_DIR="${1:-$GEOIP_DIR}"
  ensure_downloaded
  log "databases ready in ${GEOIP_DIR}:"
  ls -lh "$GEOIP_DIR"/*.mmdb >&2
  cat >&2 <<EOF

local test — point a service at them and run it:

  export RAMA_IP_GEO_DB="geolite2=${GEOIP_DIR}/${GEOLITE2_CITY}+${GEOIP_DIR}/${GEOLITE2_ASN};ip2location=${GEOIP_DIR}/${IP2LOCATION_DB}"
  cargo run -p rama-cli -- serve ip --bind 127.0.0.1:8080
  # then: curl -s -H 'Accept: application/json' localhost:8080/ | jq .geo
EOF
}

# ---------------------------------------------------------------------------
# fly: provision + deploy + push, phased and concurrency-capped
#
# Volume creation is concurrency-safe, but `fly deploy` / `fly ssh` share a
# local agent that crashes under heavy parallelism, so deploys run at a low cap
# and every Fly op is retried. Pushes (the slow part: ~158MB per machine) run
# at a higher cap to saturate throughput without melting the agent.
# ---------------------------------------------------------------------------

DEPLOY_CONCURRENCY="${DEPLOY_CONCURRENCY:-2}"
PUSH_CONCURRENCY="${PUSH_CONCURRENCY:-6}"
FAIL_DIR=""

machine_ids() {
  fly machine list -a "$1" --json 2>/dev/null \
    | grep -o '"id":[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/'
}

# ensure there is one geoip volume per machine of app $1 (create the deficit)
provision_app() {
  local app="$1" want have need
  want="$(machine_ids "$app" | grep -c . || true)"
  have="$(fly volumes list -a "$app" 2>/dev/null | grep -cw "$FLY_VOLUME" || true)"
  need=$(( want - have ))
  if [ "$need" -gt 0 ]; then
    log "[$app] creating $need '$FLY_VOLUME' volume(s) (have $have, machines $want)"
    retry fly volumes create "$FLY_VOLUME" -a "$app" -r "$FLY_REGION" \
      -s "$FLY_VOLUME_SIZE_GB" -n "$need" -y >/dev/null \
      || { warn "[$app] volume create failed"; return 1; }
  else
    log "[$app] volumes ok ($have for $want machine(s))"
  fi
}

# deploy app $1 using its checked-in fly.toml (rama-ipv4 -> deployments/ipv4)
deploy_app() {
  local app="$1" cfg="$DEPLOY_DIR/${1#rama-}/fly.toml"
  [ -f "$cfg" ] || { warn "[$app] no fly.toml at $cfg"; return 1; }
  log "[$app] deploying"
  retry fly deploy -c "$cfg" -a "$app" --yes \
    || { warn "[$app] deploy failed after $RETRY_MAX attempts"; return 1; }
}

# push all 3 dbs to one machine; arg = "app:machine_id".
# NOTE: failures must `return 1`, not `die`/`exit` — these run inside a
# parallel_map subshell whose `|| marker` only fires on a non-zero return.
push_one() {
  local app="${1%%:*}" mid="${1##*:}" f n
  for f in "$GEOLITE2_CITY" "$GEOLITE2_ASN" "$IP2LOCATION_DB"; do
    log "[$app/$mid] put $f"
    n=1
    while true; do
      # Fly autostop is driven by service traffic, not SSH, so a machine can be
      # reaped mid-sync (and a running machine's idle timer is NOT reset by our
      # session) — re-wake it before every attempt. Volumes persist regardless.
      fly machine start "$mid" -a "$app" >/dev/null 2>&1 || true
      # flyctl sftp refuses to overwrite, so drop any prior/partial copy first
      fly ssh console -a "$app" --machine "$mid" -C "rm -f $VOLUME_MOUNT/$f" >/dev/null 2>&1 || true
      fly ssh sftp put "$GEOIP_DIR/$f" "$VOLUME_MOUNT/$f" -a "$app" --machine "$mid" && break
      if [ "$n" -ge "$RETRY_MAX" ]; then warn "[$app/$mid] upload failed: $f"; return 1; fi
      sleep $(( n * 2 + (RANDOM % 5) ))
      n=$((n + 1))
    done
  done
}

# every "app:machine_id" pair across FLY_APPS, one per line
all_machine_jobs() {
  local app mid
  for app in $FLY_APPS; do
    for mid in $(machine_ids "$app"); do printf '%s:%s\n' "$app" "$mid"; done
  done
}

# run FN over each remaining arg, at most $cap concurrently; bash-3.2 safe
# (batched, no `wait -n`). Per-item failures are recorded as marker files.
parallel_map() {
  local cap="$1" fn="$2"; shift 2
  local item active=0 tag
  for item in "$@"; do
    tag="$(printf '%s' "$item" | tr '/:' '__')"
    ( "$fn" "$item" || : >"$FAIL_DIR/$tag" ) >"/tmp/geoip_${tag}.log" 2>&1 &
    active=$((active + 1))
    if [ "$active" -ge "$cap" ]; then wait; active=0; fi
  done
  wait
}

# die if any marker files were written during the last phase
check_phase() {
  local phase="$1" fails
  fails="$(find "$FAIL_DIR" -type f 2>/dev/null)"
  if [ -n "$fails" ]; then
    warn "$phase failed for:"; printf '%s\n' "$fails" | sed 's#.*/##;s/^/  - /' >&2
    die "$phase failed (per-item logs in /tmp/geoip_*.log)"
  fi
  log "$phase ok"
}

cmd_rollout() {
  require_cmd curl tar unzip fly
  ensure_downloaded
  FAIL_DIR="$(mktemp -d)"
  # word-splitting of the app / "app:machine" lists into items is intentional
  # shellcheck disable=SC2046,SC2086
  {
    log "provisioning volumes: $FLY_APPS"
    parallel_map 8 provision_app $FLY_APPS;                       check_phase provision
    log "deploying mounts (cap $DEPLOY_CONCURRENCY): $FLY_APPS"
    parallel_map "$DEPLOY_CONCURRENCY" deploy_app $FLY_APPS;      check_phase deploy
    log "pushing databases to all machines (cap $PUSH_CONCURRENCY)"
    parallel_map "$PUSH_CONCURRENCY" push_one $(all_machine_jobs); check_phase push
  }
  log "rollout complete for: $FLY_APPS"
}

cmd_sync() {
  require_cmd curl tar unzip fly
  ensure_downloaded
  FAIL_DIR="$(mktemp -d)"
  log "pushing databases to all machines (cap $PUSH_CONCURRENCY): $FLY_APPS"
  # word-splitting of the "app:machine" list into items is intentional
  # shellcheck disable=SC2046
  parallel_map "$PUSH_CONCURRENCY" push_one $(all_machine_jobs); check_phase push
  log "sync complete"
}

main() {
  case "${1:-}" in
    download) shift; cmd_download "${1:-}";;
    rollout)  cmd_rollout;;
    sync)     cmd_sync;;
    *) sed -n '2,40p' "$0"; exit 2;;
  esac
}

main "$@"
