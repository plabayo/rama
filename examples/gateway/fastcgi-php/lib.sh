#!/usr/bin/env bash
# Shared helpers for the rama-fastcgi-php example scripts.
#
# Sourced by `gateway/run.sh` and `migration/run.sh`.
#
# Each script runs in one of two modes:
#
#   test  (default)  Boot php-fpm + rama, run curl/jq assertions, tear down,
#                    exit 0 on success. This is what CI invokes.
#   run              Boot php-fpm + rama and keep them running so you can
#                    poke at the gateway with curl, your browser, etc. Tear
#                    down cleanly on Ctrl-C (or any signal).
#
# Pass the mode as the first argument:
#     ./gateway/run.sh              # test mode
#     ./gateway/run.sh test         # test mode (explicit)
#     ./gateway/run.sh run          # interactive mode
set -euo pipefail

# Repo root: the directory containing the top-level Cargo.toml.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

# Pretty logging
log()  { printf '\033[1;34m[fastcgi-php]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[fastcgi-php]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[fastcgi-php]\033[0m FAIL: %s\n' "$*" >&2; exit 1; }

# Parse the optional run/test mode argument. Sets the global $MODE to one of
# "test" or "run".
parse_mode() {
    case "${1:-test}" in
        test|--test|"") MODE=test ;;
        run|--run)      MODE=run ;;
        -h|--help)
            cat <<USAGE >&2
Usage: $0 [test|run]

  test  (default)  Boot the stack, run jq/curl assertions, exit. Used by CI.
  run              Boot the stack and keep it running until you Ctrl-C.
USAGE
            exit 0
            ;;
        *) fail "unknown mode '${1}', expected 'test' or 'run'" ;;
    esac
}

# Print the README-style hint a user wants after the stack is up in run
# mode: where to curl, where to find logs, how to stop.
run_mode_hint() {
    local base="$1"
    cat <<HINT >&2

────────────────────────────────────────────────────────────────────────────
  rama-fastcgi-php example is now running.

  Try it:
      curl -k $base/
      curl -k $base/api/users
      curl -k -X POST $base/submit --data-binary 'hello=world'

  Workdir (php-fpm + rama logs, php-fpm.conf): $WORKDIR

  Press Ctrl-C to stop both processes and clean up.
────────────────────────────────────────────────────────────────────────────

HINT
}

# Wait until a signal arrives or every passed child PID has exited. Used in
# run mode. Relies on the script's own EXIT trap for cleanup.
#
# Implementation: poll the children with `kill -0`. We deliberately avoid
# `wait -n` because it's bash 4.3+ and macOS still ships bash 3.2.
wait_for_signal() {
    local pids=("$@")
    while true; do
        local alive=0
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                alive=1
                break
            fi
        done
        if (( alive == 0 )); then
            return 0
        fi
        sleep 0.5
    done
}

# Locate the php-fpm binary, or exit 77 (CI's "skip" code) with an
# explanatory message if it's not installed.
#
# Probes (in order):
#   1. `$PHP_FPM_BIN` (explicit override).
#   2. Anything on $PATH named php-fpm or php-fpm<version>.
#   3. Homebrew's daemon dirs — Brew installs daemons under `sbin/` and that
#      dir is often *not* on $PATH even after `brew shellenv`. The most
#      common reason "brew install php" appears to "not include php-fpm".
#   4. Common Linux package layouts (`/usr/sbin`).
find_php_fpm() {
    local versioned=(php-fpm8.4 php-fpm8.3 php-fpm8.2 php-fpm8.1 php-fpm8.0 php-fpm7.4)

    if [[ -n "${PHP_FPM_BIN:-}" && -x "${PHP_FPM_BIN}" ]]; then
        printf '%s\n' "$PHP_FPM_BIN"
        return 0
    fi

    for candidate in php-fpm "${versioned[@]}"; do
        if command -v "$candidate" >/dev/null 2>&1; then
            command -v "$candidate"
            return 0
        fi
    done

    local search_dirs=(
        /opt/homebrew/sbin    # macOS Apple Silicon Homebrew
        /opt/homebrew/bin
        /usr/local/sbin       # macOS Intel Homebrew, also some Linux
        /usr/local/bin
        /usr/sbin             # most Linux distros
    )
    for dir in "${search_dirs[@]}"; do
        for candidate in php-fpm "${versioned[@]}"; do
            if [[ -x "$dir/$candidate" ]]; then
                printf '%s\n' "$dir/$candidate"
                return 0
            fi
        done
    done

    warn "php-fpm not found."
    warn "  - Debian/Ubuntu:  apt-get install -y php-fpm"
    warn "  - macOS Homebrew: brew install php   (it installs /opt/homebrew/sbin/php-fpm,"
    warn "skipping"
    exit 77
}

require_jq() {
    if ! command -v jq >/dev/null 2>&1; then
        warn "jq not found in PATH — skipping (install: apt-get install jq)"
        exit 77
    fi
}

require_curl() {
    if ! command -v curl >/dev/null 2>&1; then
        fail "curl not found in PATH"
    fi
}

# Generate a minimal php-fpm config file in $1 (the example's work dir)
# listening on the address $2 (e.g. "127.0.0.1:9000" or "/abs/path/to/sock").
write_fpm_conf() {
    local workdir="$1"
    local listen="$2"
    local pid_file="$workdir/php-fpm.pid"
    cat >"$workdir/php-fpm.conf" <<EOF
; Auto-generated by rama-fastcgi-php example harness — do not edit.
[global]
pid = $pid_file
error_log = $workdir/php-fpm.err.log
daemonize = no

[www]
listen = $listen
listen.allowed_clients = 127.0.0.1
pm = static
pm.max_children = 2
catch_workers_output = yes
clear_env = no
EOF
    echo "$workdir/php-fpm.conf"
}

# Wait until $1 (URL or file path) is ready. Honours \$RAMA_FASTCGI_PHP_TIMEOUT_S.
wait_for_tcp() {
    local host="$1" port="$2"
    local timeout="${RAMA_FASTCGI_PHP_TIMEOUT_S:-15}"
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if (echo > "/dev/tcp/$host/$port") 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    fail "timeout waiting for tcp $host:$port"
}

wait_for_unix_socket() {
    local sock="$1"
    local timeout="${RAMA_FASTCGI_PHP_TIMEOUT_S:-15}"
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if [[ -S "$sock" ]]; then
            return 0
        fi
        sleep 0.1
    done
    fail "timeout waiting for unix socket $sock"
}

# Echo the JSON response from $1 (curl args) and assert that piping it
# through jq filter $2 yields the exact string $3.
assert_jq_eq() {
    local url="$1" jq_filter="$2" expected="$3"
    shift 3
    local body
    body="$(curl --silent --show-error --fail-with-body --max-time 10 -k "$@" "$url")" \
        || fail "curl failed for $url: $body"
    local actual
    actual="$(printf '%s' "$body" | jq -r "$jq_filter")"
    if [[ "$actual" != "$expected" ]]; then
        printf '%s\n' "$body" >&2
        fail "assertion failed: jq '$jq_filter' on $url — expected '$expected', got '$actual'"
    fi
    log "  OK  $url  →  $jq_filter == $expected"
}
