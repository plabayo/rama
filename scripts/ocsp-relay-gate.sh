#!/usr/bin/env bash
#
# MITM OCSP-stapling gate.
#
# Stands up the `mitm_ocsp_relay_gate` example (a local upstream TLS+HTTP server
# behind the boring TlsMitmRelay proxy) across three upstream revocation
# profiles and asserts, with real external clients, that:
#
#   upstream advertises | curl (plain) | curl --cert-status | openssl -status
#   --------------------+--------------+--------------------+-----------------
#   OCSP responder      | trusts       | trusts             | successful/good
#   CRL distribution pt | trusts       | trusts             | successful/good
#   nothing             | trusts       | FAILS (no staple)  | (no response)
#
# The `none` row is the negative control: a genuinely revocation-less upstream
# where a strict client must NOT see a staple — proving the gate isn't a
# rubber stamp. Chain trust holds in all three.
#
# `curl --cert-status` needs an OpenSSL/GnuTLS-backed curl (not SecureTransport).
# On macOS that means a brew curl; the system one is skipped automatically.
# Set OCSP_GATE_REQUIRE=1 (CI) to turn "no suitable curl" into a hard failure.
# Overrides: OCSP_GATE_CURL, OCSP_GATE_OPENSSL.

set -euo pipefail
cd "$(dirname "$0")/.."

REQUIRE="${OCSP_GATE_REQUIRE:-0}"
OPENSSL="${OCSP_GATE_OPENSSL:-openssl}"

# Pick a curl that actually enforces --cert-status (OpenSSL/GnuTLS/wolfSSL
# backends). SecureTransport/LibreSSL builds list the flag but don't verify.
find_curl() {
    local c ver
    for c in "${OCSP_GATE_CURL:-}" curl \
        /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl; do
        [ -n "$c" ] || continue
        ver="$(command -v "$c" >/dev/null 2>&1 && "$c" -V 2>/dev/null)" || continue
        echo "$ver" | grep -qiE 'openssl|gnutls|wolfssl|boringssl' || continue
        echo "$ver" | grep -qi 'securetransport' && continue
        command -v "$c" 2>/dev/null || echo "$c"
        return 0
    done
    return 1
}

if ! CURL="$(find_curl)"; then
    msg="no curl with --cert-status support found (need an OpenSSL/GnuTLS-backed curl)"
    if [ "$REQUIRE" = "1" ]; then echo "FATAL: $msg" >&2; exit 1; fi
    echo "SKIP: $msg" >&2
    exit 0
fi
echo "curl:    $CURL"
echo "openssl: $OPENSSL"

cargo build --example mitm_ocsp_relay_gate --features=http-full,boring
BIN=target/debug/examples/mitm_ocsp_relay_gate

WORK="$(mktemp -d)"
PROXY_PID=""
cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

run_scenario() {
    local kind="$1"
    local ca="$WORK/ca-$kind.pem"
    local out="$WORK/out-$kind.log"

    "$BIN" --upstream-revocation "$kind" --ca-out "$ca" >"$out" 2>&1 &
    PROXY_PID=$!

    local addr=""
    for _ in $(seq 1 100); do
        addr="$(sed -n 's/^READY proxy=\([^ ]*\) .*/\1/p' "$out" 2>/dev/null)"
        [ -n "$addr" ] && break
        kill -0 "$PROXY_PID" 2>/dev/null || { cat "$out"; fail "$kind: harness exited early"; }
        sleep 0.1
    done
    [ -n "$addr" ] || { cat "$out"; fail "$kind: harness never became READY"; }

    local port="${addr##*:}"
    local resolve="upstream.example:$port:127.0.0.1"
    local url="https://upstream.example:$port/"
    echo "[$kind] proxy=$addr"

    # Chain trust must hold in every scenario.
    "$CURL" -sS --cacert "$ca" --resolve "$resolve" "$url" >/dev/null \
        || fail "$kind: plain curl (chain trust) failed"

    local status
    status="$("$OPENSSL" s_client -connect "127.0.0.1:$port" \
        -servername upstream.example -status -CAfile "$ca" </dev/null 2>/dev/null || true)"

    case "$kind" in
    ocsp | crl)
        "$CURL" -sS --cert-status --cacert "$ca" --resolve "$resolve" "$url" >/dev/null \
            || fail "$kind: curl --cert-status rejected the stapled leaf"
        echo "$status" | grep -q "OCSP Response Status: successful" \
            || fail "$kind: openssl did not report a successful OCSP response"
        echo "$status" | grep -q "Cert Status: good" \
            || fail "$kind: openssl did not report 'Cert Status: good'"
        echo "[$kind] OK — staple present, valid, trusted by curl --cert-status"
        ;;
    none)
        if "$CURL" -sS --cert-status --cacert "$ca" --resolve "$resolve" "$url" >/dev/null 2>&1; then
            fail "none: curl --cert-status unexpectedly succeeded (a staple was sent?)"
        fi
        echo "[none] OK — no staple (parity), chain still trusted, --cert-status correctly fails"
        ;;
    esac

    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
}

# Real crates.io through the CONNECT proxy: mirror the live origin cert + staple,
# then prove a strict client (curl --cert-status) and cargo both accept it.
run_connect() {
    local ca="$WORK/ca-connect.pem"
    local out="$WORK/out-connect.log"

    "$BIN" --connect --ca-out "$ca" >"$out" 2>&1 &
    PROXY_PID=$!

    local addr=""
    for _ in $(seq 1 100); do
        addr="$(sed -n 's/^READY proxy=\([^ ]*\) .*/\1/p' "$out" 2>/dev/null)"
        [ -n "$addr" ] && break
        kill -0 "$PROXY_PID" 2>/dev/null || { cat "$out"; fail "connect: harness exited early"; }
        sleep 0.1
    done
    [ -n "$addr" ] || { cat "$out"; fail "connect: harness never became READY"; }
    local proxy="http://$addr"
    echo "[connect] proxy=$addr -> real crates.io"

    "$CURL" -sS --cert-status --proxy "$proxy" --cacert "$ca" \
        -o /dev/null https://index.crates.io/config.json \
        || fail "connect: curl --cert-status rejected the mirrored crates.io leaf"
    echo "[connect] OK - curl --cert-status trusts the stapled crates.io mirror"

    local proj="$WORK/cargo-probe"
    mkdir -p "$proj/src"
    : >"$proj/src/lib.rs"
    printf '[package]\nname = "gate-probe"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\nitoa = "1"\n' >"$proj/Cargo.toml"
    CARGO_HOME="$WORK/cargo-home" \
        CARGO_HTTP_PROXY="$proxy" \
        CARGO_HTTP_CAINFO="$ca" \
        CARGO_HTTP_CHECK_REVOKE=true \
        cargo generate-lockfile --manifest-path "$proj/Cargo.toml" \
        || fail "connect: cargo failed to fetch crates.io through the MITM"
    grep -q 'name = "itoa"' "$proj/Cargo.lock" \
        || fail "connect: cargo did not resolve itoa through the MITM"
    echo "[connect] OK - cargo fetched crates.io through the MITM (CA trusted, staple OK)"

    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
}

for kind in ocsp crl none; do run_scenario "$kind"; done

# Real-crates.io leg needs network; CI always has it, local dev may not.
if "$CURL" -sS --max-time 15 -o /dev/null https://index.crates.io/config.json 2>/dev/null; then
    run_connect
else
    msg="cannot reach index.crates.io (no network?); skipping real-crates.io checks"
    [ "$REQUIRE" = "1" ] && fail "$msg"
    echo "SKIP: $msg" >&2
fi

echo "ALL OCSP RELAY GATE SCENARIOS PASSED"
