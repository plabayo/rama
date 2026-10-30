#!/usr/bin/env bash
# Run the opt-in lossy-link Swift tests with dummynet loss and delay on one
# loopback port. Only dnctl/pfctl run as root; the shaping is removed on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

port="${RAMA_NE_LOSSY_LINK_PORT:-47391}"
bytes="${RAMA_NE_LOSSY_LINK_BYTES:-67108864}"
plr="${RAMA_NE_LOSSY_LINK_PLR:-0.02}"
delay_ms="${RAMA_NE_LOSSY_LINK_DELAY_MS:-30}"
pipe=47391
anchor="com.apple/rama-lossy-link"
token=""

# shellcheck disable=SC2329 # invoked by the EXIT trap
teardown() {
    sudo pfctl -a "$anchor" -F all >/dev/null 2>&1 || true
    sudo dnctl pipe delete "$pipe" >/dev/null 2>&1 || true
    if [[ -n "$token" ]]; then
        sudo pfctl -X "$token" >/dev/null 2>&1 || true
    fi
}
trap teardown EXIT

sudo dnctl pipe "$pipe" config plr "$plr" delay "$delay_ms"
# Shape both directions of the test port; each loopback packet passes lo0 out once.
printf 'dummynet out quick on lo0 proto tcp from any to any port %s pipe %s\n%s\n' \
    "$port" "$pipe" \
    "dummynet out quick on lo0 proto tcp from any port $port to any pipe $pipe" |
    sudo pfctl -a "$anchor" -f -
token="$(sudo pfctl -E 2>&1 | awk '/Token/ { print $3 }')"

swift_test() {
    RAMA_NE_LOSSY_LINK_TESTS=1 \
    RAMA_NE_LOSSY_LINK_PORT="$port" \
    RAMA_NE_LOSSY_LINK_BYTES="$bytes" \
        swift test --traits PrivateNetworkProxyControl -c release -Xswiftc -DRAMA_TESTING \
            -Xlinker -L"$(pwd)/tproxy_rs/target/debug" \
            -Xlinker -lrama_tproxy_example -Xlinker -lz \
            -Xlinker -framework -Xlinker NetworkExtension \
            -Xlinker -framework -Xlinker SystemConfiguration \
            "$@"
}

# System-wide TCP counters (root shows the real values); other loopback traffic adds noise.
tcp_counters() {
    sudo netstat -s -p tcp | awk '
        /data packets? \(.*\) retransmitted/ { print "retransmitted_packets", $1 }
        /discarded for bad checksum/ { print "bad_checksum_discards", $1 }
        /^\t[0-9]+ retransmit timeouts?$/ { print "retransmit_timeouts", $1 }
        /out-of-order packets? \(/ { print "out_of_order_packets", $1 }'
}

tests=(
    testNativeConnectionDeliversIntactStreamOverLossyLink
    testNativeConnectionRootWritesAfterCompletion
    testSwiftConnectionDeliversIntactStreamOverLossyLink
    testSwiftConnectionIgnoresRootWritesAfterCompletion
)

status=0
for test in "${tests[@]}"; do
    before="$(tcp_counters)"
    # Only the first run builds; `swift build` cannot enable the testable imports other targets need.
    swift_test --filter "LossyLinkTransferTests/$test" "$@" || status=1
    after="$(tcp_counters)"
    echo "== $test TCP counter deltas"
    join <(sort <<<"$before") <(sort <<<"$after") | awk '{ printf "   %s %d\n", $1, $3 - $2 }'
done
exit "$status"
