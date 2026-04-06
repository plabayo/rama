#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "linux_tproxy_tcp_setup.sh only supports Linux" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "run this script as root (for example via sudo)" >&2
  exit 1
fi

PORT="${PORT:-62052}"
INTERCEPT_PORT="${INTERCEPT_PORT:-80}"
FWMARK="${FWMARK:-1}"
ROUTE_TABLE="${ROUTE_TABLE:-100}"
NFT_TABLE="${NFT_TABLE:-rama_tproxy_tcp}"
PROXY_UID="${PROXY_UID:-0}"

if ! command -v ip >/dev/null 2>&1; then
  echo "'ip' command not found" >&2
  exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
  echo "'nft' command not found" >&2
  exit 1
fi

ip rule del fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" 2>/dev/null || true
ip rule add fwmark "${FWMARK}" lookup "${ROUTE_TABLE}"
ip route replace local 0.0.0.0/0 dev lo table "${ROUTE_TABLE}"

nft delete table inet "${NFT_TABLE}" 2>/dev/null || true
nft add table inet "${NFT_TABLE}"
nft "add chain inet ${NFT_TABLE} output { type route hook output priority mangle; }"
nft "add chain inet ${NFT_TABLE} prerouting { type filter hook prerouting priority mangle; }"
nft add rule inet "${NFT_TABLE}" output \
  counter \
  ip daddr != 127.0.0.0/8 \
  meta skuid != "${PROXY_UID}" \
  tcp dport "${INTERCEPT_PORT}" \
  meta mark set "${FWMARK}"
nft add rule inet "${NFT_TABLE}" prerouting \
  counter \
  meta mark "${FWMARK}" \
  tcp dport "${INTERCEPT_PORT}" \
  tproxy to :"${PORT}" \
  meta mark set "${FWMARK}"

cat <<EOF
installed Linux TPROXY example rules:
  listen port: ${PORT}
  intercept tcp dport: ${INTERCEPT_PORT}
  fwmark: ${FWMARK}
  route table: ${ROUTE_TABLE}
  nft table: inet ${NFT_TABLE}
  exempt proxy uid: ${PROXY_UID}

undo with:
  sudo ./examples/linux_tproxy_tcp_cleanup.sh
EOF
