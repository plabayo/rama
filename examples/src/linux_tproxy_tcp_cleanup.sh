#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "linux_tproxy_tcp_cleanup.sh only supports Linux" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "run this script as root (for example via sudo)" >&2
  exit 1
fi

FWMARK="${FWMARK:-1}"
ROUTE_TABLE="${ROUTE_TABLE:-100}"
NFT_TABLE="${NFT_TABLE:-rama_tproxy_tcp}"

if ! command -v ip >/dev/null 2>&1; then
  echo "'ip' command not found" >&2
  exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
  echo "'nft' command not found" >&2
  exit 1
fi

nft delete table inet "${NFT_TABLE}" 2>/dev/null || true
ip rule del fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" 2>/dev/null || true
ip route flush table "${ROUTE_TABLE}" 2>/dev/null || true

cat <<EOF
removed Linux TPROXY example rules:
  fwmark: ${FWMARK}
  route table: ${ROUTE_TABLE}
  nft table: inet ${NFT_TABLE}
EOF
