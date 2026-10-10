#!/usr/bin/env bash
set -euo pipefail

apt_opts=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
apt_get() {
    local seconds=$1
    shift
    sudo env DEBIAN_FRONTEND=noninteractive timeout --kill-after=10 "$seconds" apt-get "${apt_opts[@]}" "$@"
}
for attempt in 1 2 3 4; do
    if apt_get 60 update && apt_get 90 install --yes --no-install-recommends --download-only postgresql; then
        apt_get 120 install --yes --no-install-recommends postgresql
        exit 0
    fi
    echo "::warning::apt-install: attempt $attempt of 4 failed"
    if [[ -f /etc/apt/apt-mirrors.txt ]]; then
        sudo sed -i '/azure\.archive\.ubuntu\.com/d' /etc/apt/apt-mirrors.txt
    fi
    sleep 5
done
echo "::error::apt-install: could not fetch packages after 4 attempts"
exit 1
