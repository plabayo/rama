#!/usr/bin/env bash
set -euo pipefail

# add-apt-repository first queries api.launchpad.net and fetches a signing key.
# Neither is needed for this known archive: retain its key here so all network
# I/O goes through apt-install's bounded download retries and infra-failure gate.
# Published fingerprint (also checked when updating this file):
# https://launchpad.net/~wireshark-dev/+archive/ubuntu/stable
# A2E402B85A4B70CD78D8A3D9D875551314ECA0F0
# shellcheck source=/dev/null
source /etc/os-release
if [[ "$ID" != ubuntu || -z "${VERSION_CODENAME:-}" ]]; then
  echo 'wireshark-source: requires an Ubuntu codename' >&2
  exit 1
fi
sudo install -D -m 0644 "$ACTION_PATH/wireshark.asc" /etc/apt/keyrings/wireshark.asc
# Scope the key to this archive rather than adding it to apt's global trust.
cat <<SOURCES | sudo tee /etc/apt/sources.list.d/wireshark.sources >/dev/null
Types: deb
URIs: https://ppa.launchpadcontent.net/wireshark-dev/stable/ubuntu/
Suites: $VERSION_CODENAME
Components: main
Signed-By: /etc/apt/keyrings/wireshark.asc
SOURCES
