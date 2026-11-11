#!/usr/bin/env bash
set -euo pipefail

read -ra tool_entries <<< "${TOOLS:-}"
read -ra required_formulae <<< "${FORMULAE:-}"
if [[ ${#tool_entries[@]} -eq 0 && ${#required_formulae[@]} -eq 0 ]]; then
  echo 'brew-install: no tools or formulae given' >&2
  exit 1
fi
missing=()
if [[ ${#tool_entries[@]} -gt 0 ]]; then
  for entry in "${tool_entries[@]}"; do
    formula=${entry%%=*}
    tool=${entry#*=}
    if ! command -v "$tool" >/dev/null && ! brew list --versions "$formula" >/dev/null 2>&1; then
      missing+=("$formula")
    fi
  done
fi
# A command named openssl or postgres need not provide the required version or libraries.
if [[ ${#required_formulae[@]} -gt 0 ]]; then
  for formula in "${required_formulae[@]}"; do
    if ! brew list --versions "$formula" >/dev/null 2>&1; then
      missing+=("$formula")
    fi
  done
fi
if [[ ${#missing[@]} -eq 0 ]]; then
  echo 'brew-install: all dependencies already installed'
  exit 0
fi
for attempt in 1 2 3; do
  if brew install "${missing[@]}"; then
    exit 0
  fi
  echo "::warning::brew-install: attempt $attempt of 3 failed"
  if [[ "$attempt" -lt 3 ]]; then
    sleep 5
  fi
done
echo '::error::brew-install: could not install dependencies after 3 attempts'
exit 1
