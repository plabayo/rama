#!/usr/bin/env bash

# Run tests with isolated crypto providers. A workspace-wide invocation unifies
# features and can silently select another provider through a dependency.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

backend=${1:-all}
if [ "$#" -gt 0 ]; then
    shift
fi

case "$backend" in
    all) backends=(rustcrypto ring aws-lc boring) ;;
    rustcrypto|ring|aws-lc|boring) backends=("$backend") ;;
    *)
        echo "usage: $0 [all|rustcrypto|ring|aws-lc|boring] [nextest arguments...]" >&2
        exit 2
        ;;
esac

for backend in "${backends[@]}"; do
    cargo_args=(--locked --no-default-features -p rama-crypto)
    case "$backend" in
        rustcrypto) cargo_args+=(-p rama-quic) ;;
        ring|aws-lc)
            cargo_args+=(-p rama-tls -p rama-tls-rustls -p rama-quic)
            cargo_args+=(--features "rama-crypto/$backend,rama-crypto/native-certs,rama-tls/http,rama-tls-rustls/http,rama-tls-rustls/$backend,rama-quic/rustls,rama-quic/$backend")
            # ACME requires aws-lc; selecting it in the ring run would enable both.
            if [ "$backend" = aws-lc ]; then
                cargo_args+=(-p rama-tls-acme)
            fi
            ;;
        boring)
            cargo_args+=(-p rama-tls -p rama-tls-boring)
            cargo_args+=(--features "rama-crypto/boring,rama-crypto/inspect,rama-crypto/native-certs,rama-tls/http,rama-tls/inspect,rama-tls-boring/http,rama-tls-boring/compression,rama-tls-boring/ua")
            ;;
    esac

    echo "Running crypto tests with $backend"
    cargo nextest run "${cargo_args[@]}" "$@"
done
