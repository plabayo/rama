#!/usr/bin/env bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

exit_code=0

# docs.rs builds use the package metadata from the published crate, not this
# workspace's local `.cargo/config.toml`. Any crate whose docs.rs all-features
# build enables `dial9` must pass `--cfg tokio_unstable` via rustc-args, because
# `dial9-tokio-telemetry` depends on Tokio's unstable runtime APIs.
echo "Checking docs.rs metadata for dial9 crates..."
docs_rs_metadata_missing=0
for manifest in $(cd $SCRIPT_DIR/.. && find . -name Cargo.toml -not -path './target/*' | sort); do
    if ! (cd $SCRIPT_DIR/.. && grep -q '^\[package.metadata.docs.rs\]' "$manifest"); then
        continue
    fi
    if ! (cd $SCRIPT_DIR/.. && grep -q '^dial9[[:space:]]*=' "$manifest"); then
        continue
    fi
    if ! (cd $SCRIPT_DIR/.. && awk '
        /^\[package\.metadata\.docs\.rs\]/ {
            in_docs_rs = 1
            next
        }
        /^\[/ {
            in_docs_rs = 0
        }
        in_docs_rs && /^all-features[[:space:]]*=[[:space:]]*true/ {
            all_features = 1
        }
        in_docs_rs && /^rustc-args[[:space:]]*=/ && /tokio_unstable/ {
            tokio_unstable = 1
        }
        END {
            exit all_features && !tokio_unstable ? 1 : 0
        }
    ' "$manifest"); then
        echo "❌ $manifest enables dial9 in docs.rs all-features builds but is missing rustc-args = [\"--cfg\", \"tokio_unstable\"]"
        docs_rs_metadata_missing=1
        exit_code=1
    fi
done
if [ "$docs_rs_metadata_missing" -eq 0 ]; then
    echo "✅ docs.rs metadata covers all dial9 all-features builds"
fi

exit $exit_code
