#!/usr/bin/env bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

exit_code=0

# Make sure all examples are included in the rama book
for example in $(cd $SCRIPT_DIR/.. && find examples/src -maxdepth 1 -type f -name '*.rs' -not -name 'mod.rs'); do
    echo "Checking $example..."
    if ! grep -qr "$example" docs/book; then
        echo "❌ Example $example, missing in rama book"
        exit_code=1
    elif ! grep -q "$(basename "$example" .rs)" examples/Cargo.toml; then
        echo "❌ Example "$(basename "$example" .rs)", missing in examples Cargo.toml"
        exit_code=1
    elif ! grep -q "./src/$(basename "$example")" examples/README.md; then
        echo "❌ Example "$(basename "$example" .rs)", missing in examples README.md"
        exit_code=1
    else
        echo "✅ Example $example, found in all expected locations"
    fi
done

# Make sure every example reserves its own unique port. By convention each
# example binds to a port in the 6xxxx range (referenced both in its doc
# comment and its bind call); two examples sharing one would collide when run
# together (CI, docs tests, local experimentation).
echo "Checking example port uniqueness..."
port_clash=0
ports_file=$(mktemp)
trap 'rm -f "$ports_file"' EXIT
for example in $(cd $SCRIPT_DIR/.. && find examples/src -maxdepth 1 -type f -name '*.rs' -not -name 'mod.rs'); do
    for port in $(cd $SCRIPT_DIR/.. && grep -hoE '6[0-9]{4}' "$example" | sort -u); do
        printf '%s %s\n' "$port" "$example" >> "$ports_file"
    done
done
if ! sort "$ports_file" | awk '
    $1 == last_port {
        if (!reported) {
            print "❌ Port " last_port " used by both " last_example " and " $2
            reported = 1
        } else {
            print "❌ Port " $1 " also used by " $2
        }
        clash = 1
        next
    }
    {
        last_port = $1
        last_example = $2
        reported = 0
    }
    END {
        exit clash ? 1 : 0
    }
'; then
    port_clash=1
    exit_code=1
fi
if [ "$port_clash" -eq 0 ]; then
    echo "✅ All examples use unique ports"
fi

# Examples should only import from the `rama` facade crate (plus tokio / a few
# others), never from the internal `rama_*` sub-crates, so users can copy-paste
# an example into a project that only depends on `rama`.
echo "Checking examples for rama_* imports..."
rama_import=0
for example in $(cd $SCRIPT_DIR/.. && find examples/src -maxdepth 1 -type f -name '*.rs' -not -name 'mod.rs'); do
    if (cd $SCRIPT_DIR/.. && grep -nE '^[[:space:]]*use[[:space:]]+rama_' "$example"); then
        echo "❌ Example $example imports from an internal rama_* crate (use the rama facade instead)"
        rama_import=1
        exit_code=1
    fi
done
if [ "$rama_import" -eq 0 ]; then
    echo "✅ No examples import from internal rama_* crates"
fi

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
