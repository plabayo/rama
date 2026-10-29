#!/usr/bin/env bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

exit_code=0

# An example is either a single `examples/src/<name>.rs` file, or an
# `examples/src/<name>/` directory grouping the files of one example
# (e.g. a server and a client sharing a service definition).

# Make sure all examples are included in the rama book
for example in $(cd $SCRIPT_DIR/.. && find examples/src -maxdepth 2 -type f -name '*.rs' -not -name 'mod.rs'); do
    echo "Checking $example..."
    if ! grep -qr "$example" docs/book; then
        echo "❌ Example $example, missing in rama book"
        exit_code=1
    elif ! grep -q "$(basename "$example" .rs)" examples/Cargo.toml; then
        echo "❌ Example "$(basename "$example" .rs)", missing in examples Cargo.toml"
        exit_code=1
    elif ! grep -q "./${example#examples/}" examples/README.md; then
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
for example in $(cd $SCRIPT_DIR/.. && find examples/src -mindepth 1 -maxdepth 1 \( -type d -o -name '*.rs' \) -not -name 'mod.rs'); do
    for port in $(cd $SCRIPT_DIR/.. && grep -rhoE '6[0-9]{4}' "$example" | sort -u); do
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
for example in $(cd $SCRIPT_DIR/.. && find examples/src -maxdepth 2 -type f -name '*.rs' -not -name 'mod.rs'); do
    if (cd $SCRIPT_DIR/.. && grep -nE '^[[:space:]]*use[[:space:]]+rama_' "$example"); then
        echo "❌ Example $example imports from an internal rama_* crate (use the rama facade instead)"
        rama_import=1
        exit_code=1
    fi
done
if [ "$rama_import" -eq 0 ]; then
    echo "✅ No examples import from internal rama_* crates"
fi

# Projects outside the workspace keep their own lock files; CI builds them with
# --locked, so a workspace dependency bump must refresh each of them too.
echo "Checking standalone project lock files..."
members=$(cd $SCRIPT_DIR/.. && cargo metadata --no-deps --format-version 1 \
    | grep -o '"manifest_path":"[^"]*"' | sed 's/^"manifest_path":"//; s/"$//')
for manifest in $(cd $SCRIPT_DIR/.. && git ls-files '*/Cargo.toml'); do
    if grep -qxF "$(cd $SCRIPT_DIR/.. && pwd)/$manifest" <<<"$members"; then
        continue
    fi
    dir=$(dirname "$manifest")
    while [ "$dir" != . ] && ! (cd $SCRIPT_DIR/.. && git ls-files --error-unmatch "$dir/Cargo.lock" >/dev/null 2>&1); do
        dir=$(dirname "$dir")
    done
    if [ "$dir" = . ]; then
        echo "❌ $manifest is outside the workspace without its own Cargo.lock"
        exit_code=1
    fi
done
for lockfile in $(cd $SCRIPT_DIR/.. && git ls-files '*/Cargo.lock'); do
    if (cd $SCRIPT_DIR/.. && cargo metadata --locked --format-version 1 \
        --manifest-path "$(dirname "$lockfile")/Cargo.toml" >/dev/null 2>&1); then
        echo "✅ $lockfile is up to date"
    else
        echo "❌ $lockfile is stale, run \`just update-deps\`"
        exit_code=1
    fi
done

exit $exit_code
