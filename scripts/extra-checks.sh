#!/usr/bin/env bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

exit_code=0

# Make sure all examples are included in the rama book
for example in $(cd $SCRIPT_DIR/.. && find examples -maxdepth 1 -type f -name '*.rs' -not -name 'mod.rs'); do
    echo "Checking $example..."
    if ! grep -qr "$example" docs/book; then
        echo "❌ Example $example, missing in rama book"
        exit_code=1
    elif ! grep -q "$(basename "$example" .rs)" Cargo.toml; then
        echo "❌ Example "$(basename "$example" .rs)", missing in workspace Cargo.toml"
        exit_code=1
    elif ! grep -q "./$(basename "$example")" examples/README.md; then
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
declare -A port_owner
port_clash=0
for example in $(cd $SCRIPT_DIR/.. && find examples -maxdepth 1 -type f -name '*.rs' -not -name 'mod.rs'); do
    for port in $(cd $SCRIPT_DIR/.. && grep -hoE '6[0-9]{4}' "$example" | sort -u); do
        if [ -n "${port_owner[$port]}" ]; then
            echo "❌ Port $port used by both ${port_owner[$port]} and $example"
            port_clash=1
            exit_code=1
        else
            port_owner[$port]=$example
        fi
    done
done
if [ "$port_clash" -eq 0 ]; then
    echo "✅ All examples use unique ports"
fi

exit $exit_code
