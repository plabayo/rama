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

exit $exit_code
