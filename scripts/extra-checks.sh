#!/usr/bin/env bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

exit_code=0

# Make sure all examples are included in the rama book
for example in $(cd $SCRIPT_DIR/.. && find examples -type f -name '*.rs' -not -name 'mod.rs'); do
    echo "Checking $example..."
    if ! grep -qr "$example" docs/book; then
        echo "❌ Example $example, missing in rama book"
        exit_code=1
    else
        echo "✅ Example $example, found in rama book"
    fi
done

exit $exit_code