# JSONPath Compliance Test Suite

This Compliance Test Suite may be used to test implementations of JSONPath
[RFC 9535](https://www.rfc-editor.org/rfc/rfc9535).

See [cts.json](cts.json) for the Compliance Test Suite.

See the [Contributor Guide](https://github.com/jsonpath-standard/jsonpath-compliance-test-suite/blob/main/CONTRIBUTING.md) if you'd like to submit changes.

To use this test suite, it's recommended you embed this repository as a git submodule of your implementation.

### Conventions

Basic conventions around source file formatting are captured in the `.editorconfig` file.
Many editors support that file natively. Others (such as VS code) require a plugin, see https://editorconfig.org/.

### Contributing

To add or modify a test suite, edit the corresponding file in the `tests` directory.
To generate `cts.json`, run the `build.sh` located in the root folder. Do not modify `cts.json` directly.
More details are available in the [Contributor Guide](https://github.com/jsonpath-standard/jsonpath-compliance-test-suite/blob/main/CONTRIBUTING.md).

### Non-determinism

Where the spec allows non-deterministic results for a given testcase, the testcase should specify an array of all the valid results (each of which is itself an array representing the resultant nodelist from the query) in the "results" member (and should not specify a "result" member).
