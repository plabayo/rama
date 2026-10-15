# Real-browser HTTP/1 profile round trip

From the repository root:

```sh
just test-browser-profile-h1 /absolute/path/to/new-evidence-directory
```

The command builds the debug CLI, starts a disposable PostgreSQL container and an
fp listener on loopback, drives an isolated headless Chrome navigation to `/report`,
exports the resulting profile, and replays it with `rama send --emulate`. A second,
separate database collects the replay. The built-in `rama ua compare --literal
--allow-partial-coverage` checks retained capture membership, and tshark independently
checks the request's header names, casing, order, and values on the wire. Host values
are normalized only after verifying each request names its own listener.

This is a partial browser-matrix proof: plaintext HTTP/1.1 navigation with Chrome.
It does not establish TLS, H2, H3, Firefox, Safari, other request flows, generated
values, or distribution fidelity. The reference page can collect additional flows;
`comparison.json` explicitly lists those not exercised by the single replay. The
command must not be used to claim complete reference coverage.

Requirements:

- Docker running and a locally cached `postgres:17-alpine` image. The harness resolves
  the local image ID and never pulls an image implicitly.
- Chrome/Chromium, Python 3, Node with its built-in WebSocket API, and tshark/dumpcap.
- Permission to capture the loopback interface (`lo0` on macOS, `lo` on Linux).

For custom locations or a prebuilt optimized CLI:

```sh
python3 examples/tests/browser_profile/chrome_h1.py \
  --rama target/release/rama --chrome /path/to/chrome \
  --interface lo --output /absolute/path/to/new-evidence-directory
```

The output directory must not already exist. It contains packet captures, reference
and replay archives, both comparison reports, and process logs. No key log is needed
for plaintext HTTP. The browser profile is deleted when the command finishes. The
harness terminates its owned child processes and removes its named disposable
container on success, failure, timeout, or interruption. It overrides inherited
fp/database settings and removes storage cookies; it never connects to an existing
database or changes a running browser profile. No transparent proxy is enabled.

The local tests cover exact tuple matching, authority checks, database isolation,
and cleanup after failure. Run them with normal and optimized Python:

```sh
python3 -m unittest discover -s examples/tests/browser_profile -p 'test_*.py'
python3 -O -m unittest discover -s examples/tests/browser_profile -p 'test_*.py'
```
