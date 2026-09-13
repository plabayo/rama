# QUIC interop runner

This standalone Rust endpoint runs against the independent
[QUIC interop runner](https://github.com/quic-interop/quic-interop-runner).
The default gate requires **24 explicit successes**: Rama in both roles against
quic-go and ngtcp2 for `handshake`, `transfer`, `retry`, `multiplexing`, `longrtt`,
and `transferloss`. Upstream checks packet traces and downloaded bytes through
its simulator. Missing, failed, unsupported, duplicate, or malformed outcomes
and nonzero runner exits fail the gate. Every expected Rama qlog must also be
a complete JSON sequence containing `quic:connection_closed`; validation streams
records and retains their counts in the manifest.

## Run

Install Docker Engine **>=28.1** with Linux containers, Docker Compose **>=2.36**, host
**tshark >=4.5**, Python **>=3.10** with venv/pip, Git, Bash, and **OpenSSL >=3**.
The Docker daemon must allow IPv6 bridges and `NET_ADMIN`/`NET_RAW`; Linux may
need `sudo modprobe ip6table_filter`. GitHub, PyPI, Docker Hub, and GHCR access
is required initially. The wrapper checks versions and refuses occupied
simulator subnets: `193.167.0.0/24`, `193.167.100.0/24`,
`fd00:cafe:cafe:0::/64`, and `fd00:cafe:cafe:100::/64`.
Serialize runs on the same Docker daemon. If your default Python is older,
set `PYTHON=/path/to/python3.12` (the default executable is `python3`). On
macOS, install `openssl@3` and prepend `$(brew --prefix openssl@3)/bin` to
`PATH`; the system LibreSSL cannot generate the upstream test certificates.

From the repository root:

```sh
just test-quic-interop-runner
# Reuse an already built image:
just test-quic-interop-runner --skip-build --image glendc/rama-quic-interop:local
# Shorter diagnostic subset; this does NOT satisfy the full default gate:
just test-quic-interop-runner --skip-build --tests handshake,transfer,retry
```

The default builds `linux/amd64`; on Apple silicon, pass `--platform linux/arm64`
to build and test natively. This command publishes nothing. CI publishes
`glendc/rama-quic-interop` for amd64/arm64 as `edge` on main and `latest` plus
the release tag for releases.

## Scope and artifacts

The image selects `rama-quic-interop-client` or `rama-quic-interop-server` via
`ROLE`. Endpoints speak QUIC v1 / HTTP/0.9 with ALPN `hq-interop`. The client
fetches space-separated `REQUESTS` URLs into `/downloads`; the server serves
`/www` on UDP 443 with `/certs/cert.pem` and `/certs/priv.key`. Both honor
`SSLKEYLOGFILE` and `QLOGDIR`. Recognized endpoint cases are `handshake`,
`transfer`, `retry`, and `multiconnect`; unsupported cases exit 127. Upstream
maps `multiplexing`/`transferloss` to `transfer`, and `longrtt` to `handshake`.
HTTP/3, resumption, 0-RTT, migration, v2, and forced cipher/key-update cases
are outside this initial gate.

Artifacts remain in `target/quic-interop/<timestamp>-<run-id>/`, or a **new**
directory passed with `--artifacts /absolute/path`. They include both role JSON
reports and console logs, packet captures, TLS secrets, qlogs, failed downloads,
a final container-log snapshot, cleanup logs, the effective upstream checkout,
and a manifest
with selected scope, gate results, runtime versions, source status, and image
IDs/digests. Setup failures and interruptions also retain their manifest.

`runner.lock.json` pins upstream, simulator, cleanup, and peer revisions;
`requirements.lock` pins Python dependencies including transitives. Upstream
randomizes data/loss, so packet captures vary. The adapter only scopes log
copying to this run's Compose project and pins temporary-file cleanup. It
leaves upstream protocol checks intact. Shutdown terminates the runner's
process group on interruption or a 30-minute role timeout before removing only this project's containers/networks; it
never prunes Docker or deletes another run's resources. Both endpoints have an
explicit ten-second Compose shutdown grace period to drain and flush qlogs.

## Validation and CI

```sh
python3 -m unittest discover -s rama-quic/e2e/interop-runner -p 'test_*.py'
```

CI needs a Linux runner with the prerequisites above (Ubuntu's stock tshark
may need upgrading). Build the image, invoke `run.sh --skip-build` with
`--artifacts "$RUNNER_TEMP/quic-interop"`, and upload that directory with `if: always()`.
When upgrading pins, review upstream topology, case mappings, JSON schema,
and adapter compatibility; rerun the gate tests and full 24-outcome matrix.
