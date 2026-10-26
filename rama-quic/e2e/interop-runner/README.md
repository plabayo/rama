# QUIC interop runner

This standalone Rust endpoint runs against the independent
[QUIC interop runner](https://github.com/quic-interop/quic-interop-runner).
The default gate executes all **22 active upstream testcase families**, in both
roles against quic-go and ngtcp2: 88 attempted outcomes per backend. CI runs
all three backends, partitioned into `core`, `paths`, and `loss` groups in
`runner.lock.json`. The union of those groups is tested against the full inventory.
Upstream checks packet traces and downloaded bytes through its simulator.
Missing, unexplained failed, unexpected unsupported, duplicate, or malformed outcomes and
unexpected runner exits fail the gate. Every successful Rama qlog must also be
a complete JSON sequence containing `quic:connection_closed`; validation streams
records and retains their counts in the manifest. A nonempty Rama TLS keylog
is also required. Unsupported outcomes are reported separately from successes.
The narrowly verified preferred-address classifications below are also counted
separately; the raw upstream JSON is never rewritten.

## Run

Run the Docker harness from Linux, macOS, or WSL2; it uses POSIX process groups.
The QA recipe below also runs on native Windows.

Install Docker Engine **>=28.1** with Linux containers, Docker Compose **>=2.36**, host
**tshark >=4.5**, uv, Git, Bash, and **OpenSSL >=3**.
The Docker daemon must allow IPv6 bridges and `NET_ADMIN`/`NET_RAW`; Linux may
need `sudo modprobe ip6table_filter`. GitHub, PyPI, Docker Hub, and GHCR access
is required initially. The wrapper checks versions and refuses occupied
simulator subnets: `193.167.0.0/24`, `193.167.100.0/24`,
`fd00:cafe:cafe:0::/64`, and `fd00:cafe:cafe:100::/64`.
Serialize runs on the same Docker daemon. The just recipes run Python in the
locked uv environment of `e2e/aioquic-interop`. On
macOS, install `openssl@3` and prepend `$(brew --prefix openssl@3)/bin` to
`PATH`; the system LibreSSL cannot generate the upstream test certificates.

From the repository root:

```sh
just rama-quic/test-interop-runner
# Reuse an already built image:
just rama-quic/test-interop-runner --skip-build --image glendc/rama-quic-interop:local
# Shorter diagnostic subset; this does NOT satisfy the full default gate:
just rama-quic/test-interop-runner --skip-build --tests handshake,transfer,retry
# Run one of the CI groups:
just rama-quic/test-interop-runner --group loss
# Explicit TLS override (the image and wrapper default to Boring):
just rama-quic/test-interop-runner --backend rustls-ring
```

The default builds `linux/amd64`; on Apple silicon, pass `--platform linux/arm64`
to build and test natively. This command publishes nothing. CI publishes
`glendc/rama-quic-interop` for amd64/arm64 as `edge` on main and `latest` plus
the release tag for releases.

## Scope and artifacts

The image selects `rama-quic-interop-client` or `rama-quic-interop-server` via
`ROLE`. Endpoints speak HTTP/0.9 with ALPN `hq-interop`, or HTTP/3 with ALPN `h3`
for the `http3` case. The client
fetches space-separated `REQUESTS` URLs into `/downloads`; the server serves
`/www` on UDP 443 with `/certs/cert.pem` and `/certs/priv.key`. Both honor
`SSLKEYLOGFILE` and `QLOGDIR`. Recognized endpoint cases are `handshake`,
`transfer`, `retry`, `multiconnect`, `resumption`, `zerortt`, `ecn`, `v2`, and
`http3`, plus client `keyupdate` and server `connectionmigration`/`chacha20`.
Unsupported role/case pairs exit 127 before accessing mounts or sockets. Upstream
maps many scenarios to `transfer`, and `longrtt` to `handshake`. Its
`handshakeloss`/`handshakecorruption` scenarios request 50 separate connections.
In `v2` the client starts in QUIC v1 offering v2 and the server moves the connection
to v2 (RFC 9368 compatible version negotiation); a client built on Rustls cannot
change version mid-handshake and reports the case unsupported, so the gate requires
it from Boring clients and from servers of every backend. HTTP/3 transfers stream
file bodies with bounded concurrency and validate response status and version.
Resumption requires an actually resumed second handshake; 0-RTT additionally
requires early-data acceptance. Only the 0-RTT client disables MTU discovery:
upstream counts padded MTU probes as 1-RTT request bytes. Key-update clients
initiate an update; the server receives upstream's `transfer` testcase and must
respond to the peer's update. Preferred-address servers bind an alternate port;
clients use the normal transfer path's default migration policy. Upstream verifies
path challenges/responses for address/port rebinding and observes the preferred
address switch for connection migration. ECN is checked from packet markings and
ACK-ECN frames, not inferred from a successful transfer.

The default simulator run uses default transport windows. Separate local endpoint
tests use small windows and assert nonzero MAX_DATA and MAX_STREAM_DATA counters,
including 130 streams and a 2 MiB transfer. Local preferred-address tests require
a probe and the actual remote-address change.

### Explicit capability gaps

The pinned upstream preferred-address checker requires the first server packet
on the new path to contain PATH_CHALLENGE. A server may first answer the client's
probe with PATH_RESPONSE. `check_migration.py` independently checks both decrypted
captures, one v1 handshake, both advertised endpoints and their CID, fresh DCID,
the first response and every preferred-path challenge, validation before traffic, exact 2 MiB
file bytes, and Docker exits. Only reviewed peer image digests can qualify as
`checker-incompatible`. The pinned quic-go client never attempts the advertised
path; it can qualify as `peer-did-not-exercise` only with zero preferred-path packets
in both captures and a verified transfer. Neither classification counts as an
upstream success. The upstream process returns the failed-case count; a completion
sidecar must prove it returned normally, and that count must exactly match the
verified classifications. Crashes, signals and unexpected counts remain failures.
Any failed evidence check remains a hard failure. This is an
independent verifier; upstream's checks remain unchanged. Its migration verdict
was cross-checked against upstream with only the first-packet rule relaxed.
The pinned NgTCP2 client can ignore one backup-path challenge after migrating;
the verifier records it separately and requires both captures to place its send
and arrival after the client's first non-probing packet on the preferred path.
An unanswered preferred-path challenge or an earlier previous-path challenge fails.
To repeat that read-only comparison against a retained run, use its locked Python
environment (printed during setup):

```sh
target/quic-interop/venv-<version>-<lock-hash>/bin/python \
  rama-quic/e2e/interop-runner/crosscheck_migration.py /path/to/artifacts --role client
```

Use `--role server` for the other direction. This diagnostic alters only the
checker loaded in its own Python process, leaving the upstream checkout and
recorded results intact. Set `RUST_LOG` when running the main wrapper to forward
targeted Rust tracing into the endpoint containers.

The same upstream checker reads only the first PATH_RESPONSE per packet. Rama
answers batched challenges in arrival order, with all tokens included; local wire
tests check that ordering and bounded amplification.

| Endpoint | Case | Reason |
| --- | --- | --- |
| Rama client, all backends | `chacha20` | `TlsOptions` has no TLS 1.3 cipher-suite restriction; this case requires offering only ChaCha20. Rama servers accept it. |
| Rama client, Rustls | `v2` | Compatible version switching during a handshake currently requires Boring. Rustls servers support the case. |
| Pinned quic-go, both roles | `v2`, `ecn` | The shipped interop executable rejects these testcase names. |
| Pinned quic-go server | `connectionmigration` | The shipped server executable rejects this testcase name. |

These exceptions tolerate **only an explicit exit 127 from the declared side**.
Every observed 127 must match the policy; both sides may reject in overlapping
cases. Missing TLS keys, runtime failures, and packet-check failures are never
converted into tolerated unsupported results. The adapter records Docker-inspected
exit codes, and the manifest distinguishes `rama_unsupported` from `peer_unsupported`.
The peer dispatch was checked at the image's quic-go revision
`fcc5f13aa99a9ef658ebcbf70e6026063b2704a9`; revisit exceptions when updating pins.

For HTTP/3 streaming, trailers, multiplexing, cancellation, and independent MASQUE
coverage beyond upstream's file-transfer test, see [HTTP/3 interop](../http-interop/)
and [the shared masque-go harness](../../../examples/tests/masque_interop/).

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
copying to this run's Compose project, retains exit provenance, and pins temporary-file cleanup. It
leaves upstream protocol checks intact. Shutdown terminates the runner's
process group on interruption or its role timeout (two minutes setup plus each
selected peer/case's upstream limit and 45 seconds overhead)
before removing only
this project's containers/networks; it never prunes Docker or deletes another
run's resources. The 130-minute CI job limit includes both role budgets and build
time; core's combined worst-case role budget is 102 minutes, loss's is 64 minutes.
The simulator joins its capture processes on shutdown. All
three services have an explicit ten-second Compose grace period for final
packet captures and qlog output.

## Validation and CI

```sh
just rama-quic/qa-interop-runner boring
just rama-quic/qa-interop-runner rustls-ring
just rama-quic/qa-interop-runner rustls-aws-lc
```

This runs formatting, Clippy, Rust tests, and the Python gate tests without
Docker on Linux, macOS, and Windows. POSIX process-group tests run only on Unix. CI calls the same recipes on all three platforms. The Docker
image defaults to `boring`; `--backend rustls-ring` or `--backend rustls-aws-lc`
selects another backend. CI runs all three. The runner verifies the image backend
label, including with `--skip-build`. Docker builds can override `TLS_BACKEND`.

CI needs a Linux runner with the prerequisites above (Ubuntu's stock tshark
may need upgrading). Build the image, invoke `just rama-quic/test-interop-runner --skip-build` with
`--artifacts "$RUNNER_TEMP/quic-interop"`, and upload that directory with `if: always()`.
When upgrading pins, review upstream topology, case mappings, JSON schema,
and adapter compatibility; rerun the gate tests and full backend-specific matrix.
