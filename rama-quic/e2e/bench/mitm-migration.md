# QUIC MITM migration loopback measurements

Measured on 2026-11-13: Apple M4 Max, 64 GiB, macOS 26.5.2, Rust 1.98.1, release profile.
Source commit `1490ab2ff`; reviewed patch SHA-256
`15029e9cd65d62610c3d95d427993382066433424d8bbeb9b176f389a742eff3`.
[Machine-readable results](mitm-migration.json) include the binary and raw-log hashes.

These are end-to-end loopback results: client, proxy and origin share one four-worker
runtime. They do not isolate proxy CPU cost or establish NIC throughput or maximum concurrency.

## Results

Median application throughput in MiB/s, counting both request and response bytes.
Steady throughput excludes migration intervals; total includes them. Each percentage
compares the median with the independent-relay baseline of the same run.
With nine samples per case, variation is roughly 10%; the smaller median differences
shown here do not establish either a measurable cost or a measurable gain. The ranges
are observed minima and maxima, not confidence intervals.

| Connections | Configuration | Steady median [min–max] MiB/s | Observed median difference | Total MiB/s | Migration p50 / p95 / max (ms) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | Independent relay | 232.5 [211.8–258.6] | +0.0% | 232.5 | — |
| 1 | Migration enabled, no rebind | 230.3 [217.0–245.5] | -1.0% | 230.2 | — |
| 1 | Migration enabled, one rebind | 223.4 [196.4–262.1] | -3.9% | 223.1 | 0.22 / 0.28 / 0.30 |
| 1 | Migration enabled, three rebinds | 226.8 [213.0–255.3] | -2.4% | 225.7 | 0.22 / 0.25 / 0.26 |
| 1 | Migration enabled, idle policy | 238.1 [208.3–267.8] | +2.4% | 238.1 | — |
| 16 | Independent relay | 256.5 [246.3–276.4] | +0.0% | 256.5 | — |
| 16 | Migration enabled, no rebind | 257.7 [222.0–283.2] | +0.5% | 257.7 | — |
| 16 | Migration enabled, one rebind | 254.6 [229.3–278.5] | -0.7% | 254.5 | 0.64 / 0.85 / 0.98 |
| 16 | Migration enabled, three rebinds | 255.8 [233.2–271.9] | -0.3% | 253.8 | 0.67 / 0.87 / 40.74 |
| 16 | Migration enabled, idle policy | 259.7 [227.9–280.5] | +1.3% | 259.7 | — |

## Method and limits

Nine measured rounds per configuration, with rotating order and one full unmeasured warm-up
round. Each connection exchanges four parallel 1 MiB requests and responses in each of four
phases: 32 MiB per connection per sample. Handshakes and an initial 1 MiB warm-up are excluded.
The harness uses the same native UDP transport, demux, TLS and relay in every configuration.

Rebinding moves every client concurrently. Migration timing includes opening the replacement
socket, a 64-byte exchange and observing the ingress peer change. Reused UDP ports can
require retransmission after retiring an obsolete association, so the tail can include that recovery.
Percentiles interpolate the pooled migration observations; they are descriptive, not confidence bounds.

The idle-policy case never replaces egress. At most four paths per connection are attached.
Linux GSO/GRO, larger path sets, real interfaces and signed Apple NetworkExtension switching
are unmeasured. Small differences and apparent improvements must be interpreted with run-to-run
noise; this is not a claim of zero overhead. These are manual comparisons, not CI timing gates.

## Reproduce

Build once, let other builds finish, then run the resulting test binary with each connection count:

```sh
cargo test --release -p rama-quic --features boring --lib compare_native_relay_migration --no-run
# Use the executable path printed by cargo above.
RAMA_MIGRATION_BENCH_CONNECTIONS=1 RAMA_MIGRATION_BENCH_ROUNDS=9 \
  <test-binary> compare_native_relay_migration --ignored --nocapture --test-threads=1
RAMA_MIGRATION_BENCH_CONNECTIONS=16 RAMA_MIGRATION_BENCH_ROUNDS=9 \
  <test-binary> compare_native_relay_migration --ignored --nocapture --test-threads=1
```
