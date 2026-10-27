# QUIC, HTTP/3 and CONNECT-UDP validation — 27 October 2026

Runtime validation uses commit `78ed725be061a8639805cd053f7aa55822d67302`, compared with merged main `35123eead683e05d3af1b6ca5a16940123ee1647`. All final Docker images and correctness matrices use that runtime; earlier performance investigations explicitly identify their older revisions. Windows, Android device and amd64 execution require CI after publication of the branch.

This branch expands the pinned QUIC interop runner from eight to all 22 active correctness families, in both roles against quic-go and ngtcp2, separately for Boring, Rustls/ring and Rustls/AWS-LC. That is 88 attempted outcomes per backend, 264 in total. Boring is now the default endpoint image backend; the Rustls variants remain explicit build overrides.

The upstream runner's HTTP/3 family transfers files. Additional independent tests cover streaming bodies, trailers, multiplexing, cancellation, live dynamic QPACK in both directions, and a deliberately blocked QPACK field section that resumes only after the independent encoder releases its insertions. The CONNECT-UDP harness covers six groups with independent Go peers: both proxy roles, tunneled H3 workloads, native datagram policy, H1/H2/H3 capsule policy, and transparent interception of an authenticated proxy using a custom URI template. CONNECT-IP is excluded by request.

## Upstream scorecard

All three full wrapper gates accepted their recorded outcomes: **241 raw upstream passes, 17 explicit unsupported outcomes, 3 independently verified checker limitations and 3 cases where the peer did not exercise migration**, out of 264 attempts. Classified upstream failures remain failures in the raw results.

| Backend | Raw passes | Rama unsupported | Peer unsupported | Both unsupported | Checker limitation | Peer did not exercise |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| boring | 81 | 0 | 5 | 0 | 1 | 1 |
| rustls-ring | 80 | 1 | 4 | 1 | 1 | 1 |
| rustls-aws-lc | 80 | 1 | 4 | 1 | 1 | 1 |

All twelve final client handshake-loss/corruption cells passed raw upstream checks: two families × two independent peers × three TLS backends. The earlier failing f035 case remains documented separately below.

### boring

| Upstream family | Client → quic-go | Client → ngtcp2 | Server ← quic-go | Server ← ngtcp2 |
| --- | --- | --- | --- | --- |
| handshake | Pass | Pass | Pass | Pass |
| transfer | Pass | Pass | Pass | Pass |
| longrtt | Pass | Pass | Pass | Pass |
| chacha20 | Pass | Pass | Pass | Pass |
| multiplexing | Pass | Pass | Pass | Pass |
| retry | Pass | Pass | Pass | Pass |
| resumption | Pass | Pass | Pass | Pass |
| zerortt | Pass | Pass | Pass | Pass |
| http3 | Pass | Pass | Pass | Pass |
| blackhole | Pass | Pass | Pass | Pass |
| keyupdate | Pass | Pass | Pass | Pass |
| ecn | Peer unsupported | Pass | Peer unsupported | Pass |
| amplificationlimit | Pass | Pass | Pass | Pass |
| handshakeloss | Pass | Pass | Pass | Pass |
| transferloss | Pass | Pass | Pass | Pass |
| handshakecorruption | Pass | Pass | Pass | Pass |
| transfercorruption | Pass | Pass | Pass | Pass |
| ipv6 | Pass | Pass | Pass | Pass |
| v2 | Peer unsupported | Pass | Peer unsupported | Pass |
| rebind-port | Pass | Pass | Pass | Pass |
| rebind-addr | Pass | Pass | Pass | Pass |
| connectionmigration | Peer unsupported | Checker limitation | Peer did not exercise | Pass |

### rustls-ring

| Upstream family | Client → quic-go | Client → ngtcp2 | Server ← quic-go | Server ← ngtcp2 |
| --- | --- | --- | --- | --- |
| handshake | Pass | Pass | Pass | Pass |
| transfer | Pass | Pass | Pass | Pass |
| longrtt | Pass | Pass | Pass | Pass |
| chacha20 | Pass | Pass | Pass | Pass |
| multiplexing | Pass | Pass | Pass | Pass |
| retry | Pass | Pass | Pass | Pass |
| resumption | Pass | Pass | Pass | Pass |
| zerortt | Pass | Pass | Pass | Pass |
| http3 | Pass | Pass | Pass | Pass |
| blackhole | Pass | Pass | Pass | Pass |
| keyupdate | Pass | Pass | Pass | Pass |
| ecn | Peer unsupported | Pass | Peer unsupported | Pass |
| amplificationlimit | Pass | Pass | Pass | Pass |
| handshakeloss | Pass | Pass | Pass | Pass |
| transferloss | Pass | Pass | Pass | Pass |
| handshakecorruption | Pass | Pass | Pass | Pass |
| transfercorruption | Pass | Pass | Pass | Pass |
| ipv6 | Pass | Pass | Pass | Pass |
| v2 | Both unsupported | Rama unsupported | Peer unsupported | Pass |
| rebind-port | Pass | Pass | Pass | Pass |
| rebind-addr | Pass | Pass | Pass | Pass |
| connectionmigration | Peer unsupported | Checker limitation | Peer did not exercise | Pass |

### rustls-aws-lc

| Upstream family | Client → quic-go | Client → ngtcp2 | Server ← quic-go | Server ← ngtcp2 |
| --- | --- | --- | --- | --- |
| handshake | Pass | Pass | Pass | Pass |
| transfer | Pass | Pass | Pass | Pass |
| longrtt | Pass | Pass | Pass | Pass |
| chacha20 | Pass | Pass | Pass | Pass |
| multiplexing | Pass | Pass | Pass | Pass |
| retry | Pass | Pass | Pass | Pass |
| resumption | Pass | Pass | Pass | Pass |
| zerortt | Pass | Pass | Pass | Pass |
| http3 | Pass | Pass | Pass | Pass |
| blackhole | Pass | Pass | Pass | Pass |
| keyupdate | Pass | Pass | Pass | Pass |
| ecn | Peer unsupported | Pass | Peer unsupported | Pass |
| amplificationlimit | Pass | Pass | Pass | Pass |
| handshakeloss | Pass | Pass | Pass | Pass |
| transferloss | Pass | Pass | Pass | Pass |
| handshakecorruption | Pass | Pass | Pass | Pass |
| transfercorruption | Pass | Pass | Pass | Pass |
| ipv6 | Pass | Pass | Pass | Pass |
| v2 | Both unsupported | Rama unsupported | Peer unsupported | Pass |
| rebind-port | Pass | Pass | Pass | Pass |
| rebind-addr | Pass | Pass | Pass | Pass |
| connectionmigration | Peer unsupported | Checker limitation | Peer did not exercise | Pass |


“Pass” means raw upstream success. “Unsupported” requires exit 127 from the named side. “Checker limitation” and “Peer did not exercise” are raw upstream failures with separately verified evidence; they are not relabelled passes. Both failing classifications concern preferred-address migration. See the explicit limitations below and the raw-result column of the accompanying CSV.

## What changed in production and why

The net production changes below are compared with merged main `35123eead`. The recovery, CID and packet-admission paths discussed here are also unchanged between original base `8d967b2a6` and that main revision. Intermediate branch regressions are called out separately; they are not attributed to released main.

| Change | Origin and previous coverage gap | Result and production impact |
| --- | --- | --- |
| Reset PTO backoff when discarding keys | Inherited defect. Loss/corruption could carry an Initial-space exponential backoff into Handshake recovery. The old eight-family Docker gate omitted these cases. | Key discard resets the backoff, as required by recovery semantics. Client and server deterministic tests check the next deadline. No larger timeout. |
| Coalesce recovery from multiple encryption spaces | Inherited robustness gap: probes could alternate Initial and Handshake flights instead of repairing both together. Large hybrid handshakes and burst loss exposed it. | At most two probe datagrams can carry useful data from both spaces. Stream work only suppresses Data-space retransmission, never Handshake CRYPTO. |
| Retransmit unacknowledged STREAM tails in PTO probes | New recovery capability addressing an inherited robustness gap. Main could send PING-only probes indefinitely when tail data and all subsequent ACKs were lost. | Probes carry outstanding stream bytes when no new data is available. Two probes use distinct useful bytes when possible, then repeat useful outstanding data rather than leave the second probe empty. |
| Bounded early handshake recovery | New capability addressing inherited recovery-latency gaps. Duplicate ClientHello fragments can indicate a lost server flight; repeated consumed server Handshake data can indicate a lost client Finished. The latter was exposed by the final ring loss matrix. | Up to three early retransmissions per packet space, with ordinary congestion/amplification accounting and ACK-aware deduplication. Client Finished accompanies the owed ACK before confirmation. No explicit PTO/backoff reset; normal send-time scheduling remains intact. Confirmed servers use their ACK/HANDSHAKE_DONE paths. |
| ACK and MTU admission | Inherited gaps: queued data could suppress compact ACK feedback at a full window, and MTU discovery could start before handshake confirmation. | Compact ACKs can progress without admitting coalesced data or GSO padding outside the window. Padded client Initial ACKs stay congestion-controlled. MTU discovery waits for confirmation and minimum-path validation; one outstanding probe can still progress through a full window and is charged in flight. |
| Reserve unvalidated-server credit for handshake recovery | Inherited behavior: standalone 0.5-RTT NEW_CONNECTION_ID controls could consume anti-amplification credit needed by CRYPTO retransmission. | Delay standalone controls until useful; allow coalesced controls, ACK feedback and actual early application responses. No blanket ban on early server data. |
| Rotate remote CIDs after applying the whole packet | Inherited defect. Descending NEW_CONNECTION_ID frames could trigger repeated per-frame rotation, prematurely retiring useful client CIDs. | Apply the complete packet before rotating away from the handshake CID, preserving a spare CID for preferred-path validation. |
| Validate the server's preferred local address separately | Inherited gap: application traffic could move to the preferred address before that path had been validated. Earlier tests did not cover the peer's alternate ordering or traffic still arriving on the original path. | A bounded candidate tracks its own amplification credit, three attempts, deadline and reserved CID. Promotion requires validation and a newest non-probing packet. Keep the original usable during validation and clean up on timeout, CID retirement or simultaneous migration. Candidate allocation occurs only during this transition. |
| PATH_CHALLENGE/PATH_RESPONSE handling | Inherited response coalescing lost distinct challenge tokens; challenge repetition lacked the new bounded retry schedule. | Keep distinct responses in bounded batches, pace challenge retries, and service path and recovery timers independently. Off-path batches use one received packet's credit, avoiding duplicated amplification credit. |
| STREAM/CRYPTO copy bookkeeping | Required by the new probe behavior; stale-copy failures and the write-loop failures observed during development were introduced and fixed on this branch. They are not established main defects. | Late ACKs retire every queued copy of delivered bytes; reset/FIN state remains respected. A release-build invariant guard cannot spin or emit a truncated STREAM frame. An empty retransmission queue incurs no tree-removal work. This touches the recovery/ACK hot path and was measured explicitly. |
| Rustls ChaCha20-only offers | New endpoint capability. QUIC Initial protection still needs AES when TLS negotiates only ChaCha20. | Use the final configured native provider for Initial keys, while TLS genuinely offers only ChaCha20. Both Rustls providers negotiate and transfer; custom-provider semantics remain intact. |
| CONNECT-UDP receive-drain lifetime | Inherited issue: dropping the receiver could leave the failed-send drain waiting for its five-second grace deadline. | Receiver drop wakes the drain. Independent surviving send handles retain their semantics, with no per-datagram allocation added. Paused-time and direct CLI tests cover shutdown. |
| Shared TCP/UDP ephemeral binding | Inherited Windows failure: admission by one transport does not establish availability in the other transport's port namespace. History shows failures with either allocator chosen first. | A bounded allocator alternates after conflicts, retains rejected reservations and reuses matching counterparts. HTTP retains 20 attempts, MASQUE 16. Explicit-port/non-conflict errors remain visible; optional H3 can retain TCP. Listener startup only; no forwarding overhead. |

Several intermediate regressions were caught before this branch was delivered: CRYPTO deduplication briefly suppressed a second useful probe; an application-data guard briefly blocked recovery in other encryption spaces; the initial STREAM-probe implementation exposed stale-copy/write-loop failures; and a provisional congestion/pacing gate starved MTU discovery. The final code fixes each and retains deterministic regression coverage. The performance section reports the measured ACK and MTU regressions and their corrections explicitly.

The final ring run at `f035` exposed one more recovery-latency gap after 16 successful sequential handshakes. A loss burst dropped client Finished and two PTO pairs. Rama acknowledged repeated server Handshake data without repeating its still-unacknowledged Finished; quic-go's handshake timeout then fired just before Rama's next backed-off PTO. The [retained failure and packet timeline](validation-2026-10-27/finished-recovery-failure.json) remain classified as a hard failure; the rest of that matrix was interrupted for investigation. Commit `78ed725be` adds the bounded client recovery above. A deterministic wire regression fails at `f035` and passes after the fix in both GSO modes; it verifies Finished and ACK in one datagram, unchanged PTO count and confirmation before the prior next-PTO deadline. Further tests cover the three-attempt bound, congestion admission and late ACKs. This is analogous to the bounded early recovery in [RFC 9002 §6.2.3](https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.3), not one of that section's explicitly listed client signals. Passing the new random-loss matrices supports the fix without proving every possible loss schedule succeeds.

The inherited issues survived because the old Docker selection omitted severe loss/corruption and path-change families, and memory fixtures did not combine the same peer packetization, encryption spaces, congestion state and concurrent timers. New deterministic tests preserve each failure mechanism; independent implementations exercise the resulting wire behavior. This is broader interoperability evidence, not exhaustive QUIC/H3 conformance or proof against every network schedule.

Trace-level endpoint diagnostics record packet routing; ordinary deployments with trace disabled do not format those fields. Changes apply to clients, servers and proxies. Path-state and response queues remain bounded, and listener allocation only affects startup. Performance evidence includes hot-path layers, complete transport/H3 workloads, allocation counts and handshake-load latency, with unresolved small timing differences stated below.

## CI repairs and validation scope

The requested daily run had eleven failing work jobs plus its aggregate gate. Several jobs shared a cause; the branch addresses the causes rather than suppressing the jobs:

| Failure | Change and validation |
| --- | --- |
| Android API23/API34 setup could not find `sdkmanager` | Install the required platform in the pinned emulator action's pre-launch hook, after its SDK setup. Action source and workflow syntax checked; actual device execution still requires GitHub's Android matrix. |
| Rustls verifier delegation test depended on process-global provider installation | Give the test an explicit provider and assert its delegated signature schemes. The original failure was reproduced; the isolated regression and full ring tests pass. |
| QUIC zero-CID refusal test timed out on several platforms | Exercise fragmented Initials and stateless refusal with deterministic packet accounting. The full QUIC suites pass locally on each backend. |
| Optional Wasmtime cache transitive zstd advisories | Ran the complete `just update-deps`. At the user's request, three precise advisory IDs are temporarily ignored with the affected cache path, rationale and removal condition documented. The exact daily advisory check passes. This is a policy exception, not a dependency vulnerability fix. No backport or vendor override. |
| CONNECT-UDP CLI shutdown intermittently consumed its grace deadline | Notify a receive-drain waiter when its socket receiver is dropped. A paused-time test fails before the fix at exactly 5s; socket tests and direct repeated CLI tests pass afterward. |
| Main Windows application tests could not bind the TCP/UDP twin of an ephemeral port | Committed shared bounded allocator; 17 focused tests pass, and the original algorithm fails the deterministic regression. The six failed scenarios pass three predetermined repetitions each, plus five related proxy/MASQUE tests. History contains failures with either transport chosen first, so merely reversing the allocation order does not solve the general problem. |
| Interpreter integration job skipped changes outside a maintained path list | Removed that filter and the aggregate skipped-result exemption. The job now runs after ordinary prechecks on PRs and main. The exact 232-test recipe passes. Local Nextest 0.9.133 reported two process-cleanup warnings; a checksum-verified isolated 0.9.150 ran all 232 with zero warnings. The known macOS pipe-inheritance fix landed in 0.9.145, already used by CI; no JS source or timeout change was needed. |

The advisory exceptions are `RUSTSEC-2026-0391`, `RUSTSEC-2026-0398` and `RUSTSEC-2026-0403`. Cargo-deny 0.20.2 supports advisory-ID exceptions rather than dependency-path exceptions, so these three IDs are ignored globally until the documented removal condition is met. The broader local `just deny` / `just qa` path still fails on pre-existing `RUSTSEC-2026-0387`, through optional dial9 S3 → AWS signing → crypto-bigint 0.5.5. The full dependency refresh did not remove it. No workflow invokes that all-workspace/all-features advisory command: main checks bans/licenses/sources, while the daily advisory job passes `cargo deny --log-level warn --manifest-path ./Cargo.toml --all-features check advisories`, without `--workspace`. This remains an open dependency advisory, enforced rather than excepted. It is recorded here; no separate tracking issue has been opened.

These are locally validated repairs, not a claim that a fresh GitHub run has passed on every operating system. Windows/macOS/Linux/Android runtime differences still belong to the configured CI matrix. Protocol-case deadlines and failing-test assertions remain intact; no unchanged failing test is retried until green as evidence for this report. The expanded Docker job has a 130-minute job allowance and three scenario partitions; that CI scheduling budget is separate from each upstream protocol deadline. Both independent interop jobs retain their diagnostics as CI artifacts.

## Additional coverage results

The final independent MASQUE run used the CLI built from `78ed725be`. All **73 outcomes passed**, and every Rama process shut down gracefully:

| Group | Passing outcomes | What is exercised |
| --- | ---: | --- |
| Rama client → masque-go server | 10 | Repeated CONNECT-UDP requests with independent server |
| masque-go client → Rama server | 10 | Repeated requests with independent client |
| Tunneled HTTP/3 | 1 | H3 workloads through the UDP tunnel |
| Native datagrams and policy | 10 | Multiplexed tunnels, boundary payloads, IPv4/IPv6, authentication and target policy |
| Capsules and policy | 30 | H1 Upgrade and H2/H3 Extended CONNECT, boundary payloads, unknown capsules/context IDs and policy |
| Transparent interception | 12 | Outer CONNECT proxy, authenticated H3 MASQUE, custom URI template, intercepted certificate and separate credentials |

The nested native-datagram interception case uses 0/1/1000-byte payloads to respect the inner 1200-byte path MTU. The ordinary native-datagram policy matrix and capsule cases additionally carry 1200-byte payloads. These are CLI/Boring interoperability results; all three TLS backends separately pass the direct H3 suite (three tests each), and the socket unit suite exercises its Rustls/ring development dependency.

Post-fix QUIC suites passed **1295 Boring, 1241 ring and 1242 AWS-LC tests**, with three existing ignored tests per backend. Endpoint QA passed for every backend, including 33 Python gate tests each. The exact interpreter recipe passed 232 tests with zero skips or process-leak warnings on the isolated current runner. The shared-port allocator passed its 17 deterministic tests, 23 direct CLI integration executions and strict all-target Clippy; the original allocator failed the deterministic regression before the repair.

## Reproduce the independent correctness suite

From the Rama repository root, with Docker Engine >=28.1, Compose >=2.36, tshark >=4.5, uv, Git, Bash and OpenSSL >=3:

```sh
just rama-quic/qa-interop-runner boring
just rama-quic/test-interop-runner --backend boring --artifacts /tmp/rama-boring-results
just rama-quic/test-interop-runner --backend rustls-ring --artifacts /tmp/rama-ring-results
just rama-quic/test-interop-runner --backend rustls-aws-lc --artifacts /tmp/rama-awslc-results
```

Run these serially: the upstream simulator uses fixed subnets. Output directories must be new. On Apple silicon add `--platform linux/arm64`; on macOS put Homebrew OpenSSL 3 first in PATH. The default image target is linux/amd64. `--group core`, `--group paths` and `--group loss` match the three CI partitions; the union is all 22 active families. Raw upstream JSON, packet captures, qlogs, exit provenance and a separate gate manifest are retained. A checker incompatibility never becomes a raw upstream pass.

```sh
just examples/tests/masque-interop /tmp/rama-masque-results
# That recipe also produces /tmp/rama-masque-results-peer.
just examples/tests/http3-interop /tmp/rama-masque-results-peer boring
just examples/tests/http3-interop /tmp/rama-masque-results-peer rustls-ring
just examples/tests/http3-interop /tmp/rama-masque-results-peer rustls-aws-lc
```

For the separate Docker workload benchmark, build uniquely tagged images from the baseline and branch, then run the same four cases in opposite orders:

```sh
python3 rama-quic/e2e/bench/bench_matrix.py --implementations rama-boring \
  --rama-tag YOUR_TAG --platform linux/arm64 --out /tmp/rama-perf-results \
  --logs /tmp/rama-perf-results/logs --svg none
```

The tag resolves to `glendc/rama-quic-interop:boring-YOUR_TAG`. Keep project builds and other test workloads idle while timing. The committed performance provenance contains the exact native benchmark build features, executable hashes and run arguments; these include `--bench --timer os`, since a bare Divan executable is only a smoke run.

## Explicit limits

**Unimplemented Rama capability:** Rustls clients do not implement compatible QUIC v1-to-v2 switching within an existing handshake. This remains a capability gap, not a passing test or a claim that complete protocol coverage was achieved. Boring clients and all three server backends support the upstream v2 family. The Rustls public API does not expose the required version transition; the implementation does not restart TLS or replace a caller's crypto provider to imitate success.

Pinned quic-go rejects ECN and v2 in both roles, and rejects the connectionmigration server case with exit 127. Its client does not attempt the advertised preferred path. These are explicit peer coverage gaps. The ngtcp2 pair and local wire tests cover those behaviors where the peer does not.

The pinned upstream preferred-address checker rejects a valid response-first packet ordering. The separate verifier requires both decrypted captures, correct CIDs and validation ordering, exact file bytes, client exit 0 and an allowed server exit (0, or the runner’s 137/143 stop codes) before classifying that specific incompatibility. Raw upstream results remain visible.

Upstream's disabled `versionnegotiation` case is not an active family. Its `goodput` and `crosstraffic` measurements are distinct from the 22 correctness families and are not currently part of this wrapper's gate. CONNECT-IP and WebTransport are outside this change. Local Docker evidence here is native arm64; amd64 will be exercised by the configured Linux CI matrix after the branch is pushed; it has not been run for this branch yet.

## Performance measurements

### Final comparison at `78ed725be`

The final comparison repeats all 254 native case/backend combinations in both orders, plus all four Docker workloads, against merged main `35123eead`. Both variants use the same compiler, profiles and features on the same Apple M4 Max host. All builds, functional tests and other simulator workloads are stopped during timing. Native binaries use Rust 1.98.1 and explicit Divan `--bench --timer os`; native arm64 Docker images use Rust 1.96.

Elapsed-time ratios are branch/main; lower is faster. Suite medians describe these measurements, not aggregate application throughput or statistical confidence.

| Backend | Suite | Cases | Median of case ratios | Per-case range |
| --- | --- | ---: | ---: | ---: |
| boring | `h3_datagram_demux` | 16 | 0.990 | 0.980–1.014 |
| boring | `http3` | 26 | 0.999 | 0.928–1.023 |
| boring | `http_datagram` | 14 | 0.995 | 0.914–1.032 |
| boring | `quic_handshake` | 14 | 0.973 | 0.938–1.022 |
| boring | `quic_layers` | 43 | 0.997 | 0.937–1.055 |
| boring | `quic_qlog` | 17 | 0.940 | 0.908–1.000 |
| boring | `quic_transport` | 20 | 0.996 | 0.984–1.095 |
| boring | `udp_packet` | 12 | 0.991 | 0.896–1.024 |
| ring | `http3` | 26 | 0.990 | 0.908–1.036 |
| ring | `quic_transport` | 20 | 1.014 | 0.990–1.060 |
| awslc | `http3` | 26 | 1.000 | 0.921–1.040 |
| awslc | `quic_transport` | 20 | 1.004 | 0.977–1.091 |


There is no repeatable large slowdown in these two orders, but this is not proof of performance parity. The largest individual medians are order-sensitive: Boring current-thread churn (16 connections / 1 stream) is 1.095 from pairs 1.196/0.995; AWS-LC worker churn (1 / 1) is 1.091 from 1.014/1.169; ring current-thread bulk (16 / 1) is 1.060 from 1.010/1.110. Smaller differences remain visible, including AWS-LC fragmented-header decoding at roughly 3.5–4% and ring QPACK feedback at 3.6%. The final client Finished change adds no operations to those established transport, header-decoding or QPACK paths; their timing cause is not isolated. The earlier four-order f035 follow-up below documents the same variability pattern. The short 16-chunk retransmit result is 5.5% slower; the earlier 100-iterations-per-sample experiment below provides the better timer-resolution estimate of approximately 1–2% additional recovery bookkeeping.

All seven final load scenarios completed in both orders with zero failed, retried, refused or expired handshakes. Scheduled targets were met within sampling-window rounding: P-256 800/s, RSA-2048 400/s, RSA-4096 100/s, the RSA offload variants and P-256 churn at 100/s. Each variant/pair uses 20,000 latency probes. Across the recent v23 (f035) and v24 (78ed) paired runs, the branch idle p99 was higher in five of six pairs for both scheduled latency and actual RTT. Where higher, actual RTT p99 increased by approximately 0.5–14.5%; its cause is not isolated. The two final v24 pairs differ by 9–14 µs on actual idle RTT p99. This is a directional observation that merits attention, while six pairs across two revisions do not establish its cause or an application-wide regression. P-256 tails change in both directions. RSA-2048 scheduled/actual p99 is higher in both v24 pairs, by approximately 2.5–4.3%. These observations do not support a claim of identical production latency. Full p99.9, maxima, handshake latency, accepted counts and worker utilization are retained in the linked data.

| Final load scenario / pair | Scheduled p99 main / branch (µs) | Actual RTT p99 main / branch (µs) |
| --- | ---: | ---: |
| idle, 1 | 499 / 672 | 271 / 285 |
| idle, 2 | 509 / 554 | 285 / 294 |
| pressure_p256, 1 | 443 / 383 | 318 / 266 |
| pressure_p256, 2 | 428 / 422 | 298 / 300 |
| pressure_rsa2048, 1 | 878 / 900 | 753 / 776 |
| pressure_rsa2048, 2 | 915 / 943 | 795 / 829 |
| pressure_rsa4096, 1 | 2695 / 2712 | 2570 / 2587 |
| pressure_rsa4096, 2 | 2712 / 2684 | 2587 / 2563 |


| Workload | Main round 1 | Branch round 1 | Branch round 2 | Main round 2 |
| --- | ---: | ---: | ---: | ---: |
| handshake | 59.80 ms | 61.75 ms | 62.20 ms | 61.65 ms |
| bulk | 332.85 MiB/s | 333.68 MiB/s | 334.42 MiB/s | 328.74 MiB/s |
| parallel | 277.08 MiB/s | 275.62 MiB/s | 275.64 MiB/s | 277.28 MiB/s |
| small | 3933.39 req/s | 3949.19 req/s | 3908.29 req/s | 3876.22 req/s |

In the final Docker pairs, bulk and small-stream throughput are slightly higher on the branch, while parallel throughput is approximately 0.5–0.6% lower. Startup plus handshake is 0.55–1.95 ms slower. Those small differences are retained rather than described as parity. Every measured branch parallel transfer finishes at MTU 1452 after four probes, with zero server packet loss; packet counts range from approximately 1.514 to 1.532 million per 2 GiB. One measured main parallel transfer reports 20 lost server packets, and one excluded main warmup reports 100; no sample was removed because of that result. The earlier substantial MTU/parallel-throughput regression remains corrected.


The [paired native data](validation-2026-10-27/performance.csv), [commands and binary provenance](validation-2026-10-27/performance-provenance.json), [load latency and handshake counts](validation-2026-10-27/handshake-load.json), and [Docker measurements](validation-2026-10-27/docker-performance.json) retain every sample group and outcome. Batch `v24` tests the final `78ed` runtime. Earlier investigations below keep their original revisions and are not presented as fresh measurements of `78ed`.

### Earlier native investigations at `3056` and `f035`


Primary baseline: `origin/main` revision `35123eead683e05d3af1b6ca5a16940123ee1647`. Runtime in this earlier comparison: `f035fb8b41d9808db145f6740b24d772ed82d943`. The broad batch here is v21; older v15–v20 measurements are explicitly preserved as pre-MTU-fix evidence. A separate cumulative comparison uses original base `8d967b2a61a0e8461b8859a729047193225437cd` and includes intervening upstream changes, so it must not be attributed wholly to this branch. Host: Apple M4 Max, native macOS arm64, Rust 1.98.1; same compiler, feature sets and jemalloc profiler per pair. Timed batches run without project compilation, test runners or simulators competing with them. Variant order is reversed in the second round.

An initial short-sample H3 slowdown did not persist in longer samples. The same follow-up did confirm extra ACK-processing work. The empty retransmission-tree guard in `3056fc957` eliminates that measured regression. The following ACK table is the earlier v15 comparison measured at `3056`, before the MTU correction; the ACK path is unchanged by `f035`:

| ACK retirement microbenchmark | Main `35123` | Branch before guard | After guard `3056` |
| --- | ---: | ---: | ---: |
| Reverse order, 4 ACKs |119.05ns|160.65ns|119.15ns|
| Reverse order, 512 ACKs |15.790µs|18.655µs|15.685µs|
| In order, 128 ACKs |3.7285µs|4.2890µs|3.6715µs|
| In order, 512 ACKs |15.645µs|17.510µs|15.080µs|

All ten ACK cases were measured in both orders with a 0.3-second minimum and 3000 samples minimum. After-guard/main paired median ratios range 0.959–1.001. These are layer microbenchmarks, not end-to-end throughput claims. Raw before/after/main binaries were SHA-verified; the [ACK comparison](validation-2026-10-27/ack-before-after.json) retains the measurements and hashes. Raw ACK logs, binaries and earlier short/longer pre-fix batches v13/v14 are retained locally, not committed.

The earlier v21 comparison covers all eight relevant Boring suites (162 cases), plus the 46 transport/H3 cases for each Rustls provider. The table reports branch time / main time, using the median of the two paired ratios per case; lower is faster. Suite medians are descriptive summaries, not aggregate application throughput or confidence intervals.

| Backend | Suite | Cases | Median of case ratios | Per-case range |
| --- | --- | ---: | ---: | ---: |
| boring | `h3_datagram_demux` | 16 | 0.983 | 0.956–1.011 |
| boring | `http3` | 26 | 0.983 | 0.924–1.059 |
| boring | `http_datagram` | 14 | 0.987 | 0.900–1.009 |
| boring | `quic_handshake` | 14 | 0.986 | 0.963–1.104 |
| boring | `quic_layers` | 43 | 0.991 | 0.954–1.053 |
| boring | `quic_qlog` | 17 | 0.963 | 0.894–1.000 |
| boring | `quic_transport` | 20 | 0.995 | 0.931–1.066 |
| boring | `udp_packet` | 12 | 0.991 | 0.929–1.012 |
| ring | `http3` | 26 | 0.999 | 0.908–1.055 |
| ring | `quic_transport` | 20 | 1.011 | 0.834–1.107 |
| awslc | `http3` | 26 | 0.999 | 0.939–1.038 |
| awslc | `quic_transport` | 20 | 1.000 | 0.939–1.085 |

The range extremes above motivated the focused v23 investigation below; they are individual short-batch observations, not established regression estimates. The v21 short batches exposed several slower cases: roughly 6–11% in some 16-connection workloads, 5.5% in ring abandoned-response churn, and a 10% P-256 loaded-RTT median shift. These were investigated with four predetermined run orders, longer samples, and SHA-verified saved `3056` binaries alongside main and final `f035`. The saved binary distinguishes the MTU correction from earlier branch behavior. No result was discarded to obtain a preferred outcome.

| Focused native workload | f035/main median ratio | f035/pre-MTU median ratio |
| --- | ---: | ---: |
| Boring, current-thread bulk, 16 connections / 1 stream | 0.997 | 0.994 |
| ring, current-thread bulk, 16 / 1 | 1.008 | 0.994 |
| ring, spawned-worker bulk, 16 / 1 | 1.010 | 0.982 |
| ring, worker-thread stream churn, 16 / 16 | 1.015 | 1.001 |
| AWS-LC, current-thread stream churn, 16 / 16 | 1.042 | 1.000 |
| AWS-LC, worker-thread stream churn, 16 / 16 | 1.026 | 0.989 |
| ring, abandoned-response churn | 1.014 | 1.012 |
| Boring, fragmented QPACK literals, 16 KiB | 1.015 | 0.999 |

The [focused native data](validation-2026-10-27/native-focused-comparison.json) retains every pair, including the saved pre-MTU control. These are elapsed-time ratios; lower is faster. The large shifts shrink in the longer samples and do not implicate the MTU correction. They also do **not** establish exact performance parity with main. AWS-LC current-thread ratios vary from 0.933 to 1.220 across pairs, while its saved pre-MTU binary has essentially the same four-pair median as the final binary. Smaller remaining differences include approximately 1.4% (2.05 µs) for ring abandoned-response churn and 2.6% for AWS-LC worker-thread churn. Those remain visible as unresolved small timing differences, with their spread, rather than being described as proven regressions or as parity. The ring response-churn and QPACK differences were present at `3056` as well; their cause is not isolated. Ring response-churn allocations range 137–142 and 54.81–55.04 KB per operation across the final pairs; there is no large allocation increase.

The v23 latency follow-up at f035 uses 40,000 probes per variant per pair. Idle tails remain uncertain and are often higher on the branch; the table retains all pairs rather than describing them as equal. Loaded P-256 median RTT changes direction across pairs (median final/main 0.984), so the initial 10% median increase is not repeatable. Scheduled p99 under load is 4–12 µs higher in these four pairs, while actual RTT p99 changes by −2 to +10 µs.

| Scenario / pair | Scheduled p99 main / branch (µs) | Actual RTT p99 main / branch (µs) |
| --- | ---: | ---: |
| Idle 1 | 870 / 949 | 368 / 370 |
| Idle 2 | 813 / 1036 | 339 / 388 |
| Idle 3 | 1138 / 885 | 381 / 373 |
| Idle 4 | 1066 / 1492 | 395 / 433 |
| P-256 at 800 handshakes/s, 1 | 375 / 379 | 296 / 294 |
| P-256 at 800 handshakes/s, 2 | 370 / 381 | 294 / 302 |
| P-256 at 800 handshakes/s, 3 | 371 / 375 | 285 / 293 |
| P-256 at 800 handshakes/s, 4 | 376 / 388 | 295 / 305 |

Earlier focused experiments are preserved in the [paired measurements](validation-2026-10-27/performance.csv) and [timer-resolution experiment](validation-2026-10-27/retransmit-timer-resolution.json). The 16-chunk retransmit/retire result initially differed by about 40 ns, matching the OS timer's 41 ns precision with one iteration per sample. Using 100 iterations per sample measured approximately 1–2% additional recovery bookkeeping. A speculative empty-ACK guard did not show a consistent worthwhile benefit and was discarded. Correct removal of acknowledged holes is retained; its work is proportional to outstanding holes, not total lifetime stream size. A four-order native 64-byte UDP follow-up varied in both directions (ratios 1.035, 0.926, 0.983, 1.380), despite unchanged UDP/socket/runtime code versus main. Historical-base qlog/UDP comparisons also include intervening upstream changes and cannot be attributed solely to this branch.

All seven established-connection load scenarios completed both v21 rounds at f035. P-256 at 800 handshakes/s, RSA-2048 at 400/s and RSA-4096 at 100/s met their targets with zero failed, retried, refused or expired handshakes. The RSA offload cases and 100/s P-256 churn also completed without failure. Full p50/p95/p99/p99.9, worker-busy and accepted-count evidence is included; RTT medians alone do not summarize those tails.

[Machine-readable data](validation-2026-10-27/README.md) retains every paired case, allocation value, sample count, binary hash and command. The discarded candidate is explicitly labelled in its timer-resolution experiment. The substantial ordinary-ACK regression was corrected. The v21 table also exposes slower cases, rather than hiding them in suite medians; the v23 follow-up above retains the smaller differences and latency uncertainty after investigating the larger apparent shifts. These measurements do not promise identical latency on every platform or every workload.

### Earlier Docker investigation at `f035`

A final Docker comparison caught a real regression introduced by a provisional MTU admission check on this branch. Main transferred the parallel workload at approximately 280/278 MiB/s, versus 252/261 MiB/s before the correction, with about 1.51 million versus 1.54–1.66 million datagrams per 2 GiB and no server packet loss. Narrow MTU tracing showed main reaching 1452 bytes in 4–9 ms, while the branch could take 4–8 seconds: queued streams consumed every available window/pacing opportunity before discovery was considered.

Commit `f035fb8b4` restores bounded probing through a full window and removes the unused preview clone, retaining the handshake-confirmation fix. Probes still count in flight, with at most one outstanding until ACK/loss; the deterministic regression proves convergence within four RTTs under a full window and exhausted pacer, in both GSO modes. The standards make congestion-based probe admission optional and require rate bounding when it is bypassed. [RFC 8899 §3 item 7](https://www.rfc-editor.org/rfc/rfc8899.html#section-3) and [QUIC PMTU probing](https://www.rfc-editor.org/rfc/rfc9000.html#section-14.4) support this distinction. The earlier interpretation that admission behind spare congestion credit was mandatory was incorrect. Full QUIC suites and all independent H3/MASQUE groups pass at this fix. The paired Docker results below confirm recovery of the lost parallel throughput.

| Workload | Main round 1 | Branch round 1 | Branch round 2 | Main round 2 |
| --- | ---: | ---: | ---: | ---: |
| handshake | 61.90 ms | 64.75 ms | 63.70 ms | 62.55 ms |
| bulk | 338.46 MiB/s | 336.31 MiB/s | 333.41 MiB/s | 333.73 MiB/s |
| parallel | 276.67 MiB/s | 273.62 MiB/s | 273.56 MiB/s | 271.78 MiB/s |
| small | 3945.81 req/s | 3886.26 req/s | 3914.41 req/s | 3962.23 req/s |

The [Docker measurements](validation-2026-10-27/docker-performance.json) and [fixed-certificate follow-up](validation-2026-10-27/docker-focused-comparison.json) retain all run orders. The images in this earlier comparison use `f035fb8b4`, versus main `35123eead`. These are native arm64 Docker workloads with the same virtual forwarding path. The parallel branch measured runs each send approximately 1.514 million datagrams per 2 GiB, matching main, and finish at MTU 1452 after four probes. All six measured branch parallel transfers report zero server packet loss; one excluded warmup reports 36 lost server packets. Startup-plus-handshake is 1.15–2.85 ms slower and small-stream throughput about 1.2–1.5% lower in these two pairs; those small differences are retained in the data. A separate four-order follow-up reused identical certificates and found changes in both directions: handshake branch/main ratios 1.029, 0.943, 0.980, 1.069; small-stream throughput ratios 1.051, 1.009, 0.981, 0.997. Those results do not establish a repeatable regression in either case. Bulk and parallel throughput no longer show the earlier substantial regression. A separate [traced handshake pair](validation-2026-10-27/handshake-packet-comparison.json) found both clients sending the request before HANDSHAKE_DONE, with no extra request round trip. The branch sends three server datagrams before client Finished instead of four, moving standalone NEW_CONNECTION_ID controls into the confirmed flight, and starts client MTU probing only after confirmation. Traced elapsed values are diagnostic and excluded from the performance comparison.



## ngtcp2 finding

I would not open an ngtcp2 bug report yet: the historical finding is confirmed, but it has not been reproduced on today's build. In the pinned image (ngtcp2 revision `3c23148ef32596cb75720b94615d9650cdec5391`), both decrypted captures show DCID `7817883bd877c472` sent to the original port 443 and preferred port 4433. Server-side frames 33 and 35/36 demonstrate the reuse. [RFC 9000 §9.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5) prohibits reuse across destination addresses. The client also did not answer two original-path challenges that reached it. Rama now handles that ordering without abandoning the usable original path, with deterministic coverage.

Today's image, revision `3c266f8dc72ca2f0b2cd96384d491b81a6cfe23a`, passed a fresh focused preferred-address run against Rama/ring. Its client/server captures contained 2742/2831 QUIC packets and no cross-destination CID reuse. One clean run does not rule out the earlier scheduling-dependent behavior. If it is reproduced on a current build, an ngtcp2 issue should include the historical evidence; a suitable historical reference title is `Historical preferred-address CID reuse in interop image 3c23148`, attach the old packet/keylog evidence and exact sequence, include the clean current result, and identify the current failing revision and distinguish it from the older trace. Do not describe it as a reproduced current regression. No report has been posted.

The [CID evidence](validation-2026-10-27/ngtcp2-cid-evidence.json) includes the historical CID-reuse packet rows and current capture summaries, revisions and hashes. Full packet extracts, captures, TLS keylogs and simulator logs are retained locally, not committed. The current image digest is `sha256:2479d166877e9e3df64ad4d0397030de68e424dc7680dbaa0674d88ef5e9d750`; the pinned digest is recorded in `runner.lock.json`. The first current-image harness attempt failed during simulator setup because a copied helper was missing; its evidence remains labelled as setup failure. The corrected harness's first actual protocol execution is the clean result above.

## Upstream listing

Local interop execution and image publication already exist. Neither an entirely green matrix nor additional local infrastructure is a prerequisite to requesting registration. Upstream explicitly supports exit 127 for unsupported cases and asks implementations to submit a registry PR.

As checked on 27 October 2026, Rama is absent from `implementations_quic.json`. The published edge image already contains linux/amd64 and linux/arm64 manifests; the online runner requires amd64. This branch's new default and fixes become available in edge after merging and successful publication.

Proposed registry entry:

```json
"rama": {
  "image": "glendc/rama-quic-interop:edge",
  "url": "https://github.com/plabayo/rama",
  "role": "both"
}
```

To start with an issue, open [the upstream issue form](https://github.com/quic-interop/quic-interop-runner/issues/new) with title `Add Rama as a QUIC/HTTP3 interop implementation`. Include the public image, both roles, amd64/arm64 support, environment/mount contract, TLS keylog/qlog support, explicit exit-127 behavior and the final result table from this report. Ask whether maintainers prefer an accompanying registry PR; their documented path is a PR adding the entry above. An optional link in quic.md can point to Rama's Dockerfile and endpoint script. No issue or PR has been posted by this task.

Primary reference: [upstream endpoint and registration instructions](https://github.com/quic-interop/quic-interop-runner/blob/master/README.md#building-an-endpoint).

## Evidence files and local runtime

[Machine-readable evidence](validation-2026-10-27/README.md) includes every upstream outcome, all 1,902 paired native measurements, allocation values, source/image/binary hashes, commands, latency tails, Docker workloads, functional results and CI repair details. Raw packet captures, keylogs and binaries remain in the recorded local artifact directories.

| Final matrix | Complete local wall time |
| --- | ---: |
| boring | 28.8 min |
| rustls-ring | 28.5 min |
| rustls-aws-lc | 28.5 min |

These are complete serial native-arm64 runs, including setup and upstream packet analysis; they are not amd64 CI duration predictions. CI partitions the same families into three groups per backend (nine jobs), with a 130-minute job allowance.
