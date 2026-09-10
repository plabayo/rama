# Promoted TCP bulk transfers

This patch bounds observable Swift write stalls and repairs missed resume edges.
It does **not** establish that the reported macOS NE queue growth is fixed. A
real-provider soak remains necessary before closing that part of the incident.

## Critical reading of the incident

Apple documents a write completion as data reaching the associated socket receive
buffer. It is the supported flow-control edge, not an acknowledgement that the
application read the bytes. See [write completion](https://developer.apple.com/documentation/networkextension/neappproxytcpflow/write(_:withcompletionhandler:))
and [flow copying](https://developer.apple.com/documentation/networkextension/handling-flow-copying).
The installed SDK's `NEAppProxyTCPFlow.h` confirms that contract.

The field report is valuable evidence of a stall, but summing queueing log lines
does not measure simultaneous outstanding bytes. RSS growth alone cannot assign
ownership to a particular queue. The existing pump already serializes transport
writes. If NE repeatedly completes writes while privately accumulating data, a
counter based on those same completions cannot enforce an end-to-end memory bound.
Neither increasing the Swift queue cap nor relabeling acceptance as delivery fixes
that. This patch keeps the existing physical payload envelope and serial writes.

Likewise, a finite no-progress timeout cannot both terminate a permanently silent
callback within tens of seconds and tolerate an indistinguishable 300-second
pause. The chosen default is 360,000 ms. Application-specific longer pauses still
require a longer policy or a different liveness contract.

## Behavior and policy

- `TcpWritePumpPolicy.stallTimeoutMs` is a per-pump value, default six minutes.
  It is currently an internal Swift policy field, not a new Rust/Swift FFI config
  option. Existing generation snapshots keep their own policy.
- Each TCP writer independently tracks successful completion progress. New
  admissions, transient errors, and opposite-direction traffic do not reset a
  pending stall. The shared core protects both promoted and Rust-backed writes.
- A withheld completion fails with POSIX `ETIMEDOUT`. Repeated backpressure with
  no progress fails with its most recent POSIX error. Success resets the window.
  Both native `NWError.posix` and POSIX `NSError` are recognized; DNS/TLS errors
  with matching numeric values are not retried.
- One watchdog timer per pump covers writes and aggregate-capacity waits. It is
  reused across bursts and cancelled on teardown; short writes and flow churn
  cannot accumulate six-minute delayed work registrations. A one-second weak
  recovery callback exists only while a promoted direction is paused.
- Successful write completion updates the flow activity clock while active as
  well as while draining. The promoted EOF/maintenance linger floor uses the
  writer window, rather than shortening a slow download to five seconds at EOF.
  Explicit forced teardown (engine stop, pressure eviction, path failure) remains
  able to terminate a flow earlier, with an error.
- A closed writer with a retained source tail is an error, not a successful drain.
  Existing idempotent context teardown closes remaining client halves with the
  error, cancels/detaches egress, and releases buffered payloads.
- Privacy-safe forced-teardown, write-stall, and writer-pressure enter/recovery
  records persist at notice. Stall records include pending bytes/items, outstanding
  write/retry flags, and the policy window. Teardown records identify the cause
  without publishing endpoints, application identity, payloads, or error strings.

The writer memory budget counts live physical payload roots. A callback retaining
an in-flight payload after cancel must keep its charge until the transport retires
that reference. Reporting zero earlier would hide live memory. A callback that
never arrives *and* never gets released can keep that final charge; Swift cannot
force an external transport to relinquish its reference.

## Deterministic verification

`PromotedBulkTransferTests` drives real pumps, a direct forwarder, and context
teardown with a virtual monotonic clock. It covers:

| Case | Assertion |
| --- | --- |
| 1/6/30/300-second reader pauses | Byte-identical stream, EOF after tail, no premature terminal |
| Permanently withheld callback | No early timeout; exactly one terminal at the configured deadline; both halves error-close |
| Callback after cancel | No revived retries; physical accounting returns to zero after retirement |
| Dropped drain notifications | Periodic retry resumes, preserving order and uniqueness |
| ENOBUFS/EAGAIN | Progress survives well beyond five seconds; no progress preserves the POSIX failure |
| EOF while stalled | No clean close before drain; timeout error on failure |
| Idle maintenance | Completion without new admission refreshes the activity clock |
| All forced teardown entry points | Error-carrying, one close per half with pending payloads |
| Both directional interactions | Opposite-direction activity cannot mask a stalled writer |
| Three flows, one wedged | Healthy flows progress independently within aggregate accounting |
| Four seeded fault sequences | Delivered stream remains an exact prefix; bounded timer count after each step |
| 1 GiB generated stream | Distinct chunks, saturated producer, bounded Swift retention, matching byte count and streaming SHA-256 |
| ARC cleanup | Flow, connection, writers, and forwarder deallocate after late callbacks retire |
| Aggregate wait without a write | Independent watchdog still terminates the wait |
| Empty write | No artificial progress, transport call, charge, or timer |

The 1 GiB case is a synthetic Swift-retention test, **not** a measurement of NE's
internal buffers or provider RSS. It saturates available receives with distinct,
indexed chunks, bounds pending roots to two chunks, and compares streaming SHA-256
digests without retaining a second gigabyte in the mock. Smaller pattern tests
compare every byte directly.

Use the repository's debug, Release, and ThreadSanitizer Swift recipes in
`ffi/apple/examples/transparent_proxy/justfile`. ThreadSanitizer covers Swift;
the linked Rust archive is not instrumented by those recipes.

## Real-provider soak

`Tools/slow_download.py` requires an independently known length and SHA-256. It
rate-limits reads, pauses for five minutes periodically, verifies the complete
stream, and emits JSONL progress plus optional provider RSS samples every second.
It requests identity encoding and rejects unexpected status, length, encoding,
truncation, digest mismatch, or failed PID sampling.

Run against a multi-GB HTTPS object whose route is confirmed to use promoted
passthrough in the **newly built** provider, supplying these example arguments with
real values:

```sh
python3 ffi/apple/RamaAppleNetworkExtension/Tools/slow_download.py \
  https://test-host.example/large-file \
  --expect-bytes SOURCE_BYTE_COUNT --sha256 SOURCE_SHA256 \
  --rate 1048576 --pause-every 67108864 --pause-seconds 300 \
  --provider-pid PROVIDER_PID > slow-download.jsonl
```

Collect the provider's notice log and writer-budget snapshots alongside the RSS
trace. Repeat with three concurrent clients at different rates, one paused, and
with a concurrent upload. Compare source and received hashes, EOF timing, peak
RSS during pauses, and baseline after completion. Pass requires byte-exact
completion, stable bounded RSS, baseline recovery, and no abnormal terminals.
Run a separate permanent-reader stall with a shorter test policy to verify the
error path; do not confuse that expected failure with the healthy soak.

The helper itself has been smoke-tested locally against complete and deliberately
truncated HTTP responses. That is not a real NE soak. No deployed provider PID,
confirmed promoted test URL, or source digest was supplied for this worktree, so
the real-provider acceptance criteria remain unverified.

## Initial patch validation — 2026-09-10 (`42b4fa7da`)

Environment: macOS 26.5.2 (25F84), arm64, Apple Swift 6.3.1. Worktree started
from `origin/main` at `efb38a549f078e47746dc8cae2df59129e894138`.

- Full Debug suite: 833 tests passed, zero failures.
- Ordinary production `swift build -c release`: passed.
- Full Release suite with `RAMA_TESTING`: 833 tests passed, zero failures.
- Full ThreadSanitizer suite: 833 tests passed, no reported races.
- 18 new deterministic promoted bulk-transfer tests are included in those totals.
- Soak-tool smoke checks: complete response with pause/resume and RSS sampling
  passed; truncated response and missing provider PID correctly failed.
- `git diff --check`: passed.

The Swift tests linked the existing local debug Rust static archive from the
original checkout. Rust sources were unchanged; that archive was not rebuilt for
this Swift patch. The reported macOS 26.6.2 environment and an actual NE provider
soak have not been exercised here.

The subsequent [fresh-context review](BulkTransferReview.md) records independently
confirmed fixes, stronger validation, and remaining coverage boundaries.
