# Independent review of the bulk-transfer patch

Three agents reviewed commit `42b4fa7da` independently with fresh context, without
inheriting the implementation conversation. Their scopes were writer concurrency
and accounting, production lifecycle/error handling, and test/soak-tool validity.
They made no repository edits. Confirmed findings were reproduced and corrected
by the primary agent, then the relevant reviewers checked the corrections.

## Confirmed and fixed

### P2: a write timeout replaced an already-observed server reset

A client write remained outstanding at t=0. A later server receive delivered its
final tail plus `ECONNRESET`. The writer's independent timeout expired before the
forwarder's original-error backstop and closed both client halves with
`ETIMEDOUT`, losing the earlier source error. The flow still error-closed, but
violated the existing original-error propagation contract.

The new regression failed before the fix with actual POSIX 60 (`ETIMEDOUT`) versus
expected 54 (`ECONNRESET`). `TcpFlowContext.applyWriterTerminal` now snapshots the
forwarder's latched server-read error before teardown. Its deadline remains
unchanged. The lifecycle reviewer checked queue confinement, ownership, late
callbacks, and preservation through close-once guards.

### P2: the soak tool could report success before RSS sampling failed

The helper selected return code 0 and emitted `passed` before joining its sampling
thread. A failed `ps` result arriving during the final join then emitted
`rss_sampling_failed`, but could not change the selected success result.

The helper now stops and joins monitoring before its success decision and requires
at least one successful completed sample. Two deterministic Python regressions
hold `ps` completion until `Thread.join`; they verify rejection of late failures
and that successful sampling precedes `passed`. Neither test uses timing sleeps.

## Coverage strengthened

- Randomized cases now fill the writer with a full-sized head and receive a
  second distinct tail. They assert an actual pause, dropped wake, retained tail,
  timer recovery, exact prefix/full-stream equality, and bounded timer count.
- A production-factory harness drives real EOF callbacks, validates the context's
  closing/drain flags, runs maintenance against aged activity, and resumes a
  five-minute paused drain. It explicitly uses virtual pump time and real
  maintenance time with a backdated activity observation.
- A production natural-terminal test verifies both half-closes, completed FIN,
  context teardown and released accounting **before** harness destruction can
  clean anything up.
- The 1 GiB producer fills available receive slots before allowing a destination
  completion. Distinct indexed payload roots, independent streaming SHA-256
  digests, exact byte/chunk counts, two-root accounting bounds, and EOF checks
  replace the original repeated-root/count-only workload. The test reviewer
  checked this revised model independently.

## Remaining limits

No further patch-introduced defect was established by these reviews. That is not
a proof of correctness or a substitute for the real NE soak described in
`BulkTransfers.md`.

- NE-owned queues and process RSS remain unmeasured by the Swift mocks.
- The three-flow test interleaves independent queues with ample aggregate
  capacity; it is not itself a concurrent waiter-fairness stress test. Existing
  writer-budget tests separately exercise shared pressure/admission behavior.
- A pre-existing FIN-only liveness boundary remains: the payload pump retires its
  watchdog before an NW `.finalMessage` completion. The forwarder/maintenance
  drain backstop uses shared flow activity, so a withheld FIN completion can be
  postponed while the opposite direction continues transferring. The independent
  writer timeout guarantee concerns pending payload writes, not every FIN-only
  operation. This review did not change those half-close semantics.
- Production `DispatchSourceTimer` cancellation is code-reviewed and covered by
  the full suite's ordinary scheduler paths, but deterministic bulk tests inject
  their own timer scheduler. They do not simulate macOS timer/resource behavior.

## Validation of the review follow-up

On macOS 26.5.2 / Apple Swift 6.3.1:

- Full Debug suite: 835 tests passed.
- Production Release build: passed.
- Full Release suite: 835 tests passed.
- Full ThreadSanitizer suite: 835 tests passed, no reported races.
- The totals include 20 promoted bulk-transfer tests.
- Two deterministic Python soak-monitor regressions passed.
- Two focused timestamp/maintenance scenarios passed again after guarding their
  backdated timestamps against unsigned underflow on freshly booted CI hosts.
- `git diff --check` passed.

As with the initial patch, Swift tests used the existing local Rust static archive;
Rust sources were unchanged. No real-provider NE/RSS soak was performed.
