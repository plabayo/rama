# CI scheduling and coverage

CI keeps the existing checks, toolchains, host labels, target architectures,
feature selections, backend isolation, doctests, and sanitizer/release passes.
The changes group compatible work and bound admission to scarce runners.

## Resource budgets

Every macOS job in CI, unstable CI, Pages, and CLI releases uses one of
`rama-macos-slot-0` through `rama-macos-slot-2`. Windows uses slots 0 through 3.
These names deliberately contain neither the workflow name nor the Git ref:
multiple PRs, main, schedules, and releases share the same repository budget.
Other repositories have their own concurrency groups; these slots do not reserve
organization capacity or provide an organization-wide semaphore.

Each slot uses `cancel-in-progress: false` and `queue: max`. GitHub's default
single-entry pending queue would cancel required jobs as other jobs arrived.
`queue: max` retains up to 100 pending entries per slot; it is not unbounded.
Workflow-level cancellation still supersedes obsolete PR runs. Main runs retain
the previous workflow-level concurrency policy. Pages now scopes that policy to
each ref so unrelated PRs no longer replace each other's pending runs.

GitHub Team's documented baseline is 60 total standard hosted jobs with a macOS
sublimit of 5. The repository's budget of 3 macOS and 4 Windows jobs is deliberately
smaller. See [GitHub limits](https://docs.github.com/en/actions/reference/limits)
and [concurrency semantics](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

The regular CI assignment is approximately balanced by observed runner minutes:

| Slot | Regular CI work |
| --- | --- |
| macOS 0 | Intel native tests and Intel iOS checks/linking |
| macOS 1 | ARM native tests, ARM iOS checks/linking, MSRV Clippy/formatting |
| macOS 2 | Stable Clippy/docs/XPC, Apple FFI/Swift, QUIC, Linux cross-builds |
| Windows 0 | x64 native tests |
| Windows 1 | ARM native tests |
| Windows 2 | Clippy/docs, MSRV QUIC, GNU-host Linux cross-build |
| Windows 3 | Stable QUIC |

Pages, unstable CI, and releases also use these slots. There is no priority or
work-stealing guarantee: a busy slot can have a queue while another slot is idle.
Rebalance assignments using actual job times if this becomes significant. Do not
add more slots without changing the policy checker and considering org activity.
Linux matrix groups are unique per job/run/row and do not serialize Linux work.

## Gates and retained coverage

The Rust/fuzz precheck, script checks, stable/MSRV formatting, and metadata lints
start immediately on Linux. All expensive regular CI jobs require those gates.
Pages and unstable CI run their own cheap formatting gate against their checkout.

Regular CI uses 10 macOS allocations and 7 Windows allocations. Adding Boring
coverage retains those counts by using the existing QUIC jobs:

| Previous checks | Current location |
| --- | --- |
| Stable/MSRV Clippy and native formatting, Linux/macOS/Windows | All original `check-rust` cells; formatting runs first |
| Stable docs, Linux/macOS/Windows | `doc-rust` on Linux; stable `check-rust` cells on macOS/Windows |
| Apple XPC QA | Stable macOS `check-rust` cell, still `macos-latest` |
| Apple transparent-proxy QA/e2e and separate Swift job | Combined Apple job; both original normal Swift invocations, TSan, and optimized Swift tests retained |
| QUIC: 3 backends × 2 toolchains × 3 OSes | Linux has six jobs; each macOS/Windows toolchain job runs all three backends separately |
| macOS-host Linux GNU x86 full coverage and ARM DNS sentinel | `test-rust-linux-gnu-cross-macos`, both target invocations |
| Windows GNU-host Linux CLI linking | `test-rust-linux-gnu-cross-windows`, original GNU host toolchain |
| Linux smoke of macOS-built CLI | Depends only on the macOS producer, not the Windows cross-build |
| Two overlapping cargo-hack suites | Two disjoint partitions of the full original feature-check set |

The native test matrix remains Linux x64/ARM, macOS Intel/ARM, and Windows
x64/ARM. Its all-feature, no-default, isolated crypto-backend, doctest, example,
ignored-test, Windows relay-interrupt, and revocation-gate selections are intact.
Native all-feature and no-default builds have their own steps for timing;
execution keeps the same Cargo and Nextest options. No optimization profile,
build parallelism cap, ignored-test selection, or timeout for an existing native
test step was reduced.

Both musl targets, all four Android targets, both iOS targets, dial9 with and
without tokio_unstable, Loom, ICAP boundaries/oracle, Datastar, FastCGI, QUIC
Docker interop, Autobahn client/server, H2 specification tests, semver checks,
and release ignored tests remain. The scheduled beta debug/release matrix,
nightly fuzzing, Apple ASan/Miri, docs.rs emulation/native docs, and bindings
refresh also remain. Runner labels and release targets were not substituted.

Consolidated independent suites use `!cancelled()` to keep collecting failures.
The `CI success` job requires every regular CI check to succeed, including the
Datastar and stable dial9 jobs missing from the previous deployment dependency
list. Deployments depend on this gate. The infrastructure retry workflow ignores
only this synthetic gate when classifying the original failures.

Use `CI success` if configuring a single required branch-protection check.
Several former individual check names moved; this commit does not edit GitHub
branch-protection settings or rulesets.

## Build reuse

The cache wrapper now exposes `shared-key`. On the pinned rust-cache version this
is a complete prefix replacing the normal key/job-ID prefix. The stable Linux
precheck and Clippy cell share `linux-stable-check-v1` with matching Rust flags
and toolchain environment. This shares dependency artifacts, not a prebuilt test
executable. Other cache families remain distinct where profiles, targets,
toolchains, or workspace layouts differ. There is no concurrent writer scheme
that assumes immutable caches can merge their contents.

The Apple FFI jobs explicitly cache their standalone Cargo workspaces, including
the separate ASan target directories in unstable CI. The ordinary target remains
separate from the sanitizer target. The isolated app build's temporary source
and outputs stay isolated; these cache entries do not bypass that build.
Prebuilt nextest and cargo-sort tools avoid recipe-triggered `cargo install` on
the combined Apple job; both Linux dial9 jobs also install nextest prebuilt.

All three built-in QUIC backends run sequentially within each scarce-host/toolchain job, with
all five standalone projects retaining their own manifests and lockfiles. No
backend feature union or workspace merge is used to save compilation.
The separate GnuTLS project runs on Linux with stable/MSRV, behind the same early
and final gates. It enables no built-in Rama backend. QUIC jobs retain isolated
library, crypto, example, heavy-transfer, benchmark, and peer checks on every
host/toolchain/backend; dial9, receive-window stress, the Boring dependency-isolation
check and remaining feature combinations run on Linux stable. That isolation check only
reads the locked dependency graph, so its result cannot differ by host or toolchain and
one cell covers it, which also keeps the scarce macOS/Windows runners free of a Python
interpreter requirement. Stress steps have a 15-minute timeout and also run via `just qa-full`.
The cache includes the root workspace as well as standalone peer workspaces.

## Verification

This directory's `justfile` holds the policy checks; `meta-lints` runs the same recipe.
Invoke it from the repository root, where `just scripts/ci/` lists every recipe:

```sh
just scripts/ci/qa
```

`qa` bundles `check-workflows`, `check-features` and `test`, each runnable on its own.
They execute in this directory's own locked environment: `pyproject.toml` declares PyYAML,
`uv.lock` pins its graph, and `.python-version` pins the interpreter uv selects, so they
never depend on whichever Python the machine or the runner image ships. That needs `uv`
installed, and `check-features` also needs cargo-hack 0.6.45.

The remaining checks need actionlint 1.7.12, Bash, and jq:

```sh
bash scripts/ci/check-format.sh
actionlint -ignore 'unexpected key "queue" for "concurrency" section'
```

These policy/feature/lint checks also run in `meta-lints`. The narrow actionlint
exception is needed because 1.7.12 predates GitHub's documented `queue` property;
the policy checker independently requires `queue: max` and no cancellation for
every scarce-runner matrix row. Remove the exception when upgrading to a
validator that understands the property.

The feature verifier records actual cargo-hack invocations with a Cargo shim.
Only read-only Cargo metadata/version queries are forwarded; compilation commands
are recorded. This exercises real partition scheduling without compiling. It
avoids a 0.6.45 bug where `--print-command-list` does not advance the partition
counter. After this merge, the verifier preserves 288 unique feature checks as two
144-command partitions.

For performance comparisons, use the job API's `created_at`, `started_at`, and
`completed_at`, and separate build/run step durations. The pre-change successful
[run 34892949730](https://github.com/plabayo/rama/actions/runs/34892949730) took
9h52m, with approximately 615 macOS runner-minutes. Its final cross-build waited
8h46m after prechecks and ran for 50m. This is one baseline, not a promised speedup.
Measure cold and warm runs and concurrent PR/main activity before further
sharding tests or introducing a compiler-cache backend. Those experiments are
not required to preserve or run the current coverage.
