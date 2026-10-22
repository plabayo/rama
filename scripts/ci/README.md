CI shares five macOS and eight Windows runner slots across workflows. Heavy jobs
wait for Linux prechecks, and `CI success` gates deployment. Regular CI's per-push
macOS and Windows jobs sit on their own slots so they do not queue behind the
daily, docs, unstable, or release workflows.

`CI (daily platforms)` and `CI (unstable toolchains)` both run at 00:30
Europe/Brussels on `main`, or manually on a selected branch; GitHub often starts
scheduled runs hours late, so the start leaves room to finish before 06:00.
The daily workflow covers native macOS, Intel macOS (all-features suite only),
Windows ARM and Linux ARM tests, `--no-default-features` outside Linux x86, the
release-mode e2e suite, the JS interpreter suites, Intel iOS, Linux GNU
cross-builds from macOS and Windows (including the Linux smoke test), QUIC
coverage on Windows and QUIC MSRV on macOS, and the macOS and Windows MSRV clippy
check. Regular CI retains stable QUIC coverage on Linux and macOS, MSRV coverage
on Linux, stable clippy on every platform, and runs the JS interpreter suites
only when a change can affect them.

The daily workflow has its own success gate and infrastructure retries. Platform-specific failures can surface after merging; use manual dispatch
when a PR needs those checks before merging.

`just scripts/ci/qa` runs actionlint and tests the executable CI helpers.
The workflow files define the job matrix, dependencies, permissions and runner
budgets; there is no separate Python policy duplicating that configuration.
Actionlint uses the existing exception for GitHub's `queue` property.

Python helpers use this directory's locked, stdlib-only uv environment.
Install uv, actionlint, Bash and jq. The status-mirror test exercises the actual
shell script so stale listings and cancelled runs cannot hide the latest main
failure. Signing tests check that the signing script never executes the input
binary or invokes a build tool.

`just check-http-features` ([check_http_features.py](check_http_features.py)) checks the resolved normal dependency
graphs for HTTP, the native relay examples, the excluded Apple engine/harness,
and explicit UA selections. Neither
`http` nor `http-full` enables UA support or embedded profiles. The CLI and UA
examples request those features explicitly. The per-push Linux Boring job runs this
check; it performs no compilation. Missing dependencies can be fetched under
Cargo’s locked version selection, so a cold CI cache remains supported.
