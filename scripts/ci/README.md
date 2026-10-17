CI shares five macOS and eight Windows runner slots across workflows. Heavy jobs
wait for Linux prechecks, and `CI success` gates deployment. Regular CI's per-push
macOS and Windows jobs sit on their own slots so they do not queue behind the
daily, docs, unstable, or release workflows.

`CI (daily platforms)` runs at 02:00 Europe/Brussels on `main`, or manually on a
selected branch. It covers native Intel macOS and Windows ARM tests, Intel iOS,
Linux GNU cross-builds from macOS and Windows (including the Linux smoke test),
QUIC MSRV coverage on macOS and Windows, and the macOS and Windows MSRV clippy
check. Regular CI retains stable QUIC coverage on all three operating systems,
MSRV coverage on Linux, and stable clippy on every platform.

The daily workflow has its own success gate and infrastructure retries. Its
shared job steps and cache settings are checked against regular CI to prevent
drift. Platform-specific failures can surface after merging; use manual dispatch
when a PR needs those checks before merging.

Validate changes with [check_workflows.py](check_workflows.py),
[test_workflows.py](test_workflows.py), and
[check_feature_coverage.py](check_feature_coverage.py).

`just scripts/ci/qa` runs them from the repository root in this directory's locked
uv environment (`pyproject.toml`, `uv.lock`, `.python-version`); `check-features`
also needs cargo-hack 0.6.45, and `check-format.sh` needs actionlint 1.7.12, Bash
and jq.


Fingerprint database tests use a private Unix-socket-only PostgreSQL cluster;
`pg_config` must locate the installed server tools. The wrapper propagates the
command's exit status and removes its cluster on completion or interruption:

```sh
just scripts/ci/fp-test-postgres cargo test -p rama-cli --bin rama cmd::serve::fp:: -- --ignored --skip measure_counted_profile_day_storage_and_fourteen_day_merge
```

CI runs these tests on Linux. The storage-sizing test runs separately without
competing builds, since its timings describe the local fixture.

`python3 scripts/ci/check_http_features.py` checks the resolved normal dependency
graphs for HTTP, the native relay examples, the excluded Apple engine/harness,
and explicit UA selections. Neither
`http` nor `http-full` enables UA support or embedded profiles. The CLI and UA
examples request those features explicitly. The daily Linux Boring job runs this
check; it performs no compilation. Missing dependencies can be fetched under
Cargo’s locked version selection, so a cold CI cache remains supported.
