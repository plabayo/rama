CI shares five macOS and four Windows runner slots across workflows. Heavy jobs
wait for Linux prechecks, and `CI success` gates deployment.

`CI (daily platforms)` runs at 02:00 Europe/Brussels on `main`, or manually on a
selected branch. It covers native Intel macOS and Windows ARM tests, Intel iOS,
Linux GNU cross-builds from macOS and Windows (including the Linux smoke test),
and QUIC MSRV coverage on macOS and Windows. Regular CI retains stable QUIC
coverage on all three operating systems and MSRV coverage on Linux.

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
