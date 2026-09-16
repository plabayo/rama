CI retains all existing checks while sharing five macOS and four Windows runner
slots across workflows. Heavy jobs wait for the Linux prechecks, and `CI success`
gates deployment. Validate changes with [check_workflows.py](check_workflows.py),
[test_workflows.py](test_workflows.py), and
[check_feature_coverage.py](check_feature_coverage.py).

`just scripts/ci/qa` runs them from the repository root in this directory's locked
uv environment (`pyproject.toml`, `uv.lock`, `.python-version`); `check-features`
also needs cargo-hack 0.6.45, and `check-format.sh` needs actionlint 1.7.12, Bash
and jq.
