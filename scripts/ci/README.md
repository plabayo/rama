Regular CI provides fast feedback on checks, formatting, docs, tests and examples
across Linux, macOS and Windows. Daily and unstable workflows cover additional
platforms, feature combinations and expensive suites; run them manually when needed.

Keep independent jobs parallel, share scarce runners, and cancel obsolete work.
Optimize execution before reducing coverage. The workflows in `.github/workflows/`
are the source of truth for schedules, matrices and runner allocation.

Local checks (requires just, uv, actionlint, Bash and jq):

- `just scripts/ci/qa` lints workflows and tests the CI helpers.
- `just check-http-features` verifies HTTP feature boundaries without compiling.

Keep helpers small and test their behavior rather than duplicating workflow policy.
