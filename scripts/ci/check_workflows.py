#!/usr/bin/env python3
"""Check CI admission and gating invariants (run via `just scripts/ci/qa`, which supplies PyYAML).

This intentionally evaluates only the expression subset used for runs-on and
concurrency groups. Unknown syntax fails closed instead of guessing a runner.
"""

import ast
import itertools
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SLOTS = {
    "macos": {f"rama-macos-slot-{i}" for i in range(5)},
    "windows": {f"rama-windows-slot-{i}" for i in range(8)},
}


def matrix_rows(matrix):
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    original = [dict(zip(axes, values)) for values in itertools.product(*axes.values())] if axes else []
    # GitHub excludes original combinations first. An include entry can then
    # add an excluded combination back, and it must still be budget-checked.
    original = [row for row in original if not any(
        all(row.get(k) == v for k, v in exclusion.items())
        for exclusion in matrix.get("exclude", [])
    )]
    rows = [row.copy() for row in original]
    for addition in matrix.get("include", []):
        matched = False
        for base, row in zip(original, rows):
            if all(k not in base or base[k] == v for k, v in addition.items()):
                row.update(addition)
                matched = True
        if not matched:
            rows.append(addition.copy())
    return rows if matrix else [{}]


def expression(value, matrix, job_index=0, run_id=1):
    if not isinstance(value, str) or not value.startswith("${{"):
        return value
    assert value.endswith("}}"), value
    code = value[3:-2].strip().replace("&&", " and ").replace("||", " or ")
    code = re.sub(r"\b(matrix|github|strategy)\.([a-zA-Z_][\w-]*)",
                  lambda m: f'{m[1]}[{m[2]!r}]', code)
    tree = ast.parse(code, mode="eval")
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare,
               ast.Eq, ast.NotEq, ast.Call, ast.Name, ast.Load, ast.Constant,
               ast.Subscript)
    functions = {
        "startsWith": lambda a, b: a.startswith(b),
        "format": lambda template, *args: template.format(*args),
    }
    for node in ast.walk(tree):
        assert isinstance(node, allowed), f"Unsupported expression: {value}"
        if isinstance(node, ast.Call):
            assert isinstance(node.func, ast.Name) and node.func.id in functions, value
    return eval(compile(tree, "<workflow expression>", "eval"), {"__builtins__": {}}, {
        **functions, "matrix": matrix, "github": {"run_id": run_id},
        "strategy": {"job-index": job_index},
    })


def ancestors(jobs, name):
    result = set()
    pending = [name]
    while pending:
        needs = jobs[pending.pop()].get("needs", [])
        for need in [needs] if isinstance(needs, str) else needs:
            assert need in jobs, f"Unknown dependency: {need}"
            if need not in result:
                result.add(need)
                pending.append(need)
    assert name not in result, f"Dependency cycle involving {name}"
    return result


def validate_security(workflow, path):
    """Guard the credential/build boundary; this is not a general shell analyzer."""
    assert workflow.get("permissions") == {}, (path, "Workflow permissions must default to none")
    assert "secrets." not in str(workflow.get("env", {})), (path, "Workflow-wide secret")
    if path.name == "CI-retry.yml":
        assert all("uses" not in step for job in workflow["jobs"].values() for step in job["steps"]), "Retry must remain metadata-only"
    for name, job in workflow["jobs"].items():
        steps = job.get("steps", [])
        permissions = job.get("permissions", workflow["permissions"])
        assert isinstance(permissions, dict), (path, name, "Broad token permission")
        privileged = "write" in permissions.values()
        custom_secrets = re.findall(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", str(job))
        privileged |= any(secret != "GITHUB_TOKEN" for secret in custom_secrets)
        cached = any("cache" in step.get("uses", "").lower() for step in steps)
        builds = any(
            step.get("uses", "").startswith(("dtolnay/rust-toolchain@", "docker/build-push-action@"))
            or re.search(r"\b(cargo|cross)\s+(build|check|test|clippy|install|doc|nextest|zigbuild|miri)\b", step.get("run", ""))
            for step in steps
        )
        assert not (privileged and cached), (path, name, "Privileged job must not use build caches")
        assert not (privileged and builds), (path, name, "Builds must not have secrets or write authority")
        for step in steps:
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step.get("with", {}).get("persist-credentials") is False, (path, name, "Persisted checkout token")
        if "miri" in name:
            assert not cached, (path, name, "Miri output must never be cached")
            assert not any("upload-artifact@" in step.get("uses", "") for step in steps), (path, name, "Miri output must not be uploaded")
            assert job.get("env", {}).get("MIRI_TOOLCHAIN") == "nightly-2026-09-22", (path, name, "Review the patched Miri pin before changing it")
        if path.name == "RamaCLIRelease.yaml" and name.startswith("build-release-"):
            assert not cached, (path, name, "Release builds must not restore executable caches")
            checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
            assert checkout["with"].get("ref") == "${{ needs.resolve-release.outputs.sha }}", (path, name, "Build the resolved release tag")


def validate(workflow, path):
    validate_security(workflow, path)
    jobs = workflow["jobs"]
    for name, job in jobs.items():
        ancestors(jobs, name)
        for index, row in enumerate(matrix_rows(job.get("strategy", {}).get("matrix", {}))):
            runner = expression(job.get("runs-on", ""), row)
            runners = [runner] if isinstance(runner, str) else runner
            for family, slots in SLOTS.items():
                if not any(label.startswith(family) for label in runners):
                    continue
                concurrency = job.get("concurrency", {})
                assert concurrency.get("cancel-in-progress") is False, (path, name, "cancellation")
                assert concurrency.get("queue") == "max", (path, name, "lossy queue")
                # Different PR/main runs must resolve to the same finite slot set.
                groups = {expression(concurrency.get("group"), row, index, run_id)
                          for run_id in (1, 2, 3, 1001)}
                assert len(groups) == 1, (path, name, row, "run-specific slot", groups)
                assert groups <= slots, (path, name, row, groups)
    if path.name in ("CI.yml", "CI-platforms-daily.yml"):
        checks = {name for name in jobs if not name.startswith("deploy-") and name != "ci-success"}
        assert set(jobs["ci-success"]["needs"]) == checks, "CI success must cover every check"
        assert jobs["ci-success"]["if"] == "${{ !cancelled() }}", "Gate must run after failures/skips"
        gates = ({"precheck-rust", "precheck-docs", "precheck-fmt", "meta-lints"}
                 if path.name == "CI.yml" else {"precheck-rust"})
        for name in checks - gates:
            assert gates <= ancestors(jobs, name), f"{name} bypasses early gates"
        assert not any(jobs[name].get("needs") for name in gates), "Early gates must run immediately"
    if path.name == "CI-platforms-daily.yml":
        # PyYAML's YAML 1.1 loader interprets the unquoted `on` key as True.
        triggers = workflow.get("on", workflow.get(True))
        assert triggers == {
            "schedule": [{"cron": "0 2 * * *", "timezone": "Europe/Brussels"}],
            "workflow_dispatch": {},
        }, "Daily platforms must run at 02:00 Belgian time or on demand"
        assert not any(name.startswith("deploy-") for name in jobs), "Daily checks must not deploy"
    if path.name == "CI.yml":
        assert jobs["deploy-rama-cli-docker"]["needs"] == "ci-success"
        feature_job = jobs["cargo-hack"]
        assert feature_job["strategy"]["matrix"] == {"partition": [1, 2]}, "Both feature partitions are required"
        feature_commands = [step["run"] for step in feature_job["steps"] if "run" in step and "cargo hack check" in step["run"]]
        assert feature_commands == ["cargo hack check --each-feature --no-dev-deps --workspace --partition ${{ matrix.partition }}/2"], "Feature coverage verifier must match the executed selection"


def main():
    for path in sorted((ROOT / ".github/workflows").glob("*")):
        validate(yaml.safe_load(path.read_text()), path)
    print("Workflow resource budgets and required CI gates verified")


if __name__ == "__main__":
    main()
