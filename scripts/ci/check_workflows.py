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
    "macos": {f"rama-macos-slot-{i}" for i in range(3)},
    "windows": {f"rama-windows-slot-{i}" for i in range(4)},
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


def validate(workflow, path):
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
                for run_id in (1, 2, 3):
                    group = expression(concurrency.get("group"), row, index, run_id)
                    assert group in slots, (path, name, row, group)
    if path.name == "CI.yml":
        checks = {name for name in jobs if not name.startswith("deploy-") and name != "ci-success"}
        assert set(jobs["ci-success"]["needs"]) == checks, "CI success must cover every check"
        assert jobs["ci-success"]["if"] == "${{ !cancelled() }}", "Gate must run after failures/skips"
        assert jobs["deploy-rama-cli-docker"]["needs"] == "ci-success"
        gates = {"precheck-rust", "precheck-docs", "precheck-fmt", "meta-lints"}
        for name in checks - gates:
            assert gates <= ancestors(jobs, name), f"{name} bypasses early gates"
        assert not any(jobs[name].get("needs") for name in gates), "Early gates must run immediately"
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
