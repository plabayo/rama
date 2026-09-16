"""Regression checks for scheduling mistakes that can silently lose CI coverage."""

import copy
import itertools
import re
import subprocess
import unittest

import yaml

from check_workflows import ROOT, expression, matrix_rows, validate


class WorkflowPolicyTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / ".github/workflows/CI.yml"
        self.workflow = yaml.safe_load(self.path.read_text())

    def test_current_workflows(self):
        for path in (ROOT / ".github/workflows").glob("*"):
            with self.subTest(workflow=path.name):
                validate(yaml.safe_load(path.read_text()), path)

    def test_missing_platform_budget(self):
        del self.workflow["jobs"]["test-rust-base"]["concurrency"]
        with self.assertRaises(AssertionError):
            validate(self.workflow, self.path)

    def test_lossy_queue(self):
        self.workflow["jobs"]["test-rust-base"]["concurrency"]["queue"] = "single"
        with self.assertRaises(AssertionError):
            validate(self.workflow, self.path)

    def test_run_specific_budget(self):
        job = self.workflow["jobs"]["test-rust-linux-gnu-cross-macos"]
        job["concurrency"]["group"] = "${{ format('rama-macos-slot-{0}', github.run_id) }}"
        with self.assertRaises(AssertionError):
            validate(self.workflow, self.path)

    def test_extra_slot(self):
        self.workflow["jobs"]["test-rust-linux-gnu-cross-windows"]["concurrency"]["group"] = "rama-windows-slot-4"
        with self.assertRaises(AssertionError):
            validate(self.workflow, self.path)

    def test_extra_macos_slot(self):
        job = self.workflow["jobs"]["test-rust-linux-gnu-cross-macos"]
        job["concurrency"]["group"] = "rama-macos-slot-5"
        with self.assertRaises(AssertionError):
            validate(self.workflow, self.path)

    def test_long_macos_jobs_use_five_slots(self):
        jobs = self.workflow["jobs"]
        assignments = [
            ("test-rust-base", {"os": "macos-15-intel", "toolchain": "stable"}),
            ("test-rust-base", {"os": "macos-15", "toolchain": "stable"}),
            ("test-rust-linux-gnu-cross-macos", {}),
        ]
        quic = next(name for name in jobs if name.startswith("test-quic-interop-qa"))
        assignments.extend((quic, {"os": "macos-15", "toolchain": toolchain})
                           for toolchain in ("stable", "1.96.0"))
        groups = {expression(jobs[name]["concurrency"]["group"], row)
                  for name, row in assignments}
        self.assertEqual(groups, {f"rama-macos-slot-{i}" for i in range(5)})

    def test_new_job_cannot_bypass_final_gate(self):
        self.workflow["jobs"]["new-test"] = copy.deepcopy(self.workflow["jobs"]["test-loom"])
        with self.assertRaises(AssertionError):
            validate(self.workflow, self.path)

    def test_heavy_job_cannot_bypass_cheap_checks(self):
        self.workflow["jobs"]["test-rust-base"]["needs"].remove("meta-lints")
        with self.assertRaises(AssertionError):
            validate(self.workflow, self.path)

    def test_missing_feature_partition(self):
        self.workflow["jobs"]["cargo-hack"]["strategy"]["matrix"]["partition"] = [1]
        with self.assertRaises(AssertionError):
            validate(self.workflow, self.path)

    def test_native_platform_and_toolchain_coverage(self):
        jobs = self.workflow["jobs"]
        rows = matrix_rows(jobs["test-rust-base"]["strategy"]["matrix"])
        self.assertEqual({(r["os"], r["toolchain"]) for r in rows}, {
            (os, "stable") for os in ("ubuntu-latest", "ubuntu-24.04-arm",
                                      "macos-15-intel", "macos-15", "windows-latest", "windows-11-arm")
        })
        rows = matrix_rows(jobs["check-rust"]["strategy"]["matrix"])
        self.assertEqual({(r["os"], r["toolchain"]) for r in rows}, {
            (os, toolchain) for os in ("ubuntu-latest", "macos-latest", "windows-latest")
            for toolchain in ("stable", "1.96.0")
        })

    def test_quic_platform_backend_and_toolchain_coverage(self):
        job = self.workflow["jobs"]["test-quic-interop-qa"]
        rows = matrix_rows(job["strategy"]["matrix"])
        backends = ("boring", "rustls-ring", "rustls-aws-lc")
        coverage = {(r["os"], r["toolchain"], b) for r in rows
                    for b in (backends if r["backends"] == "all" else (r["backends"],))}
        self.assertEqual(coverage, {(os, toolchain, backend)
                                   for os in ("ubuntu-latest", "macos-15", "windows-latest")
                                   for toolchain in ("stable", "1.96.0") for backend in backends})
        # Check actual step conditions, not just matrix labels: every row must run
        # each assigned backend separately, including after another step fails.
        for row in rows:
            selected = backends if row["backends"] == "all" else (row["backends"],)
            commands = []
            for step in job["steps"]:
                condition = step.get("if", "")
                if "matrix.backends" not in condition:
                    continue
                self.assertIn("!cancelled()", condition)
                if expression(condition.replace("!cancelled() && ", ""), row):
                    commands.append(step.get("run"))
            for backend, features, crypto in (
                ("boring", "boring", "boring"),
                ("rustls-ring", "rustls,ring", "ring"),
                ("rustls-aws-lc", "rustls,aws-lc", "aws-lc"),
            ):
                required = [
                    f"just rama-quic/qa-backend {features}",
                    f"cargo test -p rama-crypto --no-default-features --features {crypto} --locked",
                    f"cargo test -p rama-examples --no-default-features --features quic,{features} --test integration quic_ --locked -- --include-ignored",
                    f"cargo test -p rama-quic --no-default-features --features {features} --test many_connections --locked -- --include-ignored",
                    f"cargo check --bench quic_transport --no-default-features --features quic,{features} --locked",
                ] + [f"just rama-quic/qa-interop-{peer} {backend}"
                     for peer in ("common", "quinn", "quiche", "aioquic", "runner")]
                for command in required:
                    with self.subTest(row=row, command=command):
                        self.assertEqual(commands.count(command), int(backend in selected))
                expected_stress = row["os"] == "ubuntu-latest" and row["toolchain"] == "stable" and backend in selected
                self.assertEqual(commands.count(f"just rama-quic/qa-stress-backend {features}"), int(expected_stress))
                for selector in ("--lib dial9", "--test dial9_runtime"):
                    command = f"cargo test -p rama-quic --no-default-features --features dial9,{features} {selector} --locked"
                    expected = row["os"] == "ubuntu-latest" and row["toolchain"] == "stable" and backend in selected
                    self.assertEqual(sum(command in text.splitlines() for text in commands), int(expected))
            # Compiling without a built-in backend is host-specific, so every cell runs it.
            self.assertEqual(commands.count("just rama-quic/qa-custom-provider"),
                             int("boring" in selected))
            # The isolation check only reads the locked dependency graph, so one Linux cell
            # covers it and the scarce macOS/Windows hosts need no Python interpreter.
            expected_isolation = (row["os"] == "ubuntu-latest" and row["toolchain"] == "stable"
                                  and "boring" in selected)
            self.assertEqual(commands.count("just rama-quic/qa-boring-isolation"),
                             int(expected_isolation))
        self.assertEqual(sum(r["os"].startswith("macos") for r in rows), 2)
        self.assertEqual(sum(r["os"].startswith("windows") for r in rows), 2)

    def test_quic_feature_combinations(self):
        job = self.workflow["jobs"]["test-quic-interop-qa"]
        step = next(step for step in job["steps"] if step.get("name") == "QUIC backend combinations")
        rows = matrix_rows(job["strategy"]["matrix"])
        self.assertEqual([row for row in rows if expression(
            step["if"].replace("!cancelled() && ", ""), row)],
            [{"os": "ubuntu-latest", "toolchain": "stable", "backends": "boring"}])
        combinations = re.search(r"for features in (.*); do", step["run"])[1].split()
        actual = {frozenset(features.split(",")) for features in combinations}
        actual |= {frozenset(), frozenset({"boring"}), frozenset({"rustls", "ring"}),
                   frozenset({"rustls", "aws-lc"})}
        expected = {frozenset(combination) for size in range(5)
                    for combination in itertools.combinations(("boring", "rustls", "ring", "aws-lc"), size)}
        self.assertEqual(actual, expected)
        self.assertIn("cargo test -p rama-quic --no-default-features --locked",
                      (ROOT / "rama-quic/justfile").read_text())

    def test_quic_external_provider_and_docker_coverage(self):
        jobs = self.workflow["jobs"]
        external = jobs["test-quic-external-gnutls"]
        self.assertEqual(external["runs-on"], "ubuntu-24.04")
        self.assertEqual(matrix_rows(external["strategy"]["matrix"]),
                         [{"toolchain": "stable"}, {"toolchain": "1.96.0"}])
        self.assertEqual(sum(s.get("run") == "just rama-quic/qa-interop-gnutls"
                             for s in external["steps"]), 1)
        self.assertIn("rama-quic/e2e/gnutls-interop", (ROOT / "scripts/ci/check-format.sh").read_text())
        runner = jobs["test-quic-interop-runner"]
        self.assertEqual({r["backend"] for r in matrix_rows(runner["strategy"]["matrix"])},
                         {"boring", "rustls-ring", "rustls-aws-lc"})

    def test_cross_target_coverage(self):
        jobs = self.workflow["jobs"]
        rows = matrix_rows(jobs["precheck-rust-tier2"]["strategy"]["matrix"])
        self.assertEqual({(r["os"], r["target"]) for r in rows}, {
            ("ubuntu-latest", "armv7-linux-androideabi"),
            ("ubuntu-latest", "aarch64-linux-android"),
            ("ubuntu-latest", "i686-linux-android"),
            ("ubuntu-latest", "x86_64-linux-android"),
            ("macos-latest", "aarch64-apple-ios"),
            ("macos-15-intel", "x86_64-apple-ios"),
        })
        rows = matrix_rows(jobs["test-rust-linux-musl"]["strategy"]["matrix"])
        self.assertEqual({(r["os"], r["target"]) for r in rows}, {
            ("ubuntu-latest", "x86_64-unknown-linux-musl"),
            ("ubuntu-24.04-arm", "aarch64-unknown-linux-musl"),
        })

    def test_failed_skipped_or_cancelled_check_fails_final_gate(self):
        command = self.workflow["jobs"]["ci-success"]["steps"][0]["run"]
        for status in ("success", "failure", "skipped", "cancelled"):
            with self.subTest(status=status):
                result = subprocess.run(
                    ["bash", "-c", command], capture_output=True,
                    env={"RESULTS": '{"first":{"result":"success"},"second":{"result":"' + status + '"}}'},
                )
                self.assertEqual(result.returncode == 0, status == "success")

    def test_matrix_expansion_does_not_create_phantom_rows(self):
        self.assertEqual(matrix_rows({"include": [{"os": "macos-15"}, {"os": "windows-latest"}]}),
                         [{"os": "macos-15"}, {"os": "windows-latest"}])
        self.assertEqual(matrix_rows({"os": ["a", "b"], "include": [{"os": "a", "extra": 1}]}),
                         [{"os": "a", "extra": 1}, {"os": "b"}])

    def test_reincluded_scarce_runner_cannot_evade_budget_check(self):
        workflow = {"jobs": {"test": {
            "runs-on": "${{ matrix.os }}",
            "strategy": {"matrix": {
                "os": ["ubuntu-latest", "macos-latest"],
                "exclude": [{"os": "macos-latest"}],
                "include": [{"os": "macos-latest"}],
            }},
        }}}
        self.assertEqual(matrix_rows(workflow["jobs"]["test"]["strategy"]["matrix"]),
                         [{"os": "ubuntu-latest"}, {"os": "macos-latest"}])
        with self.assertRaises(AssertionError):
            validate(workflow, self.path.with_name("example.yml"))


if __name__ == "__main__":
    unittest.main()
