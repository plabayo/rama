"""Regression checks for scheduling mistakes that can silently lose CI coverage."""

import copy
import subprocess
import unittest

import yaml

from check_workflows import ROOT, matrix_rows, validate


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
        backends = ("rustls-ring", "rustls-aws-lc")
        coverage = {(r["os"], r["toolchain"], b) for r in rows
                    for b in (backends if r["backends"] == "both" else (r["backends"],))}
        self.assertEqual(coverage, {(os, toolchain, backend)
                                   for os in ("ubuntu-latest", "macos-15", "windows-latest")
                                   for toolchain in ("stable", "1.96.0") for backend in backends})
        for backend in backends:
            for peer in ("common", "quinn", "quiche", "aioquic", "runner"):
                command = f"just rama-quic/qa-interop-{peer} {backend}"
                self.assertEqual(sum(s.get("run") == command for s in job["steps"]), 1)

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
