"""Regression tests for credential isolation, including deliberate unsafe mutations."""

import unittest
import yaml
from check_workflows import ROOT, validate_security


class SecretBoundaryTests(unittest.TestCase):
    def load(self, name):
        path = ROOT / ".github/workflows" / name
        return path, yaml.safe_load(path.read_text())

    def test_build_cannot_gain_write_token(self):
        path, workflow = self.load("CI.yml")
        workflow["jobs"]["precheck-rust"]["permissions"] = {"contents": "write"}
        with self.assertRaisesRegex(AssertionError, "Privileged|Builds"):
            validate_security(workflow, path)

    def test_secret_in_build_environment_is_rejected(self):
        path, workflow = self.load("RamaCLIRelease.yaml")
        workflow["jobs"]["build-release-macos"].setdefault("env", {})["KEY"] = "${{ secrets.AC_API_KEY }}"
        with self.assertRaisesRegex(AssertionError, "Builds"):
            validate_security(workflow, path)

    def test_signing_job_cannot_restore_cache(self):
        path, workflow = self.load("RamaCLIRelease.yaml")
        workflow["jobs"]["sign-release-macos"]["steps"].append({"uses": "actions/cache@v4"})
        with self.assertRaisesRegex(AssertionError, "Privileged"):
            validate_security(workflow, path)

    def test_signing_job_cannot_build(self):
        path, workflow = self.load("RamaCLIRelease.yaml")
        workflow["jobs"]["sign-release-macos"]["steps"].append({"run": "cargo build"})
        with self.assertRaisesRegex(AssertionError, "Builds"):
            validate_security(workflow, path)

    def test_miri_cannot_cache_or_upload_output(self):
        for action in ("actions/cache@v4", "actions/upload-artifact@v7"):
            path, workflow = self.load("CI-unstable.yml")
            workflow["jobs"]["test-ffi-apple-ne-miri"]["steps"].append({"uses": action})
            with self.assertRaisesRegex(AssertionError, "Miri"):
                validate_security(workflow, path)

    def test_checkout_cannot_retain_token(self):
        path, workflow = self.load("CI.yml")
        workflow["jobs"]["precheck-rust"]["steps"][0]["with"]["persist-credentials"] = True
        with self.assertRaisesRegex(AssertionError, "Persisted"):
            validate_security(workflow, path)

    def test_release_cannot_build_an_unrelated_ref(self):
        path, workflow = self.load("RamaCLIRelease.yaml")
        workflow["jobs"]["build-release-linux"]["steps"][0]["with"]["ref"] = "main"
        with self.assertRaisesRegex(AssertionError, "resolved release tag"):
            validate_security(workflow, path)

    def test_deny_by_default(self):
        path, workflow = self.load("CI.yml")
        workflow["permissions"] = {"contents": "read"}
        with self.assertRaisesRegex(AssertionError, "default to none"):
            validate_security(workflow, path)
