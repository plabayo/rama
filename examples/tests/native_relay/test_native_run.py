"""Exercise the actual runner's report/strict decision with real packet fixtures."""

from contextlib import nullcontext
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from identity import Identity
from run import execute

FIXTURES = Path(__file__).parent / "tests/fixtures"


class NativeRunnerTests(unittest.TestCase):
    def run_fixture(self, root, *, allow_differences, ua_enabled=False):
        args = SimpleNamespace(
            output=root,
            protocol="h1",
            peer=Path("peer"),
            fixture=Path("fixture"),
            interface="lo",
            allow_differences=allow_differences,
            without_mirroring=False,
        )
        authority = Identity(root / "ca.pem", root / "ca.key")
        origin = Identity(root / "origin.pem", root / "origin.key")

        def start(command, _log, environment=None):
            if command[0] == "peer":
                (root / "origin.log").write_text(
                    json.dumps(dict(ready="127.0.0.1:52438"))
                )
            elif command[0] == "fixture":
                (root / "relay-ready.json").write_text(
                    json.dumps(
                        dict(
                            listen="127.0.0.1:52439",
                            ua_enabled=ua_enabled,
                        )
                    )
                )
            elif command[0] == "dumpcap":
                (root / "wire.pcapng").write_bytes(b"owned capture")
            return nullcontext(Mock(returncode=0))

        def command(arguments, **kwargs):
            if arguments[0] == "peer":
                return subprocess.CompletedProcess(arguments, 0, stdout="{}\n{}\n")
            if arguments[0] == "tshark":
                decode = arguments[arguments.index("-d") + 1]
                keylog = arguments[arguments.index("-o") + 1]
                side = "ingress" if "52439" in decode else "egress"
                self.assertTrue(
                    keylog.endswith(
                        "client.keys" if side == "ingress" else "origin.keys"
                    )
                )
                kwargs["stdout"].write(
                    (FIXTURES / ("h1-" + side + ".pdml")).read_bytes()
                )
                return subprocess.CompletedProcess(arguments, 0)
            raise AssertionError(arguments)

        with patch("run.local_identities", return_value=(authority, origin)), patch(
            "run.running",
            side_effect=start,
        ), patch("run.wait_ready"), patch("run.subprocess.run", side_effect=command):
            return execute(args)

    def test_strict_mode_persists_the_real_report_before_refusing_differences(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "native fingerprint differs"):
                self.run_fixture(root, allow_differences=False)
            report = json.loads((root / "comparison.json").read_text())
            self.assertFalse(report["fingerprint_match"])
            self.assertTrue(report["supported_tls_facts_match"])
            self.assertFalse(report["ua_enabled"])

    def test_contract_mode_keeps_the_fingerprint_failure_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(self.run_fixture(root, allow_differences=True), 0)
            report = json.loads((root / "comparison.json").read_text())
            self.assertFalse(report["fingerprint_match"])
            self.assertTrue(report["bodies_and_trailers_match"])

    def test_runtime_ua_feature_must_be_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "must have UA disabled"):
                self.run_fixture(
                    Path(directory), allow_differences=True, ua_enabled=True
                )
