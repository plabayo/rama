import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from adapter_support import copy_logs
from run_interop import implementations_without_heuristics, role_timeout, unsupported_policy


class AdapterTests(unittest.TestCase):
    def test_only_the_exact_127_endpoint_may_have_no_logs(self):
        for code in (0, 1, 127, 137):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temp:
                runner = SimpleNamespace(_rama_evidence={"case": "test"}, _rama_evidence_dir=Path(temp))
                state = [{"State": {"Running": False, "ExitCode": code}}]
                failure = subprocess.CompletedProcess([], 1, b"Could not find the file /logs/. in container")
                with patch("adapter_support.subprocess.check_output", side_effect=["id\n", json.dumps(state)]), \
                     patch("adapter_support.subprocess.run", return_value=failure):
                    if code == 127:
                        copy_logs(runner, "client", SimpleNamespace(name=temp))
                    else:
                        with self.assertRaises(RuntimeError):
                            copy_logs(runner, "client", SimpleNamespace(name=temp))
                self.assertEqual(runner._rama_evidence["client_exit"], code)

    def test_auto_unsupported_disabled_for_every_selected_implementation(self):
        self.assertEqual(implementations_without_heuristics(["peer-one", "peer-two"]), "rama,peer-one,peer-two")

    def test_ci_groups_cover_all_cases_once(self):
        lock = json.loads(Path(__file__).with_name("runner.lock.json").read_text())
        selected = [case for group in lock["case_groups"].values() for case in group]
        self.assertEqual(len(selected), len(set(selected)))
        self.assertEqual(set(selected), set(lock["cases"]))
        self.assertEqual(len(selected), 22)
        for group in lock["case_groups"].values():
            self.assertLess(2 * role_timeout(group, 2) + 20 * 60, 130 * 60)

    def test_crypto_limits_only_apply_to_client(self):
        for backend in ("boring", "rustls-ring", "rustls-aws-lc"):
            policy = unsupported_policy("server", backend, ["ngtcp2"])
            self.assertNotIn(("ngtcp2", "chacha20"), policy)
            self.assertNotIn(("ngtcp2", "v2"), policy)
            self.assertEqual(unsupported_policy("client", backend, ["ngtcp2"])[("ngtcp2", "chacha20")], {"client"})
