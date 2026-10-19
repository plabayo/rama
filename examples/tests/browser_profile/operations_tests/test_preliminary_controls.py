"""Negative certificate controls preserve each explicit preliminary request plan."""

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from flows import ReplayTarget, replay_args
from operations_tests.fixtures import JOINTS
from operations_tests.preliminary_fixtures import post_source
from preliminary import plan_preliminary, rebind_preliminary, write_preliminary
from replay import check_tls_hostname


class PreliminaryAuthenticationControlTests(unittest.TestCase):
    def test_actual_hostname_control_rebinds_every_owned_plan_and_only_route_fields(
        self,
    ):

        rows, source, value, sections = post_source()
        operation = next(
            operation for operation in source.operations if operation.name == "xhr"
        )
        requests = plan_preliminary(
            value, rows, sections, source, operation, (JOINTS["h3"],)
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = root / "authentication"
            probe.mkdir()
            target = ReplayTarget("h3", "https://capture.test:443", root / "ca.pem")
            files = write_preliminary(root / "owned-preliminary", requests, target)
            original = files[0].read_bytes()
            reference = requests[0].request
            command = replay_args(
                "rama",
                "archive",
                "output",
                target,
                "fetch",
                reference,
                preliminary_files=files,
            )
            command[-1] = target.origin + reference.uri
            command[-1:-1] = ["--resolve", "capture.test:443:127.0.0.1"]
            captured = []

            def run(arguments, **kwargs):
                captured.append(arguments)
                kwargs["stdout"].write("certificate identity mismatch\n")
                return SimpleNamespace(returncode=1)

            with patch("replay.subprocess.run", side_effect=run):
                check_tls_hostname(command, {}, probe)
            changed = captured[0]
            self.assertEqual(changed.count("--resolve"), 1)
            self.assertEqual(
                changed[changed.index("--resolve") + 1], "xapture.test:443:127.0.0.1"
            )
            replacement = Path(changed[changed.index("--pre-request") + 1])
            before = json.loads(original)
            after = json.loads(replacement.read_bytes())
            self.assertEqual(
                after["uri"], before["uri"].replace("capture.test", "xapture.test")
            )
            self.assertEqual(after["body_base64"], before["body_base64"])
            self.assertEqual(
                after["emulate_request_variant"], before["emulate_request_variant"]
            )
            self.assertEqual(
                after["emulate_connection_variant"],
                before["emulate_connection_variant"],
            )
            self.assertEqual(after["method"], "POST")
            self.assertEqual(files[0].read_bytes(), original)
            self.assertEqual(replacement.stat().st_mode & 0o777, 0o600)

    def test_hostname_control_rejects_an_unowned_or_different_origin_plan(self):

        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            probe = root / "auth"
            probe.mkdir()
            path = Path(outside) / "plan.json"
            path.write_text(json.dumps(dict(uri="https://other.test/x", headers=[])))
            command = ["rama", "--pre-request", str(path), "https://capture.test/x"]
            with self.assertRaisesRegex(ValueError, "owned"):
                rebind_preliminary(
                    command,
                    probe / "negative",
                    urlsplit(command[-1]),
                    urlsplit("https://wrong.test/x"),
                )
            owned = root / "plan.json"
            owned.write_bytes(path.read_bytes())
            command[2] = str(owned)
            with self.assertRaisesRegex(ValueError, "different origin"):
                rebind_preliminary(
                    command,
                    probe / "another",
                    urlsplit(command[-1]),
                    urlsplit("https://wrong.test/x"),
                )
