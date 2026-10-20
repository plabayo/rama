"""Negative certificate controls preserve each explicit preliminary request plan."""

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from flows import ReplayTarget, replay_args, request_segments
from operations_tests.fixtures import JOINTS
from operations_tests.preliminary_fixtures import post_source, segment_fields
from preliminary import plan_preliminary, preliminary_arguments
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
            target = ReplayTarget(
                "h3",
                "https://capture.test:443",
                root / "ca.pem",
                resolve=("capture.test:443:127.0.0.1",),
            )
            segments = preliminary_arguments(requests, target)
            reference = requests[0].request
            command = replay_args(
                "rama",
                "archive",
                "output",
                target,
                "fetch",
                reference,
                preliminary_requests=segments,
            )
            original = list(command)
            captured = []

            def run(arguments, **kwargs):
                captured.append(arguments)
                kwargs["stdout"].write("certificate identity mismatch\n")
                return SimpleNamespace(returncode=1)

            with patch("replay.subprocess.run", side_effect=run):
                check_tls_hostname(command, {}, root)
            changed = captured[0]
            self.assertEqual(command, original)
            self.assertEqual(changed.count("--resolve"), 1)
            self.assertEqual(
                changed[changed.index("--resolve") + 1], "xapture.test:443:127.0.0.1"
            )
            # The route stays a client option, ahead of the first request.
            self.assertLess(changed.index("--resolve"), changed.index("--next"))
            before = segment_fields(request_segments(original)[0])
            after = segment_fields(request_segments(changed)[0])
            self.assertEqual(
                after["uri"], before["uri"].replace("capture.test", "xapture.test")
            )
            for field in ("data", "request", "connection", "method", "initiator"):
                self.assertEqual(after[field], before[field])
            self.assertEqual(after["method"], "POST")
            rebound = {
                "alt-used": "xapture.test:443",
                "origin": "https://xapture.test:443",
            }
            self.assertEqual(
                after["headers"],
                [
                    (name, rebound.get(name.lower(), value))
                    for name, value in before["headers"]
                ],
            )
            self.assertEqual(
                request_segments(changed)[-1][-1],
                "https://xapture.test:443" + reference.uri,
            )
