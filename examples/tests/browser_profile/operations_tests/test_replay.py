"""The shared replay runner emits the declared matrix and complete TLS plans."""

from contextlib import contextmanager
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from flows import FLOWS
from operations_tests.fixtures import FINAL, JOINTS, ORIGIN, bound
from replay import verify_tls_replay


class OperationReplayTests(unittest.TestCase):
    def test_shared_commands_keep_query_request_pins_discovery_and_tls_controls(self):
        class CaptureReached(Exception):
            pass

        @contextmanager
        def process(*_args, **_kwargs):
            yield SimpleNamespace(returncode=0)

        rows, planned, value, sections = bound(bootstrap=True)
        commands, probes = [], []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "headers.pdml").write_text("<pdml/>")
            args = SimpleNamespace(output=root, rama=Path("rama"), interface="lo")
            with patch.multiple(
                "replay",
                running=process,
                wait_ready=lambda *_a: None,
                client_hellos=lambda *_a: [],
                sections_from_wire=lambda *_a: sections,
                replay_environment=lambda _e: {},
                check_missing_tls_bindings=lambda command, *_a, **kwargs: probes.append(
                    (command, kwargs)
                ),
                run_replay=lambda command, **kwargs: commands.append((command, kwargs)),
            ), patch("replay.drain_capture", side_effect=CaptureReached) as drain:
                with self.assertRaises(CaptureReached):
                    verify_tls_replay(
                        args,
                        traffic=SimpleNamespace(frames=rows, headers=rows),
                        inspected=value,
                        server_command=[],
                        environment={},
                        certificate=root / "fixture.pem",
                        port=18443,
                        fixture_origin=ORIGIN,
                        operations=planned,
                    )
            self.assertEqual(len(commands), 7)
            self.assertEqual(len(probes), 2)
            self.assertEqual(
                {kwargs["protocol"] for _command, kwargs in probes}, {"h2", "h3"}
            )
            operations = {operation.name: operation for operation in planned.operations}
            counts = dict.fromkeys(FLOWS, 1)
            counts["navigate"] = 2
            self.assertEqual(drain.call_args.kwargs["expected_per_flow"], counts)
            self.assertEqual(drain.call_args.kwargs["expected_warmups"], 4)
            self.assertTrue(drain.call_args.kwargs["operations"].replay)
            seen = set()
            for command, kwargs in commands:
                operation = next(
                    operation
                    for operation in planned.operations
                    if "--emulate-request-variant" in command
                    and command[command.index("--emulate-request-variant") + 1]
                    == operation.request
                )
                seen.add(operation.name)
                self.assertEqual(
                    command[command.index("--emulate-connection-variant") + 1],
                    operation.joint,
                )
                self.assertIn(
                    (
                        ORIGIN.replace("https:", "wss:")
                        if operation.flow == "ws"
                        else ORIGIN
                    )
                    + operation.uri,
                    command,
                )
                self.assertIn("--cacert", command)
                self.assertIn("capture.test:18443:127.0.0.1", command)
                self.assertNotIn("--emulate-warmup-connection-variant", command)
                files = [
                    Path(command[index + 1])
                    for index, flag in enumerate(command)
                    if flag == "--pre-request"
                ]
                self.assertEqual(
                    len(files),
                    int(operation.protocol == "h3" and operation.name != "navigate"),
                )
                for file in files:
                    startup = json.loads(file.read_bytes())
                    self.assertEqual(startup["method"], "GET")
                    self.assertEqual(startup["uri"], FINAL)
                    self.assertEqual(
                        startup["emulate_connection_variant"], JOINTS["h3"]
                    )
                    self.assertEqual(
                        startup["emulate_request_variant"],
                        operations["navigate"].request,
                    )
                self.assertEqual(kwargs["flow"], operation.flow)
            self.assertEqual(seen, set(planned.names))
            h3_probe = next(
                command for command, kwargs in probes if kwargs["protocol"] == "h3"
            )
            self.assertIn(FINAL, h3_probe)
            self.assertIn(operations["navigate"].request, h3_probe)
            self.assertNotIn("--emulate-warmup-connection-variant", h3_probe)
