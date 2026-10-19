"""H1 uses the shared exact-operation and certificate-control replay path."""

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from operations_tests.http_fixtures import JOINT, ORIGIN, inspected, journey
from operations import OperationLedger
from replay import verify_tls_replay
from wire import parse_pdml


class HttpReplayTests(unittest.TestCase):
    def test_h1_replay_emits_six_exact_pinned_requests_and_tls_control(self):
        class CaptureReached(Exception):
            pass

        @contextmanager
        def process(*_args, **_kwargs):
            yield SimpleNamespace(returncode=0)

        document, page = journey()
        blocks = parse_pdml(ET.tostring(document), "mixed", 65320, include_data=True)
        source = inspected(blocks)
        planned = (
            OperationLedger.from_driver(
                blocks, page["protocols"], ORIGIN, page["report_url"]
            )
            .with_joints({"h1": {"connection_joints": {1: JOINT, 4: JOINT}}})
            .with_requests(source, blocks, {})
        )
        commands, probes = [], []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "headers.pdml").write_text("<pdml/>")
            with patch.multiple(
                "replay",
                running=process,
                wait_ready=lambda *_a: None,
                client_hellos=lambda *_a: [],
                replay_environment=lambda _e: {},
                check_missing_tls_bindings=lambda command, *_a, **_k: probes.append(
                    command
                ),
                run_replay=lambda command, **_k: commands.append(command),
            ), patch("replay.drain_capture", side_effect=CaptureReached) as drain:
                with self.assertRaises(CaptureReached):
                    verify_tls_replay(
                        SimpleNamespace(output=root, rama=Path("rama"), interface="lo"),
                        traffic=SimpleNamespace(frames=blocks, headers=blocks),
                        inspected=source,
                        server_command=[],
                        environment={},
                        certificate=root / "fixture.pem",
                        port=65320,
                        fixture_origin=ORIGIN,
                        operations=planned,
                    )
            self.assertEqual(len(commands), 6)
            self.assertEqual(len(probes), 1)
            self.assertEqual(drain.call_args.kwargs["expected_warmups"], 0)
            self.assertEqual(
                {
                    command[command.index("--emulate-request-variant") + 1]
                    for command in commands
                },
                {operation.request for operation in planned.operations},
            )
            for command in commands + probes:
                self.assertIn("--http1.1", command)
                self.assertIn("--cacert", command)
                self.assertIn("h1.capture.test:65320:127.0.0.1", command)
                self.assertIn(JOINT, command)
                self.assertNotIn("--emulate-warmup-connection-variant", command)
