"""Export only after clean capture shutdown and graceful ingestion-worker drain."""

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from remote.helper import Session
from remote.tests.fixtures import GENERATION


class RemoteLifecycleTests(unittest.TestCase):
    def session(self, root):
        session = Session.__new__(Session)
        session.cell = "cd" * 16
        session.generation = GENERATION
        session.root = root
        session.port = 32543
        session.environment = {"DATABASE_URL": "owned-private-database"}
        session.check_bounds = MagicMock()
        session.processes = {
            name: SimpleNamespace(name=name, returncode=None)
            for name in ("dumpcap", "server", "postgres")
        }
        (root / "headers.pdml").write_bytes(b"<pdml/>")
        (root / "dumpcap.log").write_text(
            "Packets captured: 14\n"
            "Packets received/dropped on interface 'any': 14/0 "
            "(pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0)\n"
        )
        return session

    def test_finish_gracefully_drains_server_before_one_export_and_view(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = self.session(root)
            capture, server = session.processes["dumpcap"], session.processes["server"]
            events = []
            flushed = []

            def drain(*args, **kwargs):
                self.assertIs(args[0], capture)
                self.assertIsNone(server.returncode)
                self.assertEqual(kwargs["websocket_probe"], "driver-known-probe")
                (root / "headers.pdml").write_bytes(b"<pdml/>")
                events.append("drain_wire")
                return SimpleNamespace(bodies={"complete": True})

            def stop(process):
                events.append("stop_" + process.name)
                process.returncode = 0
                if process is server:
                    # Model queued captures becoming available only at graceful exit.
                    flushed.append("last-queued-capture")

            def command(arguments, **kwargs):
                self.assertEqual(capture.returncode, 0)
                self.assertEqual(server.returncode, 0)
                self.assertNotIn("dumpcap", session.processes)
                self.assertNotIn("server", session.processes)
                self.assertIsNone(session.processes["postgres"].returncode)
                self.assertEqual(kwargs["env"], session.environment)
                if "export" in arguments:
                    events.append("export")
                    self.assertEqual(flushed, ["last-queued-capture"])
                    Path(arguments[-1]).write_text(json.dumps(flushed))
                else:
                    self.assertIn("view", arguments)
                    events.append("view")
                    kwargs["stdout"].write(b"{}")
                return SimpleNamespace(returncode=0)

            with patch("remote.helper.drain_capture", side_effect=drain), patch(
                "remote.helper.stop", side_effect=stop
            ), patch("remote.helper.subprocess.run", side_effect=command) as run:
                receipt = session.finish("driver-known-probe")
            self.assertEqual(
                events, ["drain_wire", "stop_dumpcap", "stop_server", "export", "view"]
            )
            self.assertEqual(run.call_count, 2)
            self.assertEqual(receipt["capture_exit"], 0)
            self.assertEqual(receipt["server_exit"], 0)
            self.assertEqual(
                json.loads((root / "profiles.json").read_text()),
                ["last-queued-capture"],
            )
            self.assertFalse((root / "export.pending.json").exists())
            self.assertEqual(set(session.processes), {"postgres"})

    def test_nonzero_capture_or_server_exit_prevents_export(self):
        for failed in ("dumpcap", "server"):
            with self.subTest(
                failed=failed
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                session = self.session(root)
                events = []

                def stop(process):
                    events.append(process.name)
                    process.returncode = 1 if process.name == failed else 0

                def command(arguments, **kwargs):
                    if "export" in arguments:
                        Path(arguments[-1]).write_bytes(b"{}")
                    else:
                        kwargs["stdout"].write(b"{}")

                with patch(
                    "remote.helper.drain_capture",
                    return_value=SimpleNamespace(bodies={}),
                ), patch("remote.helper.stop", side_effect=stop), patch(
                    "remote.helper.subprocess.run", side_effect=command
                ) as run:
                    with self.assertRaisesRegex(RuntimeError, "did not exit"):
                        session.finish("driver-known-probe")
                run.assert_not_called()
                self.assertEqual(
                    events,
                    ["dumpcap"] if failed == "dumpcap" else ["dumpcap", "server"],
                )
                self.assertIn("postgres", session.processes)

    def test_nonzero_drop_counters_prevent_server_shutdown_and_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = self.session(root)
            log = root / "dumpcap.log"
            log.write_text(log.read_text().replace("ps_ifdrop:0", "ps_ifdrop:1"))

            def stop(process):
                process.returncode = 0

            def command(arguments, **kwargs):
                if "export" in arguments:
                    Path(arguments[-1]).write_bytes(b"{}")
                else:
                    kwargs["stdout"].write(b"{}")

            with patch(
                "remote.helper.drain_capture", return_value=SimpleNamespace(bodies={})
            ), patch("remote.helper.stop", side_effect=stop), patch(
                "remote.helper.subprocess.run", side_effect=command
            ) as run:
                with self.assertRaisesRegex(RuntimeError, "nonzero drops"):
                    session.finish("driver-known-probe")
            run.assert_not_called()
            self.assertIsNone(session.processes["server"].returncode)
