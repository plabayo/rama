"""Explicit H1 cells use the same owned helper with an H1-only native listener."""

import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from remote.helper import Session


class RemoteHttpHelperTests(unittest.TestCase):
    def test_actual_start_uses_declared_protocol_without_changing_tls_or_ownership(
        self,
    ):
        for protocol, versions in (("h1", "h1"), ("h2", "h1,h2"), ("h3", "auto")):
            with self.subTest(
                protocol=protocol
            ), tempfile.TemporaryDirectory() as directory:
                session = Session.__new__(Session)
                session.cell = None
                session.uid = os.getuid()
                session.user = "fixture"
                session.generation = "ab" * 16
                session.port = 32543
                session.hostname = "h1.capture.test"
                session.spawn = MagicMock(
                    return_value=SimpleNamespace(pid=4321, poll=lambda: None)
                )
                session.check_bounds = MagicMock()
                with (
                    patch("remote.helper.ROOT", Path(directory)),
                    patch("remote.helper.os.chown"),
                    patch("remote.helper.signal.alarm"),
                    patch(
                        "remote.helper.pg_program", side_effect=lambda program: program
                    ),
                    patch(
                        "remote.helper.subprocess.run",
                        return_value=SimpleNamespace(returncode=0),
                    ),
                    patch("remote.helper.wait_ready"),
                ):
                    receipt = session.start("cd" * 16, protocol)
                server = next(
                    call
                    for call in session.spawn.call_args_list
                    if call.args[0] == "server"
                )
                command = server.args[1]
                self.assertEqual(command[command.index("--http-version") + 1], versions)
                self.assertIn("--secure", command)
                self.assertEqual(command[command.index("--graceful") + 1], "10")
                self.assertEqual(
                    server.kwargs["environment"]["DATABASE_URL"],
                    server.kwargs["environment"]["RAMA_FP_DATABASE_URL"],
                )
                self.assertTrue(receipt["private_database"])
                self.assertEqual(receipt["port"], 32543)
