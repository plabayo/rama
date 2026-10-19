"""Remote session and controller cleanup ownership."""

from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from remote.run import main, run_cell
from remote.tests.fixtures import IMAGE, cells, plan


class RemoteControllerTests(unittest.TestCase):
    def test_unacknowledged_start_still_attempts_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = MagicMock()

            def request(command, **kwargs):
                if command == "start":
                    raise TimeoutError("acknowledgement lost")
                return {"server": True, "postgres": True}

            owner.request.side_effect = request
            args = SimpleNamespace(output=Path(directory))
            _root, receipt = run_cell(owner, plan(), cells()["cells"][0], 0, args, {})
            self.assertEqual(
                [call.args[0] for call in owner.request.call_args_list],
                ["start", "clean"],
            )
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["quit_outcome"], "not_attempted")

    def test_constructor_failure_does_not_claim_provider_absence_or_skip_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = MagicMock()
            owner.request.return_value = {"server": True}
            args = SimpleNamespace(output=Path(directory))
            secret = dict(
                BROWSERSTACK_USERNAME="placeholder-user",
                BROWSERSTACK_ACCESS_KEY="placeholder-key",
            )
            with patch(
                "remote.run.remote_session",
                side_effect=TimeoutError("constructor uncertain"),
            ):
                _root, receipt = run_cell(
                    owner, plan(), cells()["cells"][0], 0, args, secret
                )
            self.assertTrue(receipt["session_creation_attempted"])
            self.assertFalse(receipt["session_started"])
            self.assertEqual(receipt["quit_outcome"], "not_created_or_unconfirmed")
            self.assertEqual(receipt["provider_absence"], "not_independently_verified")
            self.assertEqual(owner.request.call_args.args, ("clean",))

    def test_cleanup_failure_prevents_readiness_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capability = root / "cells.json"
            capability.write_text(json.dumps(cells()))
            binary = root / "rama"
            binary.write_bytes(b"not-executed")
            output = root / "output"
            owner = MagicMock()
            owner.create.return_value = {"machine": "owned"}
            owner.destroy.return_value = {
                "absent": False,
                "existing_configs_unchanged": True,
            }

            def verified(*_args):
                cell_root = output / ("cd" * 16)
                cell_root.mkdir()
                return cell_root, dict(status="verified-awaiting-owner-cleanup")

            with patch("remote.run.credentials", return_value={}), patch(
                "remote.run.FlyOwner", return_value=owner
            ), patch("remote.run.local_port_guard", return_value=nullcontext()), patch(
                "remote.run.run_cell", side_effect=verified
            ):
                code = main(
                    [
                        "--output",
                        str(output),
                        "--capabilities",
                        str(capability),
                        "--app",
                        "rama-fp-h3",
                        "--image",
                        IMAGE,
                        "--rama",
                        str(binary),
                        "--execute",
                    ]
                )
            self.assertEqual(code, 1)
            owner.destroy.assert_called_once_with()
            receipt = json.loads((output / ("cd" * 16) / "cell.json").read_text())
            self.assertEqual(receipt["status"], "failed")


if __name__ == "__main__":
    unittest.main()
