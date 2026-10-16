from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from fixture_process import running, stop, wait_ready


class FixtureProcessTests(unittest.TestCase):
    def test_workflow_failure_still_stops_owned_process(self):
        process = Mock()
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as root, patch(
            "fixture_process.subprocess.Popen", return_value=process
        ), patch("fixture_process.os.killpg") as kill:
            with self.assertRaisesRegex(ValueError, "workflow"):
                with running(["fixture"], Path(root) / "log"):
                    raise ValueError("workflow")
            kill.assert_called_once_with(process.pid, signal.SIGINT)
            process.wait.assert_called_once_with(timeout=30)

    def test_shutdown_timeout_kills_group_and_fails(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("fixture", 30), 0]
        with patch("fixture_process.os.killpg") as kill:
            with self.assertRaisesRegex(RuntimeError, "cleanly"):
                stop(process)
            self.assertEqual(
                [call.args[1] for call in kill.call_args_list],
                [signal.SIGINT, signal.SIGKILL],
            )

    def test_readiness_rejects_an_exited_process_even_with_ready_log(self):
        process = Mock()
        process.poll.return_value = 1
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "log"
            log.write_text("ready")
            with self.assertRaisesRegex(RuntimeError, "exited"):
                wait_ready(process, log, lambda text: "ready" in text)


if __name__ == "__main__":
    unittest.main()
