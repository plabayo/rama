from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from fixture_process import require_h3_tshark, running, stop, wait_ready


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


class DecoderPrerequisiteTests(unittest.TestCase):
    def test_complete_schema_is_accepted(self):
        table = "F\tFrame stream\thttp3.frame_streamid\nF\tConnection\tquic.connection.number\n"
        with patch(
            "fixture_process.subprocess.check_output", return_value=table
        ) as command:
            require_h3_tshark()
        command.assert_called_once_with(
            ["tshark", "-G", "fields"], text=True, timeout=15
        )

    def test_legacy_decoder_is_rejected_before_capture(self):
        with patch(
            "fixture_process.subprocess.check_output",
            return_value="F\tConnection\tquic.connection.number\n",
        ):
            with self.assertRaisesRegex(
                RuntimeError, "tshark 4.6.*http3.frame_streamid"
            ):
                require_h3_tshark()


if __name__ == "__main__":
    unittest.main()
