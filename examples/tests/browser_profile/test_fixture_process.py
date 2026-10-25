from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from fixture_process import wait_ready


class FixtureProcessTests(unittest.TestCase):
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
