"""Exercise runner bookkeeping and bounded shutdown without Docker or network access."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, call, patch

from run_interop import compose_override, inspect_image, preflight, run_managed, snapshot_container_logs


class PrerequisiteTests(unittest.TestCase):
    def preflight_with_engine(self, engine):
        docker = {"Client": {"Version": "29.3.0"}, "Server": {"Version": engine}}
        responses = {
            ("openssl", "version"): "OpenSSL 3.6.2",
            ("docker", "compose", "version", "--short"): "v2.36.0",
            ("docker", "version", "--format", "{{json .}}"): json.dumps(docker),
            ("tshark", "--version"): "TShark (Wireshark) 4.6.6",
            ("docker", "info", "--format", "{{.OSType}}"): "linux",
            ("docker", "network", "ls", "--quiet"): "",
        }
        with patch("run_interop.shutil.which", return_value="/installed/tool"):
            with patch("run_interop.output", side_effect=lambda command: responses[tuple(command)]):
                return preflight()

    def test_new_client_does_not_hide_old_or_unknown_engine(self):
        for engine in ("27.5.1", "28.0.4", "unknown"):
            with self.subTest(engine=engine):
                with self.assertRaisesRegex(RuntimeError, r"Docker Engine >=28\.1 required"):
                    self.preflight_with_engine(engine)

    def test_supported_engine_is_recorded(self):
        for engine in ("28.1.0", "28.5.1", "29.3.0"):
            with self.subTest(engine=engine):
                self.assertEqual(self.preflight_with_engine(engine)["docker"]["Server"]["Version"], engine)


@unittest.skipUnless(os.name == "posix", "runner requires POSIX process groups")
class RunnerShutdownTests(unittest.TestCase):
    def test_signal_stops_child_before_returning(self):
        with tempfile.TemporaryDirectory() as temp:
            ready = Path(temp) / "ready"
            stopped = Path(temp) / "stopped"
            child = (
                "import signal,time; from pathlib import Path; "
                f"signal.signal(signal.SIGTERM, lambda *_: (Path({str(stopped)!r}).touch(), exit(0))); "
                f"Path({str(ready)!r}).touch(); time.sleep(30)"
            )
            launcher = (
                "import signal,sys; from run_interop import compose_override, inspect_image, run_managed, snapshot_container_logs\n"
                "def stop(*_): raise KeyboardInterrupt()\n"
                "signal.signal(signal.SIGTERM, stop)\n"
                f"run_managed([sys.executable, '-c', {child!r}])\n"
            )
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent))
            process = subprocess.Popen([sys.executable, "-c", launcher], env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "fake child did not start")
                process.send_signal(signal.SIGTERM)
                self.assertNotEqual(process.wait(timeout=5), 0)
                self.assertTrue(stopped.exists(), "child survived runner interruption")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

    def test_role_timeout_stops_the_group(self):
        process = Mock(pid=12345)
        process.wait.side_effect = [subprocess.TimeoutExpired("fake", 1800), 0, 0]
        with patch("run_interop.subprocess.Popen", return_value=process):
            with patch("run_interop.os.killpg") as killpg:
                with self.assertRaises(subprocess.TimeoutExpired):
                    run_managed(["fake"])
        self.assertEqual(killpg.call_args_list,
                         [call(12345, signal.SIGTERM), call(12345, signal.SIGKILL)])
        self.assertEqual(process.wait.call_args_list,
                         [call(timeout=1800), call(timeout=10), call(timeout=5)])

    def test_ignoring_term_escalates_to_group_kill_with_bounds(self):
        process = Mock(pid=12345)
        process.wait.side_effect = [KeyboardInterrupt(), subprocess.TimeoutExpired("fake", 10), -9]
        with patch("run_interop.subprocess.Popen", return_value=process) as popen:
            with patch("run_interop.os.killpg") as killpg:
                with self.assertRaises(KeyboardInterrupt):
                    run_managed(["fake"])
        popen.assert_called_once_with(["fake"], start_new_session=True)
        self.assertEqual(killpg.call_args_list,
                         [call(12345, signal.SIGTERM), call(12345, signal.SIGKILL)])
        self.assertEqual(process.wait.call_args_list,
                         [call(timeout=1800), call(timeout=10), call(timeout=5)])


class ContainerSnapshotTests(unittest.TestCase):
    def test_endpoints_have_explicit_shutdown_grace(self):
        services = compose_override("our-project", "linux/arm64", "sim@sha256:pinned")["services"]
        for role in ("client", "server"):
            self.assertEqual(services[role]["stop_grace_period"], "10s")
            self.assertEqual(services[role]["container_name"], f"our-project-{role}")
        self.assertEqual(services["sim"]["image"], "sim@sha256:pinned")
        self.assertEqual(services["sim"]["platform"], "linux/arm64")

    def test_no_project_containers_needs_no_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            artifacts = Path(temp)
            with (artifacts / "cleanup.log").open("w") as console:
                with patch("run_interop.subprocess.run", return_value=Mock(stdout=b"")) as run:
                    self.assertEqual(snapshot_container_logs(artifacts, {}, artifacts, console), [])
            self.assertEqual(run.call_count, 1)
            self.assertFalse((artifacts / "last-containers").exists())

    def test_copy_errors_do_not_prevent_other_service_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            artifacts = Path(temp)
            env = {"COMPOSE_PROJECT_NAME": "only-our-project", "COMPOSE_FILE": "/own/compose.json"}
            with (artifacts / "cleanup.log").open("w") as console:
                outcomes = [Mock(stdout=b"container-id"), Mock(),
                            subprocess.TimeoutExpired("sim copy", 10), Mock(), Mock()]
                with patch("run_interop.subprocess.run", side_effect=outcomes) as run:
                    errors = snapshot_container_logs(artifacts, env, artifacts, console)
            self.assertEqual(len(errors), 1)
            commands = [entry.args[0] for entry in run.call_args_list]
            self.assertEqual([command[-2] for command in commands[2:]],
                             ["sim:/logs/.", "client:/logs/.", "server:/logs/."])
            for invocation in run.call_args_list:
                self.assertEqual(invocation.kwargs["env"], env)
                self.assertEqual(invocation.kwargs["timeout"], 10)
                self.assertEqual(invocation.kwargs["cwd"], artifacts)
            self.assertIn("snapshot sim logs", (artifacts / "cleanup.log").read_text())


class ImageMetadataTests(unittest.TestCase):
    def test_inspection_selects_the_requested_platform(self):
        arm = {"Os": "linux", "Architecture": "arm64"}
        amd = {"Os": "linux", "Architecture": "amd64"}
        with patch("run_interop.output", side_effect=[json.dumps([arm]), json.dumps([amd])]) as read:
            self.assertEqual(inspect_image("peer:local", "linux/amd64"), amd)
            self.assertEqual(read.call_args.args[0][-2:], ["--platform", "linux/amd64"])
        with patch("run_interop.output", return_value=json.dumps([arm])) as read:
            self.assertEqual(inspect_image("peer:local", "linux/arm64"), arm)
            read.assert_called_once()
        with patch("run_interop.output", return_value=json.dumps([arm])):
            with self.assertRaises(RuntimeError):
                inspect_image("peer:local", "linux/amd64")


if __name__ == "__main__":
    unittest.main()
