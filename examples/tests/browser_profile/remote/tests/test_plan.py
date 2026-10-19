"""Plan validation, private configuration, capture budgets and expiry."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from remote.config import OwnerPlan, checked_cells
from remote.helper import (
    Session,
    bounded_tree,
    cell_environment,
    check_capture_counters,
    lease,
)
from remote.run import credentials, main
from remote.tests.fixtures import CAPABILITY, IMAGE, cells, plan


class RemotePlanningTests(unittest.TestCase):
    def test_dry_plan_never_loads_credentials_or_runs_fly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capability = root / "cells.json"
            capability.write_text(json.dumps(cells()))
            output = root / "plan"
            with patch(
                "remote.run.credentials", side_effect=AssertionError("credential read")
            ), patch("remote.run.FlyOwner", side_effect=AssertionError("Fly access")):
                self.assertEqual(
                    main(
                        [
                            "--output",
                            str(output),
                            "--capabilities",
                            str(capability),
                            "--app",
                            "rama-fp-h3",
                            "--image",
                            IMAGE,
                        ]
                    ),
                    0,
                )
            value = json.loads((output / "plan.json").read_text())
            self.assertEqual(
                value["machine"]["services"], plan().machine_config()["services"]
            )
            self.assertNotIn("secrets", value["machine"])
            self.assertNotIn("mounts", value["machine"])
            self.assertEqual((output / "plan.json").stat().st_mode & 0o777, 0o600)

    def test_reject_h1_unknown_matrix_and_mutable_image_before_output(self):
        for update in (
            dict(protocol="h1"),
            dict(capability=dict(CAPABILITY, browserVersion="invented")),
            dict(capability=dict(CAPABILITY, acceptInsecureCerts="true")),
        ):
            value = cells()
            value["cells"][0].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                checked_cells(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cells.json"
            path.write_text(json.dumps(cells()))
            for app, image, port in (
                ("other-app", IMAGE, 32543),
                ("rama-fp-h3", "registry.fly.io/rama-fp:edge", 32543),
                ("rama-fp-h3", IMAGE, 443),
            ):
                with self.subTest(app=app, image=image, port=port), self.assertRaises(
                    ValueError
                ):
                    OwnerPlan.read(app, image, port, path)

    def test_credential_loader_is_private_literal_and_never_sources_storage_cookie(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.env"
            path.write_text(
                "BROWSERSTACK_USERNAME='owned'\nBROWSERSTACK_ACCESS_KEY='literal$word'\nRAMA_FP_STORAGE_COOKIE='not-selected'\n"
            )
            path.chmod(0o600)
            self.assertEqual(
                credentials(path),
                dict(
                    BROWSERSTACK_USERNAME="owned",
                    BROWSERSTACK_ACCESS_KEY="literal$word",
                ),
            )
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                credentials(path)
            path.chmod(0o600)
            link = path.with_name("link")
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                credentials(link)

    def test_child_env_keeps_issuer_but_excludes_production_database_auth_and_exports(
        self,
    ):
        original = dict(
            DATABASE_URL="prod",
            RAMA_FP_DATABASE_URL="prod2",
            PGHOST="prod",
            AWS_ACCESS_KEY_ID="secret",
            S3_BUCKET="private",
            DIAL9_ENABLED="true",
            BROWSERSTACK_ACCESS_KEY="key",
            RAMA_FP_STORAGE_COOKIE="cookie",
            SSLKEYLOGFILE="unowned",
            RAMA_TLS_REMOTE="issuer",
            RAMA_TLS_REMOTE_AUTH="issuer-key",
            PATH="tools",
        )
        child = cell_environment(
            original, "host=/owned/socket dbname=owned", Path("/owned")
        )
        self.assertEqual(child["DATABASE_URL"], "host=/owned/socket dbname=owned")
        self.assertEqual(child["RAMA_FP_DATABASE_URL"], child["DATABASE_URL"])
        self.assertEqual(child["RAMA_TLS_REMOTE_AUTH"], "issuer-key")
        for key in (
            "PGHOST",
            "AWS_ACCESS_KEY_ID",
            "S3_BUCKET",
            "BROWSERSTACK_ACCESS_KEY",
            "RAMA_FP_STORAGE_COOKIE",
        ):
            self.assertNotIn(key, child)
        self.assertEqual(child["DIAL9_ENABLED"], "false")
        self.assertEqual(child["SSLKEYLOGFILE"], "/owned/server.keys")
        self.assertEqual(original["DATABASE_URL"], "prod")

    def test_capture_requires_positive_count_and_each_drop_counter_zero(self):
        log = "Packets captured: 14\nPackets received/dropped on interface 'any': 14/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0)\n"
        check_capture_counters(log)
        for bad in (
            log.replace("captured: 14", "captured: 0"),
            log.replace("ps_ifdrop:0", "ps_ifdrop:1"),
            log.replace("14/0", "14/1"),
            "",
            log + log,
        ):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                check_capture_counters(bad)

    def test_actual_evidence_walk_rejects_budget_keylog_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one").write_bytes(b"12345")
            self.assertEqual(bounded_tree(root), 5)
            with patch("remote.helper.MAX_PRIVATE_BYTES", 4), self.assertRaises(
                RuntimeError
            ):
                bounded_tree(root)
            (root / "server.keys").write_bytes(b"123")
            with patch("remote.helper.MAX_KEYLOG_BYTES", 2), self.assertRaises(
                RuntimeError
            ):
                bounded_tree(root)
            (root / "link").symlink_to(root / "one")
            with self.assertRaises(RuntimeError):
                bounded_tree(root)

    def test_owner_lease_stops_session_on_absolute_or_idle_deadline(self):
        for idle in (False, True):
            with self.subTest(idle=idle), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "evidence"
                with patch("remote.helper.ROOT", root), patch(
                    "remote.helper.os.chown"
                ), patch("remote.helper.time.sleep"), patch(
                    "remote.helper.stop_session"
                ) as stop_session:
                    if idle:
                        with patch(
                            "remote.helper.time.time",
                            side_effect=lambda: (root / "heartbeat").stat().st_mtime
                            + 301,
                        ):
                            lease()
                    else:
                        with patch(
                            "remote.helper.time.monotonic", side_effect=[0, 0, 1800]
                        ):
                            lease()
                    stop_session.assert_called_once_with()

    def test_cleanup_attempts_other_processes_files_after_one_stop_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = Session.__new__(Session)
            session.cell = "cd" * 16
            session.root = root
            session.environment = {}
            session.deadline = 1
            session.logs = []
            for name in ("pg", "socket"):
                (root / name).mkdir()
            (root / "server.keys").write_text("private")
            session.processes = {
                name: MagicMock() for name in ("dumpcap", "server", "postgres")
            }
            for process in session.processes.values():
                process.poll.return_value = 0
            seen = []

            def stop(process):
                seen.append(process)
                if len(seen) == 1:
                    raise RuntimeError("first stop failure")

            with patch("remote.helper.stop", side_effect=stop), self.assertRaises(
                RuntimeError
            ):
                session.clean()
            self.assertEqual(len(seen), 3)
            self.assertFalse((root / "server.keys").exists())
            self.assertFalse((root / "pg").exists())
            self.assertFalse((root / "socket").exists())
            self.assertIsNone(session.root)
            self.assertFalse(json.loads((root / "cleanup.json").read_text())["dumpcap"])


if __name__ == "__main__":
    unittest.main()
