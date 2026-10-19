"""Exact Machine ownership, control framing and evidence retrieval."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from remote.config import MAX_CAPTURE_BYTES
from remote.fly import FlyOwner, config_hashes
from remote.tests.fixtures import GENERATION, machine, plan


class FlyOwnershipTests(unittest.TestCase):
    def test_partial_create_adopts_only_new_exact_owner_and_checks_other_configs(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = FlyOwner(plan(), Path(directory))
            old = machine("old", dict(image="production", services=[]))
            owner.before = config_hashes({"old": old})
            new = machine("new", plan().machine_config(), plan().name)
            owner.adopt({"old": old, "new": new})
            self.assertEqual(owner.machine, "new")
            changed = deepcopy(old)
            changed["config"]["image"] = "other"
            with self.assertRaises(ValueError):
                owner.adopt({"old": changed, "new": new})
            for mutation in (
                lambda row: row["config"]["metadata"].update(
                    {"rama.evidence.owner": "ef" * 16}
                ),
                lambda row: row["config"].update(image="wrong"),
            ):
                invalid = deepcopy(new)
                mutation(invalid)
                with self.assertRaises(ValueError):
                    owner.adopt({"old": old, "new": invalid})
            owner.before = config_hashes({"new": new})
            with self.assertRaises(ValueError):
                owner.adopt({"new": new})

    def test_native_fly_service_serialization_adopts_only_exact_bindings(self):
        # Actual Fly response: empty handlers are omitted, and its unset instance
        # key is explicit null. Keep the requested and returned boundaries equal.
        services = [
            {
                "protocol": protocol,
                "internal_port": 32543,
                "ports": [{"port": 32543}],
                "force_instance_key": None,
            }
            for protocol in ("tcp", "udp")
        ]
        with tempfile.TemporaryDirectory() as directory:
            owner = FlyOwner(plan(), Path(directory))
            owner.before = {}
            config = plan().machine_config()
            config["services"] = services
            actual = machine("new", config, plan().name)
            owner.adopt({"new": actual})
            self.assertEqual(owner.machine, "new")
            for change in (
                lambda row: row["config"]["services"][0]["ports"][0].update(port=443),
                lambda row: row["config"]["services"][0]["ports"][0].update(
                    handlers=["tls"]
                ),
                lambda row: row["config"]["services"][0].update(
                    force_instance_key="other"
                ),
                lambda row: row["config"].update(mounts=[{"volume": "unowned"}]),
            ):
                altered = deepcopy(actual)
                change(altered)
                with self.subTest(change=change), self.assertRaisesRegex(
                    ValueError, "services or mounts differ"
                ):
                    owner.adopt({"new": altered})

    def test_destroy_exact_owned_machine_even_when_helper_exit_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = FlyOwner(plan(), Path(directory))
            owner.machine = "new"
            owner.before = {}
            owner.channel = MagicMock()
            owner.channel.wait.side_effect = [TimeoutError(), 0]
            owner.stderr = MagicMock()
            with patch.object(owner, "command") as command, patch.object(
                owner, "inventory", return_value={}
            ):
                result = owner.destroy()
            command.assert_called_once_with(
                ["machine", "destroy", "new", "--force"], timeout=60
            )
            self.assertFalse(result["helper_exit"])
            self.assertTrue(result["absent"])
            self.assertTrue(result["existing_configs_unchanged"])

    def test_download_enforces_declared_size_hash_and_private_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = FlyOwner(plan(), Path(directory))
            owner.machine = "new"
            path = Path(directory) / "profiles.json"
            raw = b"{}"
            expected = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

            def transfer(*args, **kwargs):
                self.assertEqual(kwargs["file_limit"], len(raw))
                path.write_bytes(raw)

            with patch.object(owner, "command", side_effect=transfer):
                owner.download("cd" * 16, "profiles.json", path, expected)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.unlink()
            for metadata, name in (
                (dict(expected, bytes=MAX_CAPTURE_BYTES + 1), "profiles.json"),
                (dict(expected, sha256="not-digest"), "profiles.json"),
                (expected, "server.keys"),
            ):
                with patch.object(owner, "command") as command, self.assertRaises(
                    ValueError
                ):
                    owner.download("cd" * 16, name, path, metadata)
                command.assert_not_called()
            with patch.object(
                owner, "command", side_effect=lambda *a, **kw: path.write_bytes(b"[]")
            ), self.assertRaises(ValueError):
                owner.download("cd" * 16, "profiles.json", path, expected)

    def test_control_ack_requires_current_generation_and_exact_framing(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = FlyOwner(plan(), Path(directory))
            owner.channel = MagicMock()
            owner.channel.stdout.fileno.return_value = 77
            for generation, extra, accepted in (
                (GENERATION, b"", True),
                ("cd" * 16, b"", False),
                (GENERATION, b"unowned bytes", False),
            ):
                raw = (
                    json.dumps(
                        dict(
                            ok=True,
                            generation=generation,
                            command="ping",
                            result={"alive": True},
                        )
                    ).encode()
                    + b"\n"
                    + extra
                )
                with patch(
                    "remote.fly.select.select",
                    return_value=([owner.channel.stdout], [], []),
                ), patch("remote.fly.os.read", return_value=raw):
                    if accepted:
                        self.assertEqual(owner.request("ping"), {"alive": True})
                    else:
                        with self.assertRaises(ValueError):
                            owner.request("ping")


if __name__ == "__main__":
    unittest.main()
