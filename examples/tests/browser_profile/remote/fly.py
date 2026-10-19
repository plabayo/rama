"""Own one named Machine and its private SSH control channel."""

import hashlib
import json
import os
from pathlib import Path
import resource
import select
import subprocess
import time

from flow_bodies import json_object
from remote.config import MAX_CAPTURE_BYTES, MAX_CONTROL_BYTES, digest, identifier

HELPER = "/opt/evidence/repo/examples/tests/browser_profile/remote/helper.py"
PYTHON = "/opt/evidence/bin/python"


def checked_inventory(rows):
    if not isinstance(rows, list) or len(rows) > 128:
        raise ValueError("invalid or excessive app Machine inventory")
    result = {}
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("id"), str)
            or not isinstance(row.get("config"), dict)
            or row["id"] in result
        ):
            raise ValueError("missing or duplicate Machine identity/config")
        result[row["id"]] = row
    return result


def config_hashes(rows):
    return {identifier: digest(row["config"]) for identifier, row in rows.items()}


class FlyOwner:
    def __init__(self, plan, output):
        self.plan, self.output = plan, output
        self.machine = None
        self.before = None
        self.channel = None
        self.stderr = None
        self.create_attempted = False

    def command(self, arguments, *, timeout=30, output=False, file_limit=None):
        command = ["flyctl", *arguments, "--app", self.plan.app]

        def limit_file():
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))

        result = subprocess.run(
            command,
            cwd=self.output,
            capture_output=True,
            timeout=timeout,
            check=True,
            preexec_fn=limit_file if file_limit is not None else None,
        )
        if len(result.stdout) > 4 * 1024 * 1024:
            raise ValueError("Fly response byte limit")
        return result.stdout if output else None

    def inventory(self):
        return checked_inventory(
            json.loads(self.command(["machine", "list", "--json"], output=True))
        )

    def owned(self, row):
        config = row["config"]
        return (
            row.get("name") == self.plan.name
            and config.get("metadata", {}).get("rama.evidence.owner")
            == self.plan.generation
            and config.get("image") == self.plan.image
        )

    def adopt(self, rows):
        candidates = [
            key
            for key, row in rows.items()
            if self.owned(row) and key not in (self.before or {})
        ]
        if len(candidates) != 1:
            raise ValueError("created Machine has no unique owned identity")
        self.machine = candidates[0]
        actual = rows[self.machine]["config"]
        expected = self.plan.machine_config()
        # Fly may add image/init bookkeeping; native listener/mount boundaries are exact.
        if actual.get("services") != expected["services"] or actual.get("mounts"):
            raise ValueError("owned Machine services or mounts differ")
        if (
            config_hashes(
                {key: row for key, row in rows.items() if key != self.machine}
            )
            != self.before
        ):
            raise ValueError("existing Machine configuration changed")

    def create(self):
        rows = self.inventory()
        self.before = config_hashes(rows)
        if any(
            row.get("name") == self.plan.name
            or row["config"].get("metadata", {}).get("rama.evidence.owner")
            == self.plan.generation
            for row in rows.values()
        ):
            raise ValueError("owner generation already exists")
        for row in rows.values():
            for service in row["config"].get("services", []):
                for port in service.get("ports", []):
                    if port.get("port") == self.plan.port:
                        raise ValueError("selected high port is already registered")
        config = self.output / "machine.json"
        config.write_text(json.dumps(self.plan.machine_config(), indent=2) + "\n")
        config.chmod(0o600)
        self.create_attempted = True
        try:
            self.command(
                [
                    "machine",
                    "run",
                    self.plan.image,
                    "--machine-config",
                    str(config),
                    "--name",
                    self.plan.name,
                    "--region",
                    "fra",
                    "--detach",
                    "--restart",
                    "no",
                    "--skip-dns-registration",
                ],
                timeout=120,
            )
        finally:
            # Reconcile an unknown create outcome before any cleanup decision.
            self.adopt(self.inventory())
        self.stderr = (self.output / "helper-ssh.log").open("xb")
        self.channel = subprocess.Popen(
            [
                "flyctl",
                "ssh",
                "console",
                "--app",
                self.plan.app,
                "--machine",
                self.machine,
                "--quiet",
                "--pty=false",
                "-C",
                f"{PYTHON} {HELPER} session",
            ],
            cwd=self.output,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            start_new_session=True,
        )
        helper = self.request("ping", timeout=60)
        if (
            helper.get("generation") != self.plan.generation
            or not re_full_digest(helper.get("rama_sha256"))
            or helper.get("helper_sha256")
            != hashlib.sha256(
                Path(__file__).with_name("helper.py").read_bytes()
            ).hexdigest()
        ):
            raise ValueError("helper provenance missing")
        return dict(
            machine=self.machine,
            image=self.plan.image,
            original_configs=self.before,
            helper=helper,
            lease="local advisory lock plus before/after app inventory; no distributed atomic lease",
        )

    def request(self, command, *, timeout=30, **fields):
        message = (
            json.dumps(
                dict(generation=self.plan.generation, command=command, **fields)
            ).encode()
            + b"\n"
        )
        if len(message) > MAX_CONTROL_BYTES or self.channel is None:
            raise ValueError("invalid owned helper request")
        self.channel.stdin.write(message)
        self.channel.stdin.flush()
        deadline = time.monotonic() + timeout
        raw = bytearray()
        while b"\n" not in raw:
            remaining = deadline - time.monotonic()
            if (
                remaining <= 0
                or not select.select([self.channel.stdout], [], [], remaining)[0]
            ):
                raise TimeoutError("owned helper acknowledgement")
            chunk = os.read(
                self.channel.stdout.fileno(),
                min(4096, MAX_CONTROL_BYTES + 1 - len(raw)),
            )
            if not chunk:
                raise RuntimeError("owned helper control channel closed")
            raw.extend(chunk)
            if len(raw) > MAX_CONTROL_BYTES:
                raise ValueError("owned helper response limit")
        if raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
            raise ValueError("unexpected owned helper control bytes")
        value = json_object(raw)
        if (
            value.get("generation") != self.plan.generation
            or value.get("ok") is not True
            or value.get("command") != command
            or not isinstance(value.get("result"), dict)
        ):
            raise ValueError("invalid owned helper acknowledgement")
        return value["result"]

    def download(self, cell, name, path, expected):
        identifier(cell)
        if (
            name not in {"profiles.json", "inspected.json", "headers.pdml"}
            or path.exists()
        ):
            raise ValueError("unowned or existing evidence destination")
        if (
            not isinstance(expected, dict)
            or set(expected) != {"bytes", "sha256"}
            or type(expected["bytes"]) is not int
            or not 0 <= expected["bytes"] <= MAX_CAPTURE_BYTES
            or not re_full_digest(expected["sha256"])
        ):
            raise ValueError("invalid evidence file metadata")
        self.command(
            [
                "ssh",
                "sftp",
                "get",
                f"/evidence/{cell}/{name}",
                str(path),
                "--machine",
                self.machine,
                "--quiet",
            ],
            timeout=60,
            file_limit=expected["bytes"],
        )
        path.chmod(0o600)
        if (
            path.stat().st_size != expected["bytes"]
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected["sha256"]
        ):
            raise ValueError("downloaded evidence digest mismatch")

    def destroy(self):
        outcomes = {}
        if self.channel is not None:
            try:
                self.channel.stdin.close()
                self.channel.wait(timeout=30)
                outcomes["helper_exit"] = self.channel.returncode == 0
            except Exception:
                outcomes["helper_exit"] = False
                try:
                    self.channel.kill()
                    self.channel.wait(timeout=5)
                except Exception:
                    pass
            finally:
                try:
                    self.stderr.close()
                except Exception:
                    outcomes["ssh_log_closed"] = False
        if self.machine is None and self.create_attempted:
            # Only an exact owner identity can be adopted after a partial create.
            try:
                self.adopt(self.inventory())
            except Exception:
                pass
        if self.machine is not None:
            try:
                self.command(
                    ["machine", "destroy", self.machine, "--force"], timeout=60
                )
                outcomes["destroyed"] = True
            except Exception:
                outcomes["destroyed"] = False
        try:
            rows = self.inventory()
            outcomes["absent"] = (
                self.machine not in rows
                if self.machine is not None
                else not any(
                    self.owned(row) and key not in (self.before or {})
                    for key, row in rows.items()
                )
            )
            outcomes["existing_configs_unchanged"] = config_hashes(rows) == self.before
        except Exception:
            outcomes["absent"] = outcomes["existing_configs_unchanged"] = False
        return outcomes


def re_full_digest(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
