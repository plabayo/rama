"""Reviewable input, limits and native Machine configuration for one owner."""

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid

from flow_bodies import json_object

FP_ROOT = Path(__file__).resolve().parents[4] / "rama-fp"
sys.path.insert(0, str(FP_ROOT / "browserstack"))
from matrix import desktop_permutations, mobile_configs

APP_HOSTS = {
    "rama-fp": "fp.ramaproxy.org",
    "rama-fp-h1": "h1.fp.ramaproxy.org",
    "rama-fp-h2": "h2.fp.ramaproxy.org",
    "rama-fp-h3": "h3.fp.ramaproxy.org",
}
CAPABILITY_FIELDS = {"browserName", "browserVersion", "os", "osVersion", "deviceName"}
MAX_CELLS = 4
CELL_SECONDS = 180
IDLE_SECONDS = 300
OWNER_SECONDS = 1800
MAX_PRIVATE_BYTES = 256 * 1024 * 1024
MAX_CAPTURE_BYTES = 40 * 1024 * 1024  # Narrower than the existing decoded PDML limit.
MAX_KEYLOG_BYTES = 1024 * 1024
MAX_CONTROL_BYTES = 65536


def image_digest(value):
    if not re.fullmatch(
        r"registry\.fly\.io/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}", value
    ):
        raise ValueError("helper image must use an immutable Fly registry digest")
    return value


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise ValueError("invalid evidence generation")
    return value


def capability_rows():
    versions, browsers, systems = desktop_permutations
    for browser in browsers:
        for version in versions:
            for system, system_version in systems:
                if browser == "Safari" and (system != "OS X" or version != "latest"):
                    continue
                if browser == "Edge" and system != "Windows":
                    continue
                yield dict(
                    browserName=browser.lower(),
                    browserVersion=version,
                    os=system,
                    osVersion=system_version,
                )
    for device, version, browser in mobile_configs:
        yield dict(browserName=browser.lower(), deviceName=device, osVersion=version)


def checked_cells(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"format_version", "cells"}
        or type(value["format_version"]) is not int
        or value["format_version"] != 1
    ):
        raise ValueError("unsupported remote cell file")
    rows = value["cells"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_CELLS:
        raise ValueError("bounded explicit remote cells required")
    allowed = list(capability_rows())
    result = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"protocol", "capability"}:
            raise ValueError("invalid remote cell")
        if row["protocol"] not in ("h1", "h2", "h3"):
            raise ValueError("remote readiness protocol must be H1, H2 or H3")
        capability = row["capability"]
        if not isinstance(capability, dict) or set(capability) - CAPABILITY_FIELDS:
            raise ValueError("unexpected browser capability")
        if any(
            not isinstance(v, str) or not v or len(v) > 128 for v in capability.values()
        ):
            raise ValueError("invalid browser identity")
        capability = dict(capability)
        capability["browserName"] = capability.get("browserName", "").lower()
        if capability not in allowed:
            raise ValueError("capability is not an explicit existing matrix row")
        normalized = dict(protocol=row["protocol"], capability=capability)
        if normalized in result:
            raise ValueError("duplicate remote cell")
        result.append(normalized)
    return result


@dataclass(frozen=True)
class OwnerPlan:
    app: str
    hostname: str
    image: str
    port: int
    generation: str
    cells: list

    @classmethod
    def read(cls, app, image, port, capability_file, generation=None):
        if app not in APP_HOSTS:
            raise ValueError("use an existing authorized fingerprint app")
        if type(port) is not int or not 32000 <= port <= 59999:
            raise ValueError("owned listener must use one high TCP/UDP port")
        raw = Path(capability_file).read_bytes()
        if len(raw) > MAX_CONTROL_BYTES:
            raise ValueError("cell file byte limit")
        return cls(
            app,
            APP_HOSTS[app],
            image_digest(image),
            port,
            identifier(generation or uuid.uuid4().hex),
            checked_cells(json_object(raw)),
        )

    @property
    def name(self):
        return "rama-evidence-" + self.generation

    @property
    def origin(self):
        return f"https://{self.hostname}:{self.port}"

    def machine_config(self):
        return dict(
            image=self.image,
            init={
                "exec": [
                    "/opt/evidence/bin/python",
                    "/opt/evidence/repo/examples/tests/browser_profile/remote/helper.py",
                    "lease",
                ]
            },
            env={
                "EVIDENCE_GENERATION": self.generation,
                "EVIDENCE_HOSTNAME": self.hostname,
                "EVIDENCE_PORT": str(self.port),
                "DIAL9_ENABLED": "false",
            },
            guest={"cpu_kind": "shared", "cpus": 1, "memory_mb": 1024},
            services=[
                dict(
                    protocol=protocol,
                    internal_port=self.port,
                    ports=[dict(port=self.port)],
                    force_instance_key=None,
                )
                for protocol in ("tcp", "udp")
            ],
            metadata={"rama.evidence.owner": self.generation},
        )

    def dry_plan(self):
        config = self.machine_config()
        return dict(
            format_version=1,
            owner=asdict(self),
            machine=config,
            machine_config_sha256=digest(config),
            bounds=dict(
                cells=MAX_CELLS,
                cell_seconds=CELL_SECONDS,
                idle_seconds=IDLE_SECONDS,
                owner_seconds=OWNER_SECONDS,
                private_bytes=MAX_PRIVATE_BYTES,
                capture_bytes=MAX_CAPTURE_BYTES,
                keylog_bytes=MAX_KEYLOG_BYTES,
            ),
            create=[
                "flyctl",
                "machine",
                "run",
                self.image,
                "--app",
                self.app,
                "--machine-config",
                "machine.json",
                "--name",
                self.name,
                "--region",
                "fra",
                "--detach",
                "--restart",
                "no",
                "--skip-dns-registration",
            ],
            interface="one owned high port; no production mounts, listeners or DB",
            acceptance="H1/H2/H3 readiness only; each actual browser chooses its WebSocket transport. No public443 or complete matrix acceptance claim.",
            cleanup="quit driver, stop capture/FP/private PG independently, erase keys, destroy exact owned Machine, verify original config hashes",
        )


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
