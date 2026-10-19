#!/usr/bin/env python3
"""Plan, then explicitly execute a small privately owned remote readiness run."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[3] / "rama-fp"))
sys.path.insert(0, str(HERE.parents[3] / "rama-fp" / "browserstack"))
from browser_automation.drivers import browser_options, remote_session
from browser_automation.workflow import run_capture_flow
from receipts import identity
from driver_receipt import write_driver_result
from remote.config import CELL_SECONDS, MAX_PRIVATE_BYTES, OwnerPlan
from remote.fly import FlyOwner
from remote.helper import bounded_tree

ENDPOINT = "https://hub.browserstack.com/wd/hub"


def write_json(path, value):
    with path.open("w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    path.chmod(0o600)


def credentials(path):
    path = Path(path).expanduser()
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_size > 16384
    ):
        raise ValueError("owned private BrowserStack credential file required")
    selected = {}
    for line in path.read_text().splitlines():
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if words[0] == "export":
            words = words[1:]
        if len(words) != 1 or "=" not in words[0]:
            raise ValueError("credential file must contain literal assignments")
        name, value = words[0].split("=", 1)
        if name not in {"BROWSERSTACK_USERNAME", "BROWSERSTACK_ACCESS_KEY"}:
            continue
        if name in selected or not value or any(c in value for c in "\0\r\n"):
            raise ValueError("invalid BrowserStack credential assignment")
        selected[name] = value
    if set(selected) != {"BROWSERSTACK_USERNAME", "BROWSERSTACK_ACCESS_KEY"}:
        raise ValueError("BrowserStack identity/key missing")
    return selected


@contextmanager
def deadline(seconds):
    def expired(*_):
        raise TimeoutError("owned stage deadline")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


@contextmanager
def local_port_guard(plan):
    root = Path(tempfile.gettempdir()) / "rama-remote-evidence-leases"
    root.mkdir(mode=0o700, exist_ok=True)
    if root.stat().st_uid != os.getuid() or stat.S_IMODE(root.stat().st_mode) & 0o077:
        raise ValueError("unowned local evidence lease directory")
    with (root / f"{plan.app}-{plan.port}").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def run_cell(owner, plan, cell, index, args, secret):
    cell_id = uuid.uuid4().hex
    root = args.output / cell_id
    root.mkdir(mode=0o700)
    receipt = dict(
        cell=cell_id,
        generation=plan.generation,
        requested=cell,
        actual={},
        status="failed",
        stage="start",
        session_started=False,
        session_creation_attempted=False,
        quit_outcome="not_attempted",
        provider_absence="not_independently_verified",
        origin=plan.origin,
    )
    started = False
    try:
        started = True  # The acknowledgement may be lost after remote startup.
        owner.request("start", cell=cell_id, protocol=cell["protocol"], timeout=120)
        capability = cell["capability"]
        options = browser_options(capability["browserName"])
        if "browserVersion" in capability:
            options.browser_version = capability["browserVersion"]
        provider = {
            key: value
            for key, value in capability.items()
            if key in {"os", "osVersion", "deviceName"}
        }
        provider.update(
            userName=secret["BROWSERSTACK_USERNAME"],
            accessKey=secret["BROWSERSTACK_ACCESS_KEY"],
            buildName="rama-owned-" + plan.generation,
            sessionName=f"readiness-{index}-{cell['protocol']}",
            source="python:rama-fp",
        )
        options.set_capability("bstack:options", provider)
        receipt["stage"] = "browser"
        receipt["session_creation_attempted"] = True
        receipt["quit_outcome"] = "not_created_or_unconfirmed"
        with deadline(CELL_SECONDS), remote_session(
            ENDPOINT, options, transport_timeout=30
        ) as driver:
            receipt["session_started"] = True
            receipt["actual"] = identity(
                driver.capabilities, secrets=tuple(secret.values())
            )
            if not receipt["actual"].get("browserName") or not receipt["actual"].get(
                "browserVersion"
            ):
                raise ValueError("resolved remote browser identity missing")
            if (
                receipt["actual"]["browserName"].lower()
                != capability["browserName"].lower()
            ):
                raise ValueError("resolved browser differs from requested matrix row")
            if (
                "deviceName" in capability
                and receipt["actual"].get("deviceName") != capability["deviceName"]
            ):
                raise ValueError("resolved mobile device identity missing or different")
            result = run_capture_flow(
                driver, plan.origin, cookies=None, expected_protocol=cell["protocol"]
            )
            write_driver_result(root / "page-result.json", result)
        receipt["quit_outcome"] = "succeeded"
        receipt["stage"] = "capture"
        capture = owner.request("finish", probe=result.websocket_probe, timeout=90)
        if (
            capture.get("cell") != cell_id
            or capture.get("generation") != plan.generation
        ):
            raise ValueError("capture generation mismatch")
        write_json(root / "capture.json", capture)
        for name, metadata in capture["files"].items():
            if (
                type(metadata.get("bytes")) is not int
                or not 0 <= metadata["bytes"] <= MAX_PRIVATE_BYTES
            ):
                raise ValueError("remote evidence file budget")
            owner.download(cell_id, name, root / name, metadata)
        bounded_tree(args.output)
        receipt["stage"] = "remote_cleanup"
        receipt["remote_cleanup"] = owner.request("clean", timeout=60)
        started = False
        if not receipt["remote_cleanup"] or not all(
            value is True for value in receipt["remote_cleanup"].values()
        ):
            raise ValueError("remote cleanup incomplete")
        receipt["stage"] = "local_replay"
        with (root / "verification.log").open("xb") as log:
            subprocess.run(
                [
                    sys.executable,
                    str(HERE / "verify.py"),
                    "--rama",
                    str(args.rama),
                    "--output",
                    str(root),
                    "--origin",
                    plan.origin,
                    "--protocol",
                    cell["protocol"],
                    "--interface",
                    args.interface,
                    "--postgres-image",
                    args.postgres_image,
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=240,
            )
        bounded_tree(args.output)
        receipt.update(status="verified-awaiting-owner-cleanup", stage="owner_cleanup")
    except Exception as error:
        receipt["failure_type"] = type(error).__name__
        if receipt["session_started"] and receipt["quit_outcome"] != "succeeded":
            receipt["quit_outcome"] = "failed_or_unconfirmed"
    finally:
        if started:
            try:
                receipt["remote_cleanup"] = owner.request("clean", timeout=60)
            except Exception:
                receipt["remote_cleanup"] = {"attempt_failed": False}
        write_json(root / "cell.json", receipt)
    return root, receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capabilities", type=Path, required=True)
    parser.add_argument("--app", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--port", type=int, default=32543)
    parser.add_argument("--rama", type=Path, default=Path("target/debug/rama"))
    parser.add_argument(
        "--credentials", type=Path, default=Path("~/.config/rama/browserstack.env")
    )
    parser.add_argument(
        "--interface", default="lo0" if sys.platform == "darwin" else "lo"
    )
    parser.add_argument("--postgres-image", default="postgres:17-alpine")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="provision only after reviewing the generated plan",
    )
    args = parser.parse_args(argv)
    os.umask(0o077)
    plan = OwnerPlan.read(args.app, args.image, args.port, args.capabilities)
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_json(args.output / "plan.json", plan.dry_plan())
    if not args.execute:
        return 0
    args.rama = args.rama.resolve(strict=True)
    write_json(
        args.output / "local-binary.json",
        dict(
            path=str(args.rama),
            sha256=hashlib.sha256(args.rama.read_bytes()).hexdigest(),
            platform=sys.platform,
            python=sys.version.split()[0],
        ),
    )
    secret = credentials(args.credentials)
    results = []
    owner = FlyOwner(plan, args.output)
    with local_port_guard(plan):
        try:
            write_json(args.output / "provisioning.json", owner.create())
            for index, cell in enumerate(plan.cells):
                results.append(run_cell(owner, plan, cell, index, args, secret))
        finally:
            cleanup = owner.destroy()
            write_json(args.output / "owner-cleanup.json", cleanup)
            for root, receipt in results:
                receipt["status"] = (
                    "passed-readiness"
                    if receipt["status"] == "verified-awaiting-owner-cleanup"
                    and cleanup
                    and all(value is True for value in cleanup.values())
                    else "failed"
                )
                write_json(root / "cell.json", receipt)
    return (
        0
        if results
        and len(results) == len(plan.cells)
        and all(receipt["status"] == "passed-readiness" for _, receipt in results)
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
