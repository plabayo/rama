#!/usr/bin/env python3
"""Run a command with a private, disposable PostgreSQL container on loopback."""

import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import uuid


def isolated_environment(parent, dsn, container):
    environment = {
        key: value for key, value in parent.items() if not key.startswith("PG")
    }
    environment.pop("RAMA_FP_STORAGE_COOKIE", None)
    for key in (
        "RAMA_BROWSER_CAPTURE_DATABASE_URL",
        "RAMA_FP_DATABASE_URL",
        "DATABASE_URL",
    ):
        environment[key] = dsn
    environment.pop("RAMA_BROWSER_TEST_PG_NATIVE", None)
    environment.pop("RAMA_BROWSER_TEST_PG_CONTAINER", None)
    if container is not None:
        environment["RAMA_BROWSER_TEST_PG_CONTAINER"] = container
    environment["NO_PROXY"] = "127.0.0.1,localhost"
    environment["no_proxy"] = "127.0.0.1,localhost"
    return environment


def run(command, image_name="postgres:17-alpine", environment=None):
    image = subprocess.check_output(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image_name],
        text=True,
        timeout=10,
    ).strip()
    name = "rama-browser-profile-" + uuid.uuid4().hex
    password = secrets.token_hex(32)
    previous = {}
    child = None

    def interrupted(number, _frame):
        raise InterruptedError(number)

    with tempfile.TemporaryDirectory(prefix="rama-browser-database-") as temporary:
        env_file = Path(temporary) / "postgres.env"
        env_file.write_text(
            f"POSTGRES_PASSWORD={password}\nPOSTGRES_DB=rama_fp_capture\n"
        )
        env_file.chmod(0o600)
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, interrupted)
        try:
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--rm",
                    "--pull=never",
                    "--name",
                    name,
                    "--label",
                    "rama.browser-profile.disposable=true",
                    "--env-file",
                    str(env_file),
                    "--publish",
                    "127.0.0.1::5432",
                    "--tmpfs",
                    "/var/lib/postgresql/data:rw,size=536870912",
                    image,
                    "-c",
                    "rama.fp_test=isolated",
                ],
                check=True,
                timeout=30,
                stdout=subprocess.DEVNULL,
            )

            # Wait for PostgreSQL before discovering its ephemeral loopback port.
            deadline = time.monotonic() + 30
            while subprocess.run(
                [
                    "docker",
                    "exec",
                    name,
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    "postgres",
                    "-d",
                    "rama_fp_capture",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).returncode:
                if time.monotonic() >= deadline:
                    raise TimeoutError("disposable database readiness")
                time.sleep(0.05)
            address = subprocess.check_output(
                ["docker", "port", name, "5432/tcp"], text=True, timeout=5
            ).strip()
            host, port = address.rsplit(":", 1)
            if host != "127.0.0.1":
                raise RuntimeError("disposable database did not bind loopback")

            # Pass isolated database settings only to the fixture subprocess.
            dsn = f"host=127.0.0.1 port={int(port)} user=postgres password={password} dbname=rama_fp_capture"
            environment = isolated_environment(
                environment if environment is not None else os.environ, dsn, name
            )
            child = subprocess.Popen(command, env=environment, start_new_session=True)
            result = child.wait(timeout=300)
            return result if result >= 0 else 128 - result
        except InterruptedError as error:
            return 128 + error.args[0]
        finally:
            # Stop the child before removing its database, including on signals.
            for number in previous:
                signal.signal(number, signal.SIG_IGN)
            try:
                if child is not None and child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=25)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=5)
                subprocess.run(
                    ["docker", "rm", "--force", name],
                    timeout=20,
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
            finally:
                for number, handler in previous.items():
                    signal.signal(number, handler)
