"""Own a private, short-lived PostgreSQL cluster without a Docker daemon."""

import os
from pathlib import Path
import secrets
import shlex
import signal
import shutil
import sys
import socket
import subprocess
import tempfile

from disposable_postgres import isolated_environment


def create_database(environment, name):
    if name not in ("rama_fp_capture", "rama_fp_replay"):
        raise ValueError("unexpected fixture database")
    fields = dict(part.split("=", 1) for part in shlex.split(
        environment["RAMA_BROWSER_CAPTURE_DATABASE_URL"]))
    connection = {"PG" + key.upper(): value for key, value in fields.items()}
    connection["PGDATABASE"] = connection.pop("PGDBNAME")
    subprocess.run(
        ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-c", "CREATE DATABASE " + name],
        env=dict(environment, **connection), check=True, timeout=10,
        stdout=subprocess.DEVNULL,
    )


def run(command, environment=None):
    parent = environment if environment is not None else os.environ
    previous, child, result = {}, None, None

    def interrupted(number, _frame):
        raise InterruptedError(number)

    # macOS Unix sockets need a short path; TemporaryDirectory is private (0700).
    with tempfile.TemporaryDirectory(prefix="rama-pg-", dir="/tmp") as temporary:
        root = Path(temporary)
        data, password_file = root / "data", root / "password"
        password = secrets.token_hex(32)
        password_file.write_text(password + "\n")
        password_file.chmod(0o600)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        dsn = f"host=127.0.0.1 port={port} user=postgres password={password} dbname=rama_fp_capture"
        env = isolated_environment(parent, dsn, None)
        env["RAMA_BROWSER_TEST_PG_NATIVE"] = str(data)
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, interrupted)
        try:
            with (root / "init.log").open("w") as log:
                subprocess.run(
                    ["initdb", "-D", str(data), "-U", "postgres", "--encoding=UTF8",
                     "--locale=C", "--auth-host=scram-sha-256", "--auth-local=trust",
                     "--pwfile=" + str(password_file)],
                    env=env, check=True, timeout=60, stdout=log, stderr=subprocess.STDOUT,
                )
            password_file.unlink()
            subprocess.run(
                ["pg_ctl", "-D", str(data), "-l", str(root / "server.log"),
                 "-o", f"-h 127.0.0.1 -p {port} -k {root} -c rama.fp_test=isolated",
                 "-w", "-t", "30", "start"],
                env=env, check=True, timeout=40, stdout=subprocess.DEVNULL,
            )
            bootstrap = dict(env, RAMA_BROWSER_CAPTURE_DATABASE_URL=dsn.replace(
                "dbname=rama_fp_capture", "dbname=postgres"))
            create_database(bootstrap, "rama_fp_capture")
            child = subprocess.Popen(command, env=env, start_new_session=True)
            result = child.wait(timeout=300)
            return result if result >= 0 else 128 - result
        except InterruptedError as error:
            return 128 + error.args[0]
        finally:
            failed = sys.exc_info()[0] is not None or result != 0
            cleanup_error = None
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
                if (data / "postmaster.pid").exists():
                    subprocess.run(
                        ["pg_ctl", "-D", str(data), "-m", "immediate", "-w", "stop"],
                        env=env, check=True, timeout=30, stdout=subprocess.DEVNULL,
                    )
            except (OSError, subprocess.SubprocessError) as error:
                cleanup_error = error
            finally:
                if failed or cleanup_error is not None:
                    try:
                        diagnostics = Path(tempfile.mkdtemp(prefix="rama-pg-diagnostics-", dir="/tmp"))
                        for name in ("init.log", "server.log"):
                            if (root / name).is_file():
                                shutil.copyfile(root / name, diagnostics / name)
                        print(f"PostgreSQL fixture diagnostics: {diagnostics}", file=sys.stderr)
                    except OSError as error:
                        print(f"Could not retain PostgreSQL diagnostics: {error}", file=sys.stderr)
                for number, handler in previous.items():
                    signal.signal(number, handler)
            if cleanup_error is not None:
                print(f"PostgreSQL fixture cleanup failed: {cleanup_error}", file=sys.stderr)
                if not failed:
                    raise RuntimeError("PostgreSQL fixture cleanup failed") from cleanup_error
