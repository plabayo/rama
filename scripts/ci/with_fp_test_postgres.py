#!/usr/bin/env python3
"""Run a command against a private, Unix-socket-only fingerprint test database."""

import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile


def postgres_bin(explicit):
    if explicit:
        directory = Path(explicit)
    else:
        config = shutil.which("pg_config")
        if not config:
            raise RuntimeError("PostgreSQL server tools are required (pg_config missing)")
        directory = Path(subprocess.check_output([config, "--bindir"], text=True).strip())
    for name in ("initdb", "pg_ctl", "createdb"):
        if not os.access(directory / name, os.X_OK):
            raise RuntimeError(f"PostgreSQL server tool missing: {directory / name}")
    return directory


def run(command, directory):
    if os.geteuid() == 0:
        raise RuntimeError("run the PostgreSQL harness as an unprivileged user")
    # Ignore caller connection defaults: no command may reach a different cluster.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    with tempfile.TemporaryDirectory(prefix="rama-fp-m3-pg-", dir="/tmp") as temporary:
        root = Path(temporary)
        data = root / "data"
        log = root / "postgres.log"
        subprocess.run(
            [str(directory / "initdb"), "-D", str(data), "-U", "postgres",
             "--auth=trust", "--encoding=UTF8", "--no-locale"],
            env=environment, check=True, stdout=subprocess.DEVNULL,
        )
        with (data / "postgresql.conf").open("a") as config:
            config.write(f"\nlisten_addresses = ''\nunix_socket_directories = '{root}'\n"
                         "unix_socket_permissions = 0700\nrama.fp_test = 'isolated'\n")
        ctl = [str(directory / "pg_ctl"), "-D", str(data), "-w", "-t", "30"]
        previous = {}
        child = None

        def interrupted(number, _frame):
            raise InterruptedError(number)

        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, interrupted)
        result = 1
        try:
            subprocess.run(ctl + ["-l", str(log), "start"], env=environment, check=True)
            subprocess.run(
                [str(directory / "createdb"), "-h", str(root), "-p", "5432",
                 "-U", "postgres", "rama_fp_m3_test"],
                env=environment, check=True,
            )
            environment["RAMA_FP_TEST_PG"] = (
                f"host={root} port=5432 user=postgres dbname=rama_fp_m3_test"
            )
            environment["RAMA_FP_DATABASE_URL"] = environment["RAMA_FP_TEST_PG"]
            child = subprocess.Popen(command, env=environment, start_new_session=True)
            result = child.wait()
            if result < 0:
                result = 128 - result
        except InterruptedError as error:
            result = 128 + error.args[0]
        finally:
            # A second signal must not interrupt teardown of this owned cluster.
            for number in previous:
                signal.signal(number, signal.SIG_IGN)
            try:
                if child is not None and child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                if (data / "postmaster.pid").exists():
                    stopped = subprocess.run(ctl + ["-m", "immediate", "stop"], env=environment)
                    if stopped.returncode:
                        raise RuntimeError("could not stop the owned PostgreSQL test cluster")
            finally:
                for number, handler in previous.items():
                    signal.signal(number, handler)
            if result and log.exists():
                print(log.read_text(), end="")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-bin", help="directory containing PostgreSQL server tools")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    return run(command, postgres_bin(args.postgres_bin))


if __name__ == "__main__":
    raise SystemExit(main())
