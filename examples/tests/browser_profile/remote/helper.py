#!/usr/bin/env python3
"""Own one private PostgreSQL/FP/capture generation inside the temporary VM."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import signal
import shutil
import math
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from flow_bodies import json_object
from remote.config import (
    CELL_SECONDS,
    IDLE_SECONDS,
    OWNER_SECONDS,
    MAX_CAPTURE_BYTES,
    MAX_CONTROL_BYTES,
    MAX_KEYLOG_BYTES,
    MAX_PRIVATE_BYTES,
    identifier,
)
from fixture_process import stop, wait_ready
from wire import drain_capture

ROOT = Path("/evidence")
RAMA = "/app/rama"


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    path.chmod(0o600)


def pg_program(name):
    candidates = sorted(Path("/usr/lib/postgresql").glob("*/bin/" + name))
    if len(candidates) != 1:
        raise RuntimeError("exactly one PostgreSQL runtime required")
    return str(candidates[0])


def cell_environment(parent, dsn, root):
    environment = {
        key: value
        for key, value in parent.items()
        if not key.startswith(("PG", "AWS_", "S3_", "DIAL9_", "BROWSERSTACK_"))
    }
    for key in (
        "RAMA_FP_STORAGE_COOKIE",
        "RAMA_FP_TEST_PG",
        "RAMA_BROWSER_TEST_PG_CONTAINER",
        "RAMA_IP_GEO_DB",
        "SSLKEYLOGFILE",
    ):
        environment.pop(key, None)
    for key in (
        "DATABASE_URL",
        "RAMA_FP_DATABASE_URL",
        "RAMA_BROWSER_CAPTURE_DATABASE_URL",
    ):
        environment[key] = dsn
    environment.update(
        DIAL9_ENABLED="false",
        SSLKEYLOGFILE=str(root / "server.keys"),
        HOME=str(root),
        RUST_LOG="info",
        NO_COLOR="1",
    )
    return environment


def bounded_tree(root):
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("unexpected link in owned evidence")
        if path.is_file():
            size = path.stat().st_size
            if path.name == "server.keys" and size > MAX_KEYLOG_BYTES:
                raise RuntimeError("owned TLS keylog budget exceeded")
            total += size
            if total > MAX_PRIVATE_BYTES:
                raise RuntimeError("owned evidence budget exceeded")
    return total


def check_capture_counters(log):
    captured = re.findall(r"Packets captured: (\d+)", log)
    interfaces = re.findall(
        r"Packets received/dropped on interface [^\n]*: (\d+)/(\d+) \(pcap:(\d+)/dumpcap:(\d+)/flushed:(\d+)/ps_ifdrop:(\d+)\)",
        log,
    )
    if (
        len(captured) != 1
        or int(captured[0]) <= 0
        or not interfaces
        or any(any(int(value) for value in row[1:]) for row in interfaces)
    ):
        raise RuntimeError("capture counters absent or nonzero drops")


class Session:
    def __init__(self, generation, port, hostname):
        self.generation = identifier(generation)
        if not 32000 <= port <= 59999 or not re.fullmatch(r"[a-z0-9.-]+", hostname):
            raise ValueError("invalid owned listener")
        self.port, self.hostname = port, hostname
        self.uid = 1000
        self.user = pwd.getpwuid(self.uid).pw_name
        self.cell = self.root = self.environment = None
        self.processes = {}
        self.logs = []
        self.deadline = None

    def spawn(self, name, command, *, user=None, environment=None, output=None):
        log = (self.root / (name + ".log")).open("xb")
        self.logs.append(log)
        destination = log if output is None else output.open("xb")
        if destination is not log:
            self.logs.append(destination)
        process = subprocess.Popen(
            command,
            stdout=destination,
            stderr=log,
            env=environment,
            start_new_session=True,
            user=user,
        )
        self.processes[name] = process
        return process

    def check_bounds(self):
        bounded_tree(ROOT)
        if (
            self.root
            and (self.root / "server.keys").exists()
            and (self.root / "server.keys").stat().st_size > MAX_KEYLOG_BYTES
        ):
            raise RuntimeError("owned TLS keylog budget exceeded")
        for name, process in self.processes.items():
            if process.poll() is not None:
                raise RuntimeError("owned process exited: " + name)

    def start(self, cell, protocol):
        if self.cell is not None or protocol not in ("h1", "h2", "h3"):
            raise ValueError("one H1/H2/H3 cell at a time")
        self.deadline = time.monotonic() + CELL_SECONDS
        signal.alarm(CELL_SECONDS)
        self.cell = identifier(cell)
        self.root = ROOT / self.cell
        self.root.mkdir(mode=0o700, exist_ok=False)
        os.chown(self.root, self.uid, self.uid)
        data, socket = self.root / "pg", self.root / "socket"
        socket.mkdir(mode=0o700)
        os.chown(socket, self.uid, self.uid)
        dsn = f"host={socket} user={self.user} dbname=rama_fp_capture"
        self.environment = cell_environment(os.environ, dsn, self.root)
        with (self.root / "initdb.log").open("xb") as log:
            subprocess.run(
                [
                    pg_program("initdb"),
                    "-D",
                    str(data),
                    "--auth-local=trust",
                    "--auth-host=reject",
                    "--no-locale",
                    "--encoding=UTF8",
                ],
                user=self.uid,
                env=self.environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=30,
            )
        pg = self.spawn(
            "postgres",
            [
                pg_program("postgres"),
                "-D",
                str(data),
                "-k",
                str(socket),
                "-h",
                "",
                "-c",
                "shared_buffers=16MB",
                "-c",
                "max_connections=16",
            ],
            user=self.uid,
            environment=self.environment,
        )
        deadline = time.monotonic() + 20
        while subprocess.run(
            [pg_program("pg_isready"), "-h", str(socket), "-U", self.user],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        ).returncode:
            if pg.poll() is not None or time.monotonic() >= deadline:
                raise TimeoutError("private PostgreSQL readiness")
            time.sleep(0.05)
        subprocess.run(
            [
                pg_program("createdb"),
                "-h",
                str(socket),
                "-U",
                self.user,
                "rama_fp_capture",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        keys = self.root / "server.keys"
        keys.touch(mode=0o600, exist_ok=False)
        os.chown(keys, self.uid, self.uid)
        versions = {"h1": "h1", "h2": "h1,h2", "h3": "auto"}[protocol]
        fp = self.spawn(
            "server",
            [
                RAMA,
                "serve",
                "fp",
                "--bind",
                f"0.0.0.0:{self.port}",
                "--http-version",
                versions,
                "--secure",
                "--graceful",
                "10",
            ],
            user=self.uid,
            environment=self.environment,
        )
        wait_ready(
            fp, self.root / "server.log", lambda text: "listening" in text, timeout=30
        )
        # Warm only certificate issuance; this exchange is outside the capture epoch.
        with (self.root / "certificate-warmup.log").open("xb") as log:
            subprocess.run(
                [
                    RAMA,
                    "send",
                    "--http1.1",
                    "--resolve",
                    f"{self.hostname}:{self.port}:127.0.0.1",
                    f"https://{self.hostname}:{self.port}/consent",
                ],
                env=self.environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=30,
            )
        # dumpcap drops filesystem capabilities. Give it an already opened
        # private output descriptor instead of access through another UID's 0700 directory.
        capture = self.spawn(
            "dumpcap",
            [
                "dumpcap",
                "-q",
                "-i",
                "any",
                "-a",
                f"duration:{CELL_SECONDS}",
                "-a",
                f"filesize:{MAX_CAPTURE_BYTES // 1024}",
                "-f",
                f"tcp port {self.port} or udp port {self.port}",
                "-w",
                "-",
            ],
            output=self.root / "reference.pcapng",
        )
        wait_ready(
            capture, self.root / "dumpcap.log", lambda text: "File:" in text, timeout=10
        )
        self.check_bounds()
        return dict(
            cell=self.cell,
            started_at=now(),
            generation=self.generation,
            capture_pid=capture.pid,
            server_pid=fp.pid,
            postgres_pid=pg.pid,
            private_database=True,
            port=self.port,
        )

    def finish(self, probe):
        if (
            self.cell is None
            or not isinstance(probe, str)
            or not 1 <= len(probe.encode()) <= 1024
            or any(c in probe for c in "\0\r\n")
        ):
            raise ValueError("active cell and bounded browser probe required")
        self.check_bounds()
        traffic = drain_capture(
            self.processes["dumpcap"],
            capture=self.root / "reference.pcapng",
            keylog=self.root / "server.keys",
            protocol="mixed",
            server_port=self.port,
            output=self.root / "headers.pdml",
            timeout=15,
            websocket_probe=probe,
        )
        capture = self.processes["dumpcap"]
        stop(capture)
        if capture.returncode != 0:
            raise RuntimeError("owned capture did not exit cleanly")
        self.processes.pop("dumpcap")
        log = (self.root / "dumpcap.log").read_text()
        check_capture_counters(log)
        # Graceful shutdown drains the ingestion worker before this single export.
        server = self.processes["server"]
        stop(server)
        if server.returncode != 0:
            raise RuntimeError("owned FP server did not exit gracefully")
        self.processes.pop("server")
        archive = self.root / "profiles.json"
        subprocess.run(
            [RAMA, "ua", "export", "--output", str(archive)],
            env=self.environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=10,
        )
        archive.chmod(0o600)
        with (self.root / "inspected.json").open("xb") as out:
            subprocess.run(
                [RAMA, "ua", "view", "--json", str(archive)],
                env=self.environment,
                stdout=out,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=15,
            )
        receipt = dict(
            cell=self.cell,
            generation=self.generation,
            finished_at=now(),
            bodies=traffic.bodies,
            capture_stopped=True,
            capture_exit=capture.returncode,
            server_exit=server.returncode,
            zero_drops=True,
            files={},
        )
        for name in ("profiles.json", "inspected.json", "headers.pdml"):
            path = self.root / name
            receipt["files"][name] = dict(
                bytes=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        write_json(self.root / "capture.json", receipt)
        return receipt

    def clean(self):
        """Attempt every owned cleanup even if another process/file failed."""
        signal.alarm(0)
        results = {}
        for name in ("dumpcap", "server", "postgres"):
            process = self.processes.pop(name, None)
            if process is None:
                continue
            try:
                stop(process)
                results[name] = process.poll() is not None
            except Exception:
                results[name] = False
        for stream in self.logs:
            try:
                stream.close()
            except Exception:
                results["logs_closed"] = False
        self.logs.clear()
        if self.root is not None:
            keys = self.root / "server.keys"
            try:
                keys.unlink(missing_ok=True)
                results["keylog_removed"] = not keys.exists()
            except Exception:
                results["keylog_removed"] = False
            for name in ("pg", "socket"):
                try:
                    shutil.rmtree(self.root / name)
                    results[name + "_removed"] = True
                except FileNotFoundError:
                    results[name + "_removed"] = True
                except Exception:
                    results[name + "_removed"] = False
            write_json(self.root / "cleanup.json", results)
        self.cell = self.root = self.environment = self.deadline = None
        if not all(results.values()):
            raise RuntimeError("owned process cleanup failed")
        return results


def provenance(session):
    """Bind this helper and its actual tool executables without exposing env."""
    tools = {}
    for name, command in (
        ("rama", [RAMA, "--version"]),
        ("tshark", ["tshark", "--version"]),
        ("postgres", [pg_program("postgres"), "--version"]),
    ):
        text = subprocess.check_output(
            command, stderr=subprocess.STDOUT, timeout=10
        ).decode()
        tools[name] = text.splitlines()[0][:256]
    return dict(
        alive=True,
        generation=session.generation,
        tools=tools,
        rama_sha256=hashlib.sha256(Path(RAMA).read_bytes()).hexdigest(),
        helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        platform=sys.platform,
        python=sys.version.split()[0],
    )


def serve():
    session = Session(
        os.environ["EVIDENCE_GENERATION"],
        int(os.environ["EVIDENCE_PORT"]),
        os.environ["EVIDENCE_HOSTNAME"],
    )

    def expired(*_):
        raise TimeoutError("owned helper lease expired")

    signal.signal(signal.SIGALRM, expired)
    signal.signal(signal.SIGTERM, expired)
    signal.signal(signal.SIGINT, expired)
    session_file = ROOT / "session.json"
    write_json(session_file, dict(pid=os.getpid(), generation=session.generation))
    try:
        while True:
            remaining = (
                IDLE_SECONDS
                if session.deadline is None
                else math.ceil(session.deadline - time.monotonic())
            )
            if remaining <= 0:
                raise TimeoutError("owned cell deadline")
            signal.alarm(remaining)
            line = sys.stdin.buffer.readline(MAX_CONTROL_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_CONTROL_BYTES:
                raise ValueError("helper control byte limit")
            request = json_object(line)
            if request.pop("generation", None) != session.generation:
                raise ValueError("helper owner generation mismatch")
            command = request.pop("command", None)
            if command == "start":
                result = session.start(**request)
            elif command == "finish":
                result = session.finish(**request)
            elif command == "clean":
                result = session.clean()
            elif command == "ping":
                result = provenance(session)
            elif command == "close":
                break
            else:
                raise ValueError("unknown helper command")
            ROOT.joinpath("heartbeat").touch()
            print(
                json.dumps(
                    dict(
                        ok=True,
                        generation=session.generation,
                        command=command,
                        result=result,
                    )
                ),
                flush=True,
            )
    finally:
        signal.alarm(0)
        try:
            session.clean()
        finally:
            session_file.unlink(missing_ok=True)


def stop_session():
    path = ROOT / "session.json"
    if not path.is_file():
        return
    value = json_object(path.read_bytes())
    if (
        value.get("generation") != os.environ["EVIDENCE_GENERATION"]
        or type(value.get("pid")) is not int
    ):
        raise RuntimeError("invalid owned helper PID receipt")
    pid = value["pid"]
    command = Path(f"/proc/{pid}/cmdline")
    if command.exists():
        argv = command.read_bytes().split(b"\0")
        if str(Path(__file__).resolve()).encode() not in argv or b"session" not in argv:
            raise RuntimeError("owned helper PID was reused")
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 120
        while command.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        if command.exists():
            raise RuntimeError("owned helper failed TTL cleanup")


def lease():
    ROOT.mkdir(mode=0o700, exist_ok=False)
    os.chown(ROOT, 1000, 1000)
    heartbeat = ROOT / "heartbeat"
    heartbeat.touch(mode=0o600)
    started = time.monotonic()
    try:
        while time.monotonic() - started < OWNER_SECONDS:
            if time.time() - heartbeat.stat().st_mtime > IDLE_SECONDS:
                return
            bounded_tree(ROOT)
            time.sleep(1)
    finally:
        stop_session()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("lease", "session"))
    args = parser.parse_args()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_CAPTURE_BYTES, MAX_CAPTURE_BYTES))
    lease() if args.mode == "lease" else serve()
