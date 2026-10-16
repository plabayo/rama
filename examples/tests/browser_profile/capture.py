#!/usr/bin/env python3
"""Protocol fixtures behind the common browser runner.

All protocols use the shared Selenium journey and isolated CLI fp database.
H1 and TLS H2 capture and strictly replay; H3 currently verifies original capture.
Wire decoding and checks live in wire.py; replay inputs live in flows.py.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

import flows
import wire

from capture_fields import compare_capture_fields
from connection_fields import compare_connection_fields, h2_prefixes
from fixture_process import running, wait_ready
from h3_sequence_wire import sequence_evidence
from replay import replay_environment, verify_tls_replay
from quic_wire import client_settings, compare_quic_captures, first_flights
from tls_wire import client_hellos, compare_tls_captures

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "rama-fp"))
from browser_automation.drivers import browser_options, local_session
from browser_automation.workflow import run_capture_flow


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def fixture_certificate(root):
    """Trust only this one ephemeral certificate through its SPKI exception."""
    key, certificate = root / "key.pem", root / "cert.pem"
    with (root / "certificate.log").open("w") as log:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout",
                str(key),
                "-out",
                str(certificate),
            ],
            check=True,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    key.chmod(0o600)
    public = subprocess.check_output(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"], timeout=10
    )
    der = subprocess.check_output(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], input=public, timeout=10
    )
    return key, certificate, base64.b64encode(hashlib.sha256(der).digest()).decode()


def capture_tls(args):
    root = args.output
    dsn = os.environ["RAMA_BROWSER_CAPTURE_DATABASE_URL"]
    if not (
        dsn == os.environ["DATABASE_URL"] == os.environ["RAMA_FP_DATABASE_URL"]
        and "host=127.0.0.1 " in dsn
        and "dbname=rama_fp_capture" in dsn
    ):
        raise RuntimeError("isolated loopback fixture database required")

    # Prepare a private TLS identity and bind this run to a fresh listener.
    key, certificate, spki = fixture_certificate(root)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    environment = dict(
        os.environ,
        RUST_LOG="info",
        NO_COLOR="1",
        RAMA_TLS_KEY=base64.b64encode(key.read_bytes()).decode(),
        RAMA_TLS_CRT=base64.b64encode(certificate.read_bytes()).decode(),
        SSLKEYLOGFILE=str(root / "server.keys"),
    )
    server_command = [
        str(args.rama),
        "serve",
        "fp",
        "--bind",
        f"127.0.0.1:{port}",
        "--http-version",
        args.protocol,
        "--secure",
    ]
    capture_command = [
        "dumpcap",
        "-i",
        args.interface,
        "-a",
        "duration:90",
        "-f",
        f"tcp port {port} or udp port {port}",
        "-w",
        str(root / "reference.pcapng"),
    ]

    # Trust only this fixture certificate and record protocol-forcing options.
    options = browser_options(args.browser, protocol=args.protocol)
    options.add_argument("--ignore-certificate-errors-spki-list=" + spki)
    options.add_argument("--host-resolver-rules=MAP localhost 127.0.0.1")
    if args.protocol == "h3":
        options.add_argument(f"--origin-to-force-quic-on=localhost:{port}")

    # Capture the shared browser journey, then drain buffered packets.
    with running(server_command, root / "server.log", environment) as server:
        wait_ready(
            server,
            root / "server.log",
            lambda text: bool(re.search(r"(listening|service ready)", text)),
        )
        with running(capture_command, root / "dumpcap.log") as packets:
            wait_ready(
                packets, root / "dumpcap.log", lambda text: "File:" in text, timeout=10
            )
            with local_session(
                args.browser,
                profile=root / "browser-profile",
                binary=args.browser_binary,
                keylog=root / "browser.keys",
                options=options,
            ) as browser:
                result = run_capture_flow(
                    browser,
                    f"https://localhost:{port}",
                    expected_protocol=args.protocol,
                )
            traffic = wire.drain_capture(
                packets,
                capture=root / "reference.pcapng",
                keylog=root / "browser.keys",
                protocol=args.protocol,
                server_port=port,
                output=root / "headers.pdml",
            )
    headers, bodies = traffic.headers, traffic.bodies
    if server.returncode or packets.returncode:
        raise RuntimeError("fixture process failed; see logs")

    # Compare the exported profile against independently decoded wire evidence.
    with (root / "export.log").open("w") as log:
        subprocess.run(
            [str(args.rama), "ua", "export", "--output", str(root / "profiles.json")],
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
            timeout=30,
        )
    with (root / "inspected.json").open("w") as output:
        subprocess.run(
            [str(args.rama), "ua", "view", "--json", str(root / "profiles.json")],
            stdout=output,
            check=True,
            timeout=30,
        )
    inspected = json.loads((root / "inspected.json").read_text())
    fields = compare_capture_fields(inspected, headers)
    tls = compare_tls_captures(
        inspected,
        client_hellos(
            (root / "headers.pdml").read_bytes(),
            "Tcp" if args.protocol == "h2" else "Quic",
        ),
        headers,
    )
    connection_fields = None
    if args.protocol == "h2":
        data = (root / "headers.pdml").read_bytes()
        connection_fields = compare_connection_fields(
            inspected, client_hellos(data, "Tcp"), h2_prefixes(data, port), headers
        )
    else:
        data = (root / "headers.pdml").read_bytes()
        connection_fields = compare_quic_captures(
            inspected,
            first_flights(data, port),
            client_hellos(data, "Quic"),
            client_settings(data, port),
            headers,
            sequence_evidence(data, port),
        )
    replay = None
    if args.protocol == "h2":
        replay = verify_tls_replay(
            args,
            traffic=traffic,
            inspected=inspected,
            server_command=server_command,
            environment=environment,
            certificate=certificate,
            port=port,
        )
    report = {
        "browser": result.browser_name,
        "version": result.browser_version,
        "protocols": dict(result.protocols),
        "browser_arguments": options.arguments,
        "fields": fields,
        "connection_fields": connection_fields,
        "tls": tls,
        "bodies": bodies,
        "replay": replay,
        "scope": (
            "original capture and strict replay checks"
            if replay is not None
            else "original capture checks; native QUIC replay remains unfinished"
        ),
    }
    (root / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


def capture(args):
    try:
        return capture_plaintext(args) if args.protocol == "h1" else capture_tls(args)
    finally:
        shutil.rmtree(args.output / "browser-profile", ignore_errors=True)
        for name in ("key.pem", "server.keys", "browser.keys", "replay.keys"):
            (args.output / name).unlink(missing_ok=True)


def capture_plaintext(args):
    """Capture and strictly replay H1 using the same isolated fixture boundary."""
    rama = args.rama
    require(
        os.environ["DATABASE_URL"] == os.environ["RAMA_BROWSER_CAPTURE_DATABASE_URL"],
        "database isolation",
    )
    require(
        os.environ["RAMA_FP_DATABASE_URL"]
        == os.environ["RAMA_BROWSER_CAPTURE_DATABASE_URL"],
        "fp database isolation",
    )
    require(
        "host=127.0.0.1 " in os.environ["DATABASE_URL"], "loopback database required"
    )
    root = args.output
    flow_mode = args.flows
    require(flow_mode in ("navigate", "all"), "unsupported flow mode")
    all_flows = flow_mode == "all"
    print(f"capture evidence: {root}", flush=True)
    processes, streams = [], []

    def start(command, name):
        path = root / name
        stream = path.open("w")
        streams.append(stream)
        process = subprocess.Popen(
            command,
            stdout=stream,
            stderr=subprocess.STDOUT,
            env=dict(os.environ, RUST_LOG="info", NO_COLOR="1"),
            start_new_session=True,
        )
        processes.append(process)
        (root / "processes.json").write_text(
            json.dumps([item.pid for item in processes])
        )
        return process, path

    def ready(process, log, pattern):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            text = re.sub(r"\x1b\[[0-9;]*m", "", log.read_text())
            match = re.search(pattern, text)
            if match:
                return int(match.group(1))
            if process.poll() is not None:
                raise RuntimeError(text[-2000:])
            time.sleep(0.05)
        raise TimeoutError(log)

    def stop(process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=40)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    def capture_wire(port, label):
        capture, log = start(
            [
                "dumpcap",
                "-i",
                args.interface,
                "-a",
                "duration:60",
                "-f",
                f"tcp port {port} or udp port {marker_port}",
                "-w",
                str(root / (label + ".pcapng")),
            ],
            label + "-dumpcap.log",
        )
        deadline = time.monotonic() + 10
        while not (
            (root / (label + ".pcapng")).exists() and "File:" in log.read_text()
        ):
            if capture.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("capture did not start")
            time.sleep(0.02)
        marker.sendto(b"rama-h1-capture-ready", ("127.0.0.1", marker_port))
        while "Packets:" not in log.read_text():
            if capture.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("capture readiness marker not seen")
            time.sleep(0.02)
        return capture

    def finish_capture(capture, label, port):
        # Wait for the independent decoder before stopping BPF delivery.
        marker.sendto(b"rama-h1-capture-finished", ("127.0.0.1", marker_port))
        deadline = time.monotonic() + 10
        last_error = None
        while True:
            if all_flows:
                try:
                    wire.read_capture(
                        root / (label + ".pcapng"), port, label == "reference-wire"
                    )
                    break
                except (ValueError, subprocess.CalledProcessError) as error:
                    last_error = error
            else:
                decoded = subprocess.run(
                    [
                        "tshark",
                        "-r",
                        str(root / (label + ".pcapng")),
                        "-d",
                        f"tcp.port=={port},http",
                        "-Y",
                        'http.request.method == "GET" && http.request.uri == "/report"',
                        "-T",
                        "fields",
                        "-e",
                        "http.request.method",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=3,
                )
                if "GET" in decoded.stdout:
                    break
            if capture.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(
                    f"packet capture incomplete or invalid: {last_error}"
                )
            time.sleep(0.05)
        stop(capture)
        require(capture.returncode == 0, "capture failed")

    marker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    marker.bind(("127.0.0.1", 0))
    marker_port = marker.getsockname()[1]

    def interrupted(number, _frame):
        raise InterruptedError(number)

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)

    try:
        server, log = start(
            [str(rama), "serve", "fp", "--bind", "127.0.0.1:0", "--http-version", "h1"],
            "fp.log",
        )
        port = ready(server, log, r"network\.local\.port[= ]+(\d+)")

        # Record the browser's original requests before exporting their profile.
        reference_wire = capture_wire(port, "reference-wire")
        browser_kind = args.browser
        require(browser_kind in ("chrome", "firefox"), "unsupported browser")
        with local_session(
            browser_kind, profile=root / "browser-profile", binary=args.browser_binary
        ) as driver:
            capture_result = run_capture_flow(
                driver,
                f"http://127.0.0.1:{port}",
                expected_protocol="h1",
                all_flows=all_flows,
            )
            (root / "page.html").write_text(capture_result.report_html)
            result = {
                "browser": capture_result.browser_name,
                "version": capture_result.browser_version,
                "protocols": dict(capture_result.protocols),
            }
        require(
            "report" in (root / "page.html").read_text().lower(), "fp page not rendered"
        )
        stop(server)
        finish_capture(reference_wire, "reference-wire", port)
        require(server.returncode == 0, "fp capture did not drain")
        with (root / "export.log").open("w") as output:
            subprocess.run(
                [str(rama), "ua", "export", "--output", str(root / "profiles.json")],
                check=True,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=30,
            )
        archive = json.loads((root / "profiles.json").read_text())
        require(archive["profiles"], "reference profile not captured")
        (root / "summary.json").write_text(
            json.dumps(
                {
                    "scope": f"{browser_kind.title()} H1 {flow_mode} capture/export and strict replay; see comparison.json for exact membership results",
                    "profiles": len(archive["profiles"]),
                    "browser": result["browser"],
                    "draw": {
                        "seed": "01" * 32,
                        "connection_key": "02" * 32,
                        "request_key": "03" * 32,
                    },
                },
                indent=2,
            )
            + "\n"
        )
        print(
            f'{browser_kind.title()} H1 capture/export: {len(archive["profiles"])} profiles',
            flush=True,
        )

        # Replay into a second database so reference observations cannot mask failure.
        os.environ.update(replay_environment(os.environ))
        replay, log = start(
            [str(rama), "serve", "fp", "--bind", "127.0.0.1:0", "--http-version", "h1"],
            "fp-replay.log",
        )
        replay_port = ready(replay, log, r"network\.local\.port[= ]+(\d+)")
        replay_wire = capture_wire(replay_port, "replay-wire")
        if all_flows:
            reference_flows = wire.read_capture(
                root / "reference-wire.pcapng", port, True
            )
            for flow in flows.FLOWS:
                args = flows.replay_args(
                    rama,
                    root / "profiles.json",
                    root / (flow + ".response"),
                    flows.ReplayTarget("h1", f"http://127.0.0.1:{replay_port}"),
                    flow,
                    reference_flows[flow][0],
                )
                with (root / (flow + "-replay.log")).open("w") as output:
                    subprocess.run(
                        args,
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                        check=True,
                        timeout=30,
                    )
        else:
            with (root / "rama-replay.log").open("w") as output:
                subprocess.run(
                    [
                        str(rama),
                        "send",
                        f'--emulate={root / "profiles.json"}',
                        "--emulate-seed",
                        "01" * 32,
                        "--emulate-connection-key",
                        "02" * 32,
                        "--emulate-request-key",
                        "03" * 32,
                        "--http1.1",
                        "--header",
                        "Connection: keep-alive",
                        "--output",
                        str(root / "replay-body.bin"),
                        f"http://127.0.0.1:{replay_port}/report",
                    ],
                    check=True,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=30,
                )
        stop(replay)
        finish_capture(replay_wire, "replay-wire", replay_port)
        require(replay.returncode == 0, "fp replay did not drain")
        with (root / "export-replay.log").open("w") as output:
            subprocess.run(
                [
                    str(rama),
                    "ua",
                    "export",
                    "--output",
                    str(root / "replay-profiles.json"),
                ],
                check=True,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=30,
            )
        replay_archive = json.loads((root / "replay-profiles.json").read_text())
        require(replay_archive["profiles"], "no replay profile captured")

        # Require both archive agreement and independent packet agreement.
        comparison = [str(rama), "ua", "compare", "--literal"]
        if not all_flows:
            comparison += ["--allow-partial-coverage"]
        comparison += [str(root / "profiles.json"), str(root / "replay-profiles.json")]
        with (root / "comparison.json").open("w") as output:
            subprocess.run(comparison, check=True, stdout=output, timeout=30)
        checker = wire.verify_h1_flows if all_flows else wire.verify_h1_navigation
        checker(root, port, replay_port)

    finally:
        # Stop every owned process even when capture, replay or comparison fails.
        marker.close()
        for number in (signal.SIGINT, signal.SIGTERM):
            signal.signal(number, signal.SIG_IGN)
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
        deadline = time.monotonic() + 10
        for process in reversed(processes):
            if process.poll() is None:
                try:
                    process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        for stream in streams:
            stream.close()
        import shutil

        shutil.rmtree(root / "browser-profile", ignore_errors=True)
