#!/usr/bin/env python3
"""Protocol fixtures behind the common browser runner.

All protocols use the shared Selenium journey and isolated CLI fp database.
All protocols capture and strictly replay their admitted native components.
Wire decoding and checks live in wire.py; replay inputs live in flows.py.
"""

import base64
import hashlib
import json
import os
from functools import partial
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

from driver_receipt import write_driver_result
from source_evidence import source_evidence
from capture_fields import compare_capture_fields
from flows import flow_protocols
from fixture_process import running, wait_ready
from fixture_tls import fixture_certificate, prepare_nss_trust
from replay import (
    check_missing_tls_bindings,
    compare_native_connections,
    connection_variants,
    current_trust_ids,
    replay_environment,
    run_replay,
    tls_hellos,
    verify_tls_replay,
)
from qpack_fields_wire import compare_field_metadata, sections_from_wire
from tls_wire import client_hellos, compare_tls_captures

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "rama-fp"))
from browser_automation.drivers import browser_options, local_session
from browser_automation.workflow import run_capture_flow


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def tls_browser_options(args, port, certificate, spki):
    """Scope fixture trust and protocol routing to this fresh browser profile."""
    options = browser_options(args.browser, protocol=args.protocol)
    prepare_profile = None
    if args.browser == "firefox":
        options.set_preference("network.proxy.type", 0)
        prepare_profile = partial(
            prepare_nss_trust,
            certificate=certificate,
            log=args.output / "nss-setup.log",
        )
        if args.protocol == "h3":
            # Seed the owned H3 route without requiring an initial TCP page load.
            # TCP stays available for standard-browser WebSocket negotiation.
            options.set_preference(
                "network.http.http3.alt-svc-mapping-for-testing",
                f"localhost;h3=:{port}",
            )
            options.set_preference(
                "network.http.http3.force-use-alt-svc-mapping-for-testing", True
            )
            options.set_preference(
                "network.http.http3.disable_when_third_party_roots_found", False
            )
    else:
        options.add_argument("--ignore-certificate-errors-spki-list=" + spki)
        options.add_argument("--host-resolver-rules=MAP localhost 127.0.0.1")
        if args.protocol == "h3":
            options.add_argument(f"--origin-to-force-quic-on=localhost:{port}")
    return options, prepare_profile


def fixture_http_versions(protocol):
    """Keep standard WebSocket fallback available on a page's owned TLS origin."""
    return {"h2": "h1,h2", "h3": "auto"}[protocol]


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
        fixture_http_versions(args.protocol),
        "--secure",
        "--graceful",
        "10",
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

    options, prepare_profile = tls_browser_options(args, port, certificate, spki)

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
                prepare_profile=prepare_profile,
            ) as browser:
                result = run_capture_flow(
                    browser,
                    f"https://localhost:{port}",
                    expected_protocol=args.protocol,
                )
                write_driver_result(root / "page-result.json", result)
            traffic = wire.drain_capture(
                packets,
                capture=root / "reference.pcapng",
                keylog=root / "browser.keys",
                protocol="mixed",
                server_port=port,
                output=root / "headers.pdml",
                websocket_probe=result.websocket_probe,
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
    data = (root / "headers.pdml").read_bytes()
    page = json.loads((root / "page-result.json").read_text())
    traffic, operations, source = source_evidence(
        data, inspected, page, f"https://localhost:{port}", port
    )
    headers, bodies = traffic.headers, traffic.bodies
    fields, tls = source["fields"], source["tls"]
    connection_fields, qpack_fields = source["connections"], source.get("qpack")
    if qpack_fields is not None:
        (root / "capture-qpack-fields.json").write_text(
            json.dumps(qpack_fields, indent=2) + "\n"
        )

    replay = verify_tls_replay(
        args,
        traffic=traffic,
        inspected=inspected,
        server_command=server_command,
        environment=environment,
        certificate=certificate,
        port=port,
        websocket_probe=result.websocket_probe,
        operations=operations,
    )
    report = {
        "browser": result.browser_name,
        "version": result.browser_version,
        "protocols": dict(result.protocols),
        "websocket_probe_sha256": hashlib.sha256(
            result.websocket_probe.encode()
        ).hexdigest(),
        "browser_arguments": options.arguments,
        "browser_preferences": options.preferences if args.browser == "firefox" else {},
        "admission": source["admission"],
        "operation_matrix": source["operation_matrix"],
        "fields": fields,
        "connection_fields": connection_fields,
        "qpack_fields": qpack_fields,
        "tls": tls,
        "bodies": bodies,
        "replay": replay,
        "scope": "original capture and strict replay checks",
    }
    (root / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


def capture(args):
    try:
        return capture_http1(args) if args.protocol == "h1" else capture_tls(args)
    finally:
        shutil.rmtree(args.output / "browser-profile", ignore_errors=True)
        for name in ("key.pem", "server.keys", "browser.keys", "replay.keys"):
            (args.output / name).unlink(missing_ok=True)


def capture_http1(args):
    """Capture H1 over TCP or TLS and replay into independent fixture storage."""
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
    secure = args.tls
    certificate = None
    environment = dict(os.environ, RUST_LOG="info", NO_COLOR="1")
    if secure:
        key, certificate, spki = fixture_certificate(root)
        environment.update(
            RAMA_TLS_KEY=base64.b64encode(key.read_bytes()).decode(),
            RAMA_TLS_CRT=base64.b64encode(certificate.read_bytes()).decode(),
            SSLKEYLOGFILE=str(root / "server.keys"),
        )
    flow_mode = args.flows
    require(flow_mode in ("navigate", "all"), "unsupported flow mode")
    all_flows = flow_mode == "all"
    print(f"capture evidence: {root}", flush=True)
    processes, streams = [], []
    server_command = [
        str(rama),
        "serve",
        "fp",
        "--bind",
        "127.0.0.1:0",
        "--http-version",
        "h1",
    ]
    if secure:
        server_command.append("--secure")

    def start(command, name):
        path = root / name
        stream = path.open("w")
        streams.append(stream)
        process = subprocess.Popen(
            command,
            stdout=stream,
            stderr=subprocess.STDOUT,
            env=environment,
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
                    keylog = None
                    if secure:
                        keylog = root / (
                            "browser.keys"
                            if label == "reference-wire"
                            else "replay.keys"
                        )
                    wire.read_capture(
                        root / (label + ".pcapng"),
                        port,
                        label == "reference-wire",
                        keylog=keylog,
                        expected_per_flow=len(variants),
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

    variants = [None]
    marker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    marker.bind(("127.0.0.1", 0))
    marker_port = marker.getsockname()[1]

    def interrupted(number, _frame):
        raise InterruptedError(number)

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)

    try:
        server, log = start(
            server_command,
            "fp.log",
        )
        port = ready(server, log, r"network\.local\.port[= ]+(\d+)")

        # Record the browser's original requests before exporting their profile.
        reference_wire = capture_wire(port, "reference-wire")
        browser_kind = args.browser
        options, prepare_profile = (
            tls_browser_options(args, port, certificate, spki)
            if secure
            else (None, None)
        )
        with local_session(
            browser_kind,
            profile=root / "browser-profile",
            binary=args.browser_binary,
            keylog=root / "browser.keys" if secure else None,
            options=options,
            prepare_profile=prepare_profile,
        ) as driver:
            capture_result = run_capture_flow(
                driver,
                f"https://localhost:{port}" if secure else f"http://127.0.0.1:{port}",
                expected_protocol="h1",
                all_flows=all_flows,
            )
            write_driver_result(root / "page-result.json", capture_result)
            (root / "page.html").write_text(capture_result.report_html)
            result = {
                "browser": capture_result.browser_name,
                "version": capture_result.browser_version,
                "protocols": dict(capture_result.protocols),
            }
            if all_flows:
                result["websocket_probe_sha256"] = hashlib.sha256(
                    capture_result.websocket_probe.encode()
                ).hexdigest()
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
                    **result,
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

        # Inspect the original archive against independently decoded H1 fields,
        # retaining one browser/flow/header observation instead of mixing variants.
        with (root / "inspected.json").open("w") as output:
            subprocess.run(
                [str(rama), "ua", "view", "--json", str(root / "profiles.json")],
                stdout=output,
                check=True,
                timeout=30,
            )
        inspected = json.loads((root / "inspected.json").read_text())
        if all_flows:
            headers = wire.read_h1_header_blocks(
                root / "reference-wire.pcapng",
                port,
                keylog=root / "browser.keys" if secure else None,
            )
            fields = compare_capture_fields(inspected, headers)
            websocket_reference = wire.read_h1_websocket_evidence(
                root / "reference-wire.pcapng",
                port,
                headers,
                keylog=root / "browser.keys" if secure else None,
                websocket_probe=capture_result.websocket_probe,
            )
            (root / "capture-fields.json").write_text(
                json.dumps(fields, indent=2) + "\n"
            )
        tls_reference = None
        if secure:
            variants = connection_variants(inspected)
            tls_reference = wire.h1_tls_evidence(
                root / "reference-wire.pcapng",
                root / "browser.keys",
                port,
                root / "headers.pdml",
                inspected,
            )

        # Replay into a second database so reference observations cannot mask failure.
        environment = replay_environment(environment)
        if secure:
            environment["SSLKEYLOGFILE"] = str(root / "replay.keys")
        replay, log = start(
            server_command,
            "fp-replay.log",
        )
        replay_port = ready(replay, log, r"network\.local\.port[= ]+(\d+)")
        replay_wire = capture_wire(replay_port, "replay-wire")
        if all_flows:
            reference_flows = wire.read_capture(
                root / "reference-wire.pcapng",
                port,
                True,
                keylog=root / "browser.keys" if secure else None,
            )
            trust_ids = None
            origin = f"http://127.0.0.1:{replay_port}"
            if secure:
                trust_ids = current_trust_ids(
                    client_hellos((root / "headers.pdml").read_bytes(), "Tcp")
                )
                origin = f"https://localhost:{replay_port}"
            target = flows.ReplayTarget("h1", origin, certificate, trust_ids)
            if secure:
                probe = flows.replay_args(
                    rama,
                    root / "profiles.json",
                    root / "binding-probe.response",
                    target,
                    "navigate",
                    reference_flows["navigate"][0],
                    connection_variant=variants[0],
                )
                check_missing_tls_bindings(
                    probe,
                    environment,
                    root,
                    protocol="h1",
                    trust_ids=trust_ids,
                )
            for index, variant in enumerate(variants):
                for flow in flows.FLOWS:
                    label = f"{index}-{flow}"
                    command = flows.replay_args(
                        rama,
                        root / "profiles.json",
                        root / (label + ".response"),
                        target,
                        flow,
                        reference_flows[flow][0],
                        connection_variant=variant,
                    )
                    run_replay(
                        command,
                        flow=flow,
                        log=root / (label + "-replay.log"),
                        environment=environment,
                        websocket_probe=capture_result.websocket_probe,
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
                    env=environment,
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
                env=environment,
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
        if all_flows:
            wire.verify_h1_flows(
                root, port, replay_port, secure=secure, variants=len(variants)
            )
            headers = wire.read_h1_header_blocks(
                root / "replay-wire.pcapng",
                replay_port,
                keylog=root / "replay.keys" if secure else None,
            )
            fields = compare_capture_fields(inspected, headers)
            websocket_replay = wire.read_h1_websocket_evidence(
                root / "replay-wire.pcapng",
                replay_port,
                headers,
                keylog=root / "replay.keys" if secure else None,
                expected_connections=len(variants),
                websocket_probe=capture_result.websocket_probe,
            )
            (root / "websocket-comparison.json").write_text(
                json.dumps(
                    dict(reference=websocket_reference, replay=websocket_replay),
                    indent=2,
                )
                + "\n"
            )
            (root / "replay-fields.json").write_text(
                json.dumps(fields, indent=2) + "\n"
            )
        else:
            wire.verify_h1_navigation(root, port, replay_port)
        if secure:
            tls_replay = wire.h1_tls_evidence(
                root / "replay-wire.pcapng",
                root / "replay.keys",
                replay_port,
                root / "replay.pdml",
                inspected,
            )
            (root / "tls-comparison.json").write_text(
                json.dumps(
                    dict(
                        reference=tls_reference,
                        replay=tls_replay,
                        variants=len(variants),
                    ),
                    indent=2,
                )
                + "\n"
            )

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
        shutil.rmtree(root / "browser-profile", ignore_errors=True)
