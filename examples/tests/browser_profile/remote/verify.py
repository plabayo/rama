#!/usr/bin/env python3
"""Run existing source/replay oracles on one privately retrieved remote cell."""

import argparse
import base64
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from capture_fields import compare_capture_fields
from disposable_postgres import run as isolated_database
from fixture_tls import fixture_certificate
from flow_bodies import check_flow_bodies, json_object
from flows import flow_protocols
from qpack_fields_wire import compare_field_metadata, sections_from_wire
from remote.admission import admit
from replay import compare_native_connections, tls_hellos, verify_tls_replay
from tls_wire import compare_tls_captures
from wire import Traffic, parse_pdml


def verify(args):
    root = args.output
    page = json_object((root / "page-result.json").read_bytes())
    probe = page["page_results"]["websocket"]["probe"]
    data = (root / "headers.pdml").read_bytes()
    port = urlsplit(args.origin).port
    frames = parse_pdml(data, "mixed", port, include_data=True, websocket_probe=probe)
    traffic = Traffic(
        tuple(block for block in frames if block.headers),
        tuple(frames),
        check_flow_bodies(frames, websocket_probe=probe),
    )
    admission = admit(data, frames, page, args.origin)
    plan = flow_protocols(frames)
    if plan != page["protocols"]:
        raise ValueError("driver protocol plan differs from source wire")
    inspected = json_object((root / "inspected.json").read_bytes())
    source = dict(
        admission=admission,
        fields=compare_capture_fields(inspected, traffic.headers),
        tls=compare_tls_captures(
            inspected, tls_hellos(data, plan.values()), traffic.headers
        ),
        connections=compare_native_connections(
            inspected, data, port, traffic.headers, plan, same_traffic_native=True
        ),
        bodies=traffic.bodies,
    )
    if "h3" in plan.values():
        source["qpack"] = compare_field_metadata(
            inspected,
            traffic.headers,
            sections_from_wire(data, port),
            expected_flows={
                flow for flow, protocol in plan.items() if protocol == "h3"
            },
            connection_joints=source["connections"]["h3"]["connection_joints"],
        )
    key = certificate = None
    try:
        key, certificate, _ = fixture_certificate(
            root, hostname=urlsplit(args.origin).hostname
        )
        environment = dict(
            os.environ,
            RAMA_TLS_KEY=base64.b64encode(key.read_bytes()).decode(),
            RAMA_TLS_CRT=base64.b64encode(certificate.read_bytes()).decode(),
            DIAL9_ENABLED="false",
            RUST_LOG="info",
            NO_COLOR="1",
        )
        server = [
            str(args.rama),
            "serve",
            "fp",
            "--bind",
            f"127.0.0.1:{port}",
            "--http-version",
            "auto" if args.protocol == "h3" else "h1,h2",
            "--secure",
            "--graceful",
            "10",
        ]
        replay = verify_tls_replay(
            args,
            traffic=traffic,
            inspected=inspected,
            server_command=server,
            environment=environment,
            certificate=certificate,
            port=port,
            websocket_probe=probe,
            fixture_origin=args.origin,
        )
        report = dict(
            source=source,
            replay=replay,
            scope="one remote H2/H3 readiness cell with exact source admission and strict local replay; not full matrix/public443 acceptance",
        )
        (root / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
        return 0
    finally:
        for name in ("key.pem", "replay.keys"):
            (root / name).unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rama", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--protocol", choices=("h2", "h3"), required=True)
    parser.add_argument(
        "--interface", default="lo0" if sys.platform == "darwin" else "lo"
    )
    parser.add_argument("--postgres-image", default="postgres:17-alpine")
    parser.add_argument("--inside-disposable-database", action="store_true")
    args = parser.parse_args(argv)
    if not args.inside_disposable_database:
        return isolated_database(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                *(sys.argv[1:] if argv is None else argv),
                "--inside-disposable-database",
            ],
            image_name=args.postgres_image,
        )
    return verify(args)


if __name__ == "__main__":
    raise SystemExit(main())
