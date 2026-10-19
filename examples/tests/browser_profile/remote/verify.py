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
from disposable_postgres import run as isolated_database
from fixture_tls import fixture_certificate
from flow_bodies import json_object
from replay import verify_tls_replay
from source_evidence import source_evidence


def verify(args):
    root = args.output
    page = json_object((root / "page-result.json").read_bytes())
    data = (root / "headers.pdml").read_bytes()
    inspected = json_object((root / "inspected.json").read_bytes())
    port = urlsplit(args.origin).port
    traffic, operations, source = source_evidence(
        data, inspected, page, args.origin, port
    )
    probe = page["page_results"]["websocket"]["probe"]
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
            {"h1": "h1", "h2": "h1,h2", "h3": "auto"}[args.protocol],
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
            operations=operations,
        )
        report = dict(
            source=source,
            replay=replay,
            scope="one remote H1/H2/H3 readiness cell with exact source admission and strict local replay; not full matrix/public443 acceptance",
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
    parser.add_argument("--protocol", choices=("h1", "h2", "h3"), required=True)
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
