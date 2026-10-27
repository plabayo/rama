#!/usr/bin/env python3
"""Emulate every embedded profile and check the fingerprints an echo service detects.

`rama serve echo` reports, for the User-Agent of each request, whether the TLS (JA4)
and HTTP (JA4H) fingerprints it observed match one recorded for that profile. For each
profile and each HTTP version it holds a GET flow for, `rama send --emulate` sends that
flow with the profile's exact User-Agent and the request-owned inputs the browser had:
cookies, connection options, origin and referer, and TLS trust anchor IDs.

Echo must report the planned User-Agent: it judges against the profile it received.
A profile whose recorded QUIC ClientHellos all carry pre_shared_key holds only resumed
handshakes. A fresh `rama send` has no ticket for the origin, so its first QUIC
ClientHello is a full handshake; for such profiles HTTP/3 checks JA4H and reports TLS
as "resumption-only reference" instead of comparing JA4. JA4 and JA4H do not cover QUIC
transport parameters, the Initial layout or HTTP/3 SETTINGS; wire-level equality is the
browser capture harness's job (run.py), which compares those with tshark against a real
browser.
"""

import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys

from fixture_process import running, wait_ready
from tls_wire import PRE_SHARED_KEY_EXTENSION, TRUST_ANCHORS_EXTENSION

# Browsers offer their usual ALPN to an HTTP/1.1-only origin and let it pick http/1.1;
# forcing --http1.1 would narrow the offer to a ClientHello no page load sends.
VERSIONS = {"HTTP/1.1": None, "HTTP/2.0": "--http2", "HTTP/3.0": "--http3"}
# Like the public h1/h2/h3 fp origins: one version per server, under the same names,
# so the ALPN offer and SNI-dependent padding match the collected traffic.
SERVERS = {"HTTP/1.1": "h1", "HTTP/2.0": "h2", "HTTP/3.0": "h3"}
# GET flows replay without request bodies; the first one a profile holds is used.
GET_INITIATORS = ("navigate", "form", "fetch", "xhr")
# Fetch site of the flow `--emulate-initiator` builds: a typed navigation, or a request
# from the page itself. Flows without fetch metadata are plain-HTTP captures.
EMULATED_SITE = {"navigate": "none", "form": "same-origin", "fetch": "same-origin",
                 "xhr": "same-origin"}
# `CanonicalDomain::LegacyField`: imported one-row-per-browser fields.
LEGACY_FIELD_DOMAIN = 23
# Supplied by the destination or transport rather than by request headers.
TRANSPORT_FIELDS = {"host", ":authority", ":path", ":scheme", ":method", "content-length"}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rama", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--match", help="only profiles whose User-Agent contains this text")
    args = parser.parse_args(argv)
    args.rama = args.rama.resolve(strict=True)
    args.output = args.output.resolve()
    return args


def header_fields(value):
    """The first captured header field list inside a decoded variant."""
    if isinstance(value, list):
        if value and all(isinstance(f, dict) and {"name", "occurrence"} <= f.keys() for f in value):
            return value
        items = value
    elif isinstance(value, dict):
        items = value.values()
    else:
        return None
    for item in items:
        found = header_fields(item)
        if found is not None:
            return found
    return None


def tls_extensions(capture, kind):
    """Extension ID sets of the retained ClientHellos on one transport."""
    return [
        {extension["id"] for extension in slot["capture"]["extensions"]}
        for slot in capture.get("slots", [])
        if slot["kind"] == kind
    ]


def profile_plans(rama):
    """Per profile and HTTP version: the GET flow to send and its request-owned inputs."""
    view = subprocess.run(
        [str(rama), "ua", "view", "--embedded", "--json"],
        check=True, capture_output=True, timeout=300,
    )
    plans = []
    for profile in json.loads(view.stdout)["profiles"]:
        requests, hellos = {}, {"TcpTls": [], "QuicTls": []}
        for scope in profile["scopes"]:
            flow = scope["flow"].get("Http") if isinstance(scope["flow"], dict) else None
            for variant in scope["variants"]:
                capture = variant["capture"]
                if capture.get("level") == "Connection":
                    for kind in hellos:
                        hellos[kind] += tls_extensions(capture, kind)
                elif (capture.get("level") == "Request" and flow
                      and flow["method"] == "GET" and flow["version"] in VERSIONS):
                    # Browsers without fetch metadata (Safari before 16.4) have none to match.
                    fetch = flow["fetch"]
                    if fetch is not None and fetch["site"] != EMULATED_SITE.get(flow["initiator"]):
                        continue
                    fields = header_fields(variant) or []
                    owned = [field["name"].lower() for field in fields
                             if isinstance(field.get("value"), dict)
                             and "Request" in field["value"]]
                    key = (flow["version"], flow["initiator"])
                    if fetch is not None or key not in requests:
                        requests[key] = owned
        flows = {}
        for version in sorted(VERSIONS):
            initiator = next((i for i in GET_INITIATORS if (version, i) in requests), None)
            if initiator is None:
                continue
            kind = "QuicTls" if version == "HTTP/3.0" else "TcpTls"
            flows[version] = {
                "initiator": initiator,
                "request_fields": requests[(version, initiator)],
                "trust_anchors": any(TRUST_ANCHORS_EXTENSION in ids for ids in hellos[kind]),
                "resumed_only": bool(hellos[kind]) and all(
                    PRE_SHARED_KEY_EXTENSION in ids for ids in hellos[kind]),
            }
        # Imported legacy rows keep their fields outside joint captures; selection only
        # draws joint captures, so such a profile cannot be emulated as itself.
        legacy = not flows and any(scope["domain"] == LEGACY_FIELD_DOMAIN
                                   for scope in profile["scopes"])
        plans.append({"user_agent": profile["key"]["user_agent"], "key": profile["key"],
                      "flows": flows, "legacy_only": legacy})
    return plans


def reserve_port():
    """A loopback port free for both TCP (H1/H2) and UDP (H3)."""
    for _ in range(64):
        with socket.socket() as tcp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                try:
                    udp.bind(("127.0.0.1", port))
                except OSError:
                    continue
                return port
    raise RuntimeError("no loopback port free for TCP and UDP")


def request_headers(fields, origin):
    """Request-owned fields in the browser's quantities; values are never compared."""
    headers = []
    cookies = fields.count("cookie")
    if cookies:
        headers.append("cookie: " + "; ".join(f"c{index}=1" for index in range(cookies)))
    values = {"connection": "keep-alive", "te": "trailers", "origin": origin,
              "referer": origin + "/"}
    for name in dict.fromkeys(fields):
        if name not in TRANSPORT_FIELDS and name != "cookie":
            headers.append(f"{name}: {values.get(name, '1')}")
    return headers


def emulate(args, plan, version, flow, port, root):
    host = f"{SERVERS[version]}.fp.ramaproxy.org"
    origin = f"https://{host}:{port}"
    command = [
        str(args.rama), "send", "--emulate", "-k",
        "--emulate-initiator", flow["initiator"],
        *([VERSIONS[version]] if VERSIONS[version] else []),
        "--resolve", f"{host}:{port}:127.0.0.1",
        "-H", "user-agent: " + plan["user_agent"],
    ]
    for header in request_headers(flow["request_fields"], origin):
        command += ["-H", header]
    if flow["trust_anchors"]:
        # The IDs belong to the destination; only the extension's presence is compared.
        command += ["--tls-requested-trust-anchors", "0102"]
    command.append(origin + "/report")
    result = subprocess.run(command, capture_output=True, timeout=60)
    (root / f"{SERVERS[version]}.log").write_bytes(result.stderr)
    verdict = {"exit": result.returncode}
    try:
        echoed = json.loads(result.stdout)
    except ValueError:
        return dict(verdict, passed=False, reason="no echo response")

    def matched(fingerprint):
        profile = (fingerprint or {}).get("profile") or {}
        return profile.get("matched"), (fingerprint or {}).get("hash"), profile.get("hash")

    verdict["ja4h"] = matched(echoed.get("http", {}).get("ja4h"))
    verdict["ja4"] = matched((echoed.get("tls") or {}).get("ja4"))
    # Echo compares with the profile of the User-Agent it received: it must be this one.
    verdict["user_agent"] = (echoed.get("ua") or {}).get("user_agent")
    verdict["version"] = (echoed.get("http") or {}).get("version")
    identity_ok = verdict["user_agent"] == plan["user_agent"] and verdict["version"] == version
    tls_ok = verdict["ja4"][0] is True or flow["resumed_only"]
    verdict["tls"] = "resumption-only reference" if flow["resumed_only"] else verdict["ja4"][0]
    verdict["passed"] = (result.returncode == 0 and identity_ok
                         and verdict["ja4h"][0] is True and tls_ok)
    return verdict


def main(argv=None):
    args = parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    plans = profile_plans(args.rama)
    if args.match:
        plans = [plan for plan in plans if args.match in plan["user_agent"]]
    reports = [dict(plan, results={}) for plan in plans]
    for version, name in SERVERS.items():
        port = reserve_port()
        server = [str(args.rama), "serve", "echo", "--mode", "https",
                  "--bind", f"127.0.0.1:{port}", "--http-version", name]
        log = args.output / f"echo-{name}.log"
        with running(server, log, dict(os.environ, NO_COLOR="1")) as process:
            wait_ready(process, log, lambda text: bool(re.search(r"(listening|ready)", text)))
            for index, report in enumerate(reports):
                flow = report["flows"].get(version)
                if flow is None:
                    continue
                root = args.output / f"{index:03d}"
                root.mkdir(exist_ok=True)
                report["results"][version] = emulate(args, report, version, flow, port, root)
    passed = failed = skipped = 0
    for index, report in enumerate(reports):
        if not report["results"]:
            reason = ("legacy-only capture: not selectable for emulation"
                      if report["legacy_only"] else "no GET request flow")
            report["status"] = "skipped"
            report["reason"] = reason
            skipped += 1
            print("SKIPPED", f"{index:03d}", reason, report["user_agent"], flush=True)
            continue
        ok = all(result["passed"] for result in report["results"].values())
        report["status"] = "passed" if ok else "failed"
        passed += ok
        failed += not ok
        summary = " ".join(
            f"{version[5:]}:{'ok' if result['passed'] else 'FAIL'}"
            f"(ja4={result.get('tls')},ja4h={(result.get('ja4h') or [None])[0]})"
            for version, result in report["results"].items())
        print("PASSED" if ok else "FAILED", f"{index:03d}", summary, report["user_agent"],
              flush=True)
    (args.output / "summary.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(f"{passed} passed, {failed} failed, {skipped} skipped of {len(reports)} embedded "
          "profiles", flush=True)
    return 0 if passed and not failed else 1


if __name__ == "__main__":
    sys.exit(main())
