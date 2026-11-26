#!/usr/bin/env python3
"""Emulate every captured request flow of every embedded profile and check what echo detects.

`rama serve echo` reports, for the User-Agent of each request, whether the TLS (JA4)
and HTTP (JA4H) fingerprints it observed match one recorded for that profile. A flow is
a distinct (HTTP version, method, initiator, Fetch metadata) a profile captured requests
for: navigations, form submissions, fetch and XHR posts, subresources, CORS preflights
and WebSocket handshakes. For each flow `rama send --emulate` replays one stored request
variant of it, pinned with `--emulate-request-variant`, with the profile's exact
User-Agent, the flow's method, initiator and `Sec-Fetch-*` values (which select the
flow), and the request-owned inputs that variant had: cookies in its quantity, connection
options, origin, referer, body metadata, CORS preflight fields and TLS trust anchor IDs.
A POST whose variant framed a body carries a small form body, otherwise none. The pinned
variant prefers a scope whose connection context a fresh local connection matches; one
captured only on resumed or early-data connections is unsupported.

Every flow is replayed with its HTTP version forced (`--http1.1`, `--http2`, `--http3`)
and every HTTP/1.1 and HTTP/2 flow over TLS also in the auto form: no version flag (for a
WebSocket `--ws-alpn`, which leaves the version to ALPN), so emulation follows what the
profile holds. A profile holding a flow of the request's kind (ordinary, tunnel or
WebSocket) under both HTTP/1.1 and HTTP/2 sends its own ALPN offer; one holding it under
only one of them, or with only that version's data, is narrowed to that version. The auto
HTTP/1.1 form goes to the HTTP/1.1-only echo, the auto HTTP/2 form to an echo serving
HTTP/1.1 and HTTP/2, where HTTP/2 must be negotiated. The request variant is selected
before that negotiation, so an auto run is not pinned: it draws a stored variant with the
same fixed seed and keys, and its header list must equal one of the flow's variants'. Each
(flow, mode) is its own result, log and count.

A WebSocket flow is sent to a `wss://` URI: the HTTP/1.1 upgrade, or Extended CONNECT over
HTTP/2 and HTTP/3. Echo runs with `--ws`, accepts the handshake and puts its report on the
handshake response as `x-rama-fingerprint-*` headers, which `rama send -v` prints and
which judge the run like echo's JSON report judges any other. A client that then rejects
the handshake response is reported with its error, apart from the verdict. Browsers send
Fetch metadata in every secure context, so a capture without it beside captures with it
(WebSocket handshakes counted apart) is a plaintext page: on HTTP/1.1 it replays over
`http://` or `ws://` against a plaintext echo, where JA4 is reported as "plaintext".
`Alt-Used` is never supplied by the caller: the Alt-Svc layer writes it only when the
request goes through an alternative. A flow with captured `Alt-Used` variants runs
"direct" (no alternative in use): it is judged against its variants without `Alt-Used`,
or, when every variant has one, against those lists with `alt-used` removed, the reserved
slot staying empty; echo then holds no recorded shape without `Alt-Used`, so JA4H is
reported as "recorded only with Alt-Used" and the exact header list decides.
An HTTP/3 flow with `Alt-Used` also runs "alt-svc": one `rama send` with `--http3` sends the
pinned variant with `Alt-Used` twice (`--next`) to `localhost` on an echo serving HTTP/1.1,
HTTP/2 and HTTP/3 with a fixture identity trusted through `--cacert`. The first response
advertises its HTTP/3 listener, which is learned only from an authenticated origin without
`-k` or `--resolve`; the second request goes through that alternative and the Alt-Svc layer
writes `Alt-Used` into the reserved slot. That second report is judged against the variant's
exact header list including `alt-used`. Its auto form ("auto alt-svc") sends no version flag
and pins no variant: the first request goes over TCP and learns the alternative, the second
reaches it over HTTP/3 and emulation draws a variant for that version, whose header list
must equal one of the flow's stored variants. HTTP/2 flows with `Alt-Used` are
replayed the same way against an echo advertising only a second HTTP/2 listener of its
own (`--alt-svc-h2-bind`), so the client never prefers an HTTP/3 alternative.
Runs execute concurrently (`--jobs`) against one echo per server; output stays in plan order.

Each run passes when echo reports the planned User-Agent, HTTP version and method, its
JA4H matches a recorded one and lists the header names of the pinned variant (forced) or
of one stored variant of the flow (auto) in order, with their casing on HTTP/1.1, and
JA4 matches, except in the cases below. Every flow that cannot be replayed is reported
as UNSUPPORTED with its reason and counted; a profile fails when any of its runs fails.

A narrowed (forced, or auto as above) HTTP/1.1 offer must match JA4 when the profile holds a TCP TLS hello offering
only http/1.1; otherwise it has no reference and TLS is reported as "http/1.1-only offer".
A narrowed HTTP/2 offer keeps the first ALPN value of the browser's offer, the only one JA4
encodes, so it must match JA4. The summary counts the auto runs narrowed because the profile
holds the flow's kind under only one version.
A profile whose TLS captures on a transport were all resumed handshakes (analysis drops
those) cannot be selected for a flow on it; those flows are unsupported.
A profile whose recorded QUIC ClientHellos all carry pre_shared_key holds only resumed
handshakes. A fresh `rama send` has no ticket for the origin, so its first QUIC
ClientHello is a full handshake; for such profiles HTTP/3 checks JA4H and reports TLS
as "resumption-only reference" instead of comparing JA4. JA4 and JA4H do not cover QUIC
transport parameters, the Initial layout or HTTP/3 SETTINGS; wire-level equality is the
browser capture harness's job (run.py), which compares those with tshark against a real
browser.
"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile

from fixture_process import running, wait_ready
from fixture_tls import fixture_certificate
from tls_wire import PRE_SHARED_KEY_EXTENSION, TRUST_ANCHORS_EXTENSION

# The flag that forces each HTTP version; the auto form sends none and keeps the
# browser's own ALPN offer.
FORCED = {"HTTP/1.1": "--http1.1", "HTTP/2.0": "--http2", "HTTP/3.0": "--http3"}
# Like the public h1/h2/h3 fp origins: one version per server, under the same names,
# so the ALPN offer and SNI-dependent padding match the collected traffic.
SERVERS = {"HTTP/1.1": "h1", "HTTP/2.0": "h2", "HTTP/3.0": "h3"}
# Plaintext HTTP/1.1 captures replay against their own echo without TLS.
PLAINTEXT = "h1-plain"
# The auto form of an HTTP/2 flow negotiates HTTP/2 with an echo that also serves HTTP/1.1.
BOTH = "h1h2"
# `CanonicalDomain::LegacyField`: imported one-row-per-browser fields.
LEGACY_FIELD_DOMAIN = 23
# Analyzed components `rama send --emulate` requires for a forced flow of each HTTP version.
REQUIRED_COMPONENTS = {"HTTP/1.1": ("h1", "tls_tcp"), "HTTP/2.0": ("h2", "tls_tcp"),
                       "HTTP/3.0": ("h3", "tls_quic", "quic"), PLAINTEXT: ("h1",)}
# Supplied by the destination, the transport or the WebSocket client rather than by -H.
TRANSPORT_FIELDS = {"host", ":authority", ":path", ":scheme", ":method", "content-length",
                    "upgrade", "sec-websocket-key", "sec-websocket-protocol", "alt-used"}
# The request header each Fetch metadata field of a flow is selected by.
FETCH_HEADERS = {"site": "sec-fetch-site", "mode": "sec-fetch-mode",
                 "destination": "sec-fetch-dest", "user_activation": "sec-fetch-user"}
# JA4H leaves these out of its header list.
JA4H_EXCLUDED = {"cookie", "referer"}
FORM_BODY = "a=1"
DRAW = "00" * 32
SEPARATOR = re.compile(r"[\s,]*")
ALPN_EXTENSION = 16
# Seconds; an HTTP/3 handshake that never completes must not stall the pool.
SEND_TIMEOUT = 60
# Serves HTTP/1.1, HTTP/2 and HTTP/3 with the fixture identity, advertising its HTTP/3.
ALT_SVC = "alt-svc"
# Serves HTTP/1.1 and HTTP/2 with the fixture identity, advertising only a second HTTP/2
# listener, so a client never prefers an HTTP/3 alternative.
ALT_SVC_H2 = "alt-svc-h2"
# Echo puts its report on a WebSocket handshake response as these headers.
FINGERPRINT_HEADER = "x-rama-fingerprint-"
# Without a version flag: learned over TCP, then reached as an alternative.
ALT_SVC_AUTO = "auto alt-svc"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rama", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--match", help="only profiles whose User-Agent contains this text")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1),
                        help="flows replayed concurrently")
    args = parser.parse_args(argv)
    args.rama = args.rama.resolve(strict=True)
    args.output = args.output.resolve()
    return args


def http1_only_offer(capture):
    """Whether a TCP TLS connection capture offered only `http/1.1` in ALPN."""
    for slot in capture.get("slots", []):
        if slot["kind"] != "TcpTls":
            continue
        for extension in slot["capture"]["extensions"]:
            if extension["id"] == ALPN_EXTENSION:
                protocols = (extension.get("value") or {}).get("Protocols") or []
                if [bytes(protocol) for protocol in protocols] == [b"http/1.1"]:
                    return True
    return False


def flow_kind(flow):
    """What a flow is for, as selection tells them apart: a WebSocket in either version's form."""
    if flow["initiator"] == "ws" or (flow["fetch"] or {}).get("mode") == "websocket":
        return "websocket"
    return "tunnel" if flow["method"] == "CONNECT" else "ordinary"


def fresh_context(flow):
    """Whether a scope's connection context is what a new local connection presents."""
    connection = flow.get("connection") or {}
    return (connection.get("token_present") is not True
            and connection.get("resumption") != "Resumed"
            and connection.get("early_data") is not True)


def replayable_context(flow):
    """Selection never serves a resumed or early-data scope to a fresh connection."""
    connection = flow.get("connection") or {}
    return connection.get("resumption") != "Resumed" and connection.get("early_data") is not True


def tls_extensions(capture, kind):
    """Extension ID sets of the retained ClientHellos on one transport."""
    return [
        {extension["id"] for extension in slot["capture"]["extensions"]}
        for slot in capture.get("slots", [])
        if slot["kind"] == kind
    ]


def request_fields(capture):
    """The captured header fields of a request variant, in wire order."""
    for slot in capture.get("slots", []):
        if slot["kind"] == "Headers":
            return slot["capture"].get("fields") or []
    return []


def flow_label(flow, plaintext=False):
    """Stable, human-readable name of one flow."""
    fetch = flow["fetch"]
    metadata = ("no-fetch-metadata" if fetch is None else "/".join(
        fetch.get(name) or "-" for name in ("site", "mode", "destination"))
        + ("/user" if fetch.get("user_activation") else ""))
    server = SERVERS.get(flow["version"], flow["version"]) + ("-plain" if plaintext else "")
    return " ".join((server, flow["method"], flow["initiator"] or "-", metadata))


def unsupported_reason(flow, plaintext):
    """Why `rama send` cannot replay this flow against echo, or None when it can."""
    if flow["version"] not in FORCED:
        return "HTTP version not served by echo"
    if flow["method"] not in ("GET", "POST", "OPTIONS", "CONNECT"):
        return "method not replayed"
    if flow["method"] == "CONNECT" and flow["initiator"] != "ws":
        return "CONNECT tunnel not replayed"
    if plaintext and flow["version"] != "HTTP/1.1":
        # Over TLS, selection skips shapes without Fetch metadata when the profile has some.
        return "captured without Fetch metadata beside TLS captures with it"
    return None


def has_alt_used(variant):
    return any(field["name"].lower() == "alt-used"
               for field in request_fields(variant["capture"]))


def without_alt_used(names):
    return [name for name in names if name.lower() != "alt-used"]


def ja4h_names(fields, version):
    """The JA4H header list of captured fields; HTTP/2 and HTTP/3 names are lowercase."""
    return [field["name"] if version == "HTTP/1.1" else field["name"].lower()
            for field in fields if field["name"].lower() not in JA4H_EXCLUDED]


def variant_id(variant):
    return bytes(variant["id"]).hex()


def embedded_profiles(rama):
    """Profiles of `rama ua view --embedded --json`, decoded one at a time to bound memory."""
    with tempfile.TemporaryFile() as output:
        subprocess.run([str(rama), "ua", "view", "--embedded", "--json"],
                       check=True, stdout=output, stderr=subprocess.PIPE, timeout=300)
        output.seek(0)
        text = output.read().decode()
    decoder = json.JSONDecoder()
    start = re.search(r'"profiles"\s*:\s*\[', text)
    if start is None:
        raise ValueError("embedded profile view lists no profiles")
    index = start.end()
    while True:
        index = SEPARATOR.match(text, index).end()
        if text.startswith("]", index):
            return
        profile, index = decoder.raw_decode(text, index)
        yield profile


def profile_plans(rama):
    """Per profile: every distinct captured request flow, each with one pinned variant."""
    plans = []
    for profile in embedded_profiles(rama):
        candidates, hellos, metadata = {}, {"TcpTls": [], "QuicTls": []}, set()
        http1_reference = False
        # Per flow kind, the versions holding a flow a fresh connection can replay.
        kind_versions = {}
        for scope in profile["scopes"]:
            flow = scope["flow"].get("Http") if isinstance(scope["flow"], dict) else None
            fresh = not flow or fresh_context(flow)
            for variant in scope["variants"]:
                capture = variant["capture"]
                if capture.get("level") == "Connection":
                    for kind in hellos:
                        hellos[kind] += tls_extensions(capture, kind)
                    http1_reference |= http1_only_offer(capture)
                elif capture.get("level") == "Request" and flow:
                    key = json.dumps({name: flow[name] for name in
                                      ("version", "method", "initiator", "fetch")},
                                     sort_keys=True)
                    # A direct run is pinned to a variant without Alt-Used where there is one.
                    rank = (not fresh, has_alt_used(variant))
                    candidates.setdefault(key, []).append((rank, flow, variant))
                    if replayable_context(flow):
                        kind_versions.setdefault(flow_kind(flow), set()).add(flow["version"])
                    if flow["fetch"] is not None:
                        metadata.add((flow["version"], flow["initiator"] == "ws"))
        flows, unsupported, unselectable = [], [], []
        for key in sorted(candidates):
            _, flow, variant = min(candidates[key], key=lambda c: c[0])
            fields = request_fields(variant["capture"])
            owned = [field["name"].lower() for field in fields
                     if isinstance(field.get("value"), dict) and "Request" in field["value"]]
            version = flow["version"]
            # Browsers send Fetch metadata in every secure context: a capture without it
            # beside ones with it is a plaintext page. Selection weighs WebSocket handshakes
            # only against each other, and some browsers send them without metadata.
            plaintext = (flow["fetch"] is None
                         and (version, flow["initiator"] == "ws") in metadata)
            label = flow_label(flow, plaintext)
            reason = unsupported_reason(flow, plaintext)
            if reason is None and not replayable_context(flow):
                reason = "captured only on resumed or early-data connections"
            if (reason is None and flow["method"] == "POST" and "content-length" in owned
                    and "content-type" not in owned):
                reason = "rama send adds Content-Type to every request body"
            components = PLAINTEXT if plaintext else version
            missing = [name for name in REQUIRED_COMPONENTS.get(components, ())
                       if not profile["components"].get(name)]
            if reason is None and missing:
                reason = "profile lacks components " + ", ".join(missing)
                if components not in unselectable:
                    unselectable.append(components)
            if reason is not None:
                unsupported.append({"flow": label, "reason": reason})
                continue
            kind = "QuicTls" if version == "HTTP/3.0" else "TcpTls"
            # Without a version flag emulation follows what the profile holds; HTTP/3 needs one.
            # A WebSocket leaves the version to ALPN only with `--ws-alpn`.
            auto = not plaintext and version in ("HTTP/1.1", "HTTP/2.0")
            # Emulation narrows such an auto run, as the forced form does, to the one TCP
            # version holding this kind of flow, or holding data at all.
            both = bool(profile["components"].get("h1") and profile["components"].get("h2"))
            flow_narrowed = (kind_versions.get(flow_kind(flow), set())
                             & {"HTTP/1.1", "HTTP/2.0"}) == {version}
            narrowed = auto and (flow_narrowed or not both)
            # An unpinned auto run may draw any stored variant of the flow. Without an
            # alternative in use no Alt-Used is sent: the variants without one are expected,
            # or, when every variant has one, their lists with that slot left empty.
            alt_used = any(has_alt_used(other) for _, _, other in candidates[key])
            plain = [other for _, _, other in candidates[key] if not has_alt_used(other)]
            variant_names = []
            for other in plain or [other for _, _, other in candidates[key]]:
                names = without_alt_used(ja4h_names(request_fields(other["capture"]), version))
                if names not in variant_names:
                    variant_names.append(names)
            # The best ranked variant with Alt-Used is replayed through the alternative.
            alt_variant = next((other for _, _, other in sorted(
                candidates[key], key=lambda c: c[0][0]) if has_alt_used(other)), None)
            flows.append({
                "label": label,
                "kind": flow_kind(flow),
                "version": version,
                "method": flow["method"],
                "initiator": flow["initiator"],
                "fetch": flow["fetch"],
                "variant": variant_id(variant),
                "plaintext": plaintext,
                "request_fields": owned,
                "ja4h_headers": without_alt_used(ja4h_names(fields, version)),
                "alt_used": alt_used,
                # Echo's recorded shapes then all hold Alt-Used: none can match JA4H.
                "alt_used_only": alt_used and not plain,
                "variant_headers": variant_names,
                "modes": (["forced", "auto"] if auto else ["forced"])
                + ([ALT_SVC, ALT_SVC_AUTO] if alt_used else []),
                # An unpinned run through the alternative may send any stored variant.
                "alt_auto_headers": [
                    ja4h_names(request_fields(other["capture"]), version)
                    for _, _, other in candidates[key]] if alt_used else [],
                "alt_variant": alt_variant and variant_id(alt_variant),
                "alt_headers": alt_variant and ja4h_names(
                    request_fields(alt_variant["capture"]), version),
                "alt_request_fields": alt_variant and [
                    field["name"].lower() for field in request_fields(alt_variant["capture"])
                    if isinstance(field.get("value"), dict) and "Request" in field["value"]],
                "auto_narrowed": narrowed,
                # Narrowed by the flow-kind rule on a profile with both versions' data.
                "flow_narrowed": narrowed and flow_narrowed and both,
                # An http/1.1-only reference hello means a forced HTTP/1.1 offer must match it.
                "http1_reference": http1_reference,
                "trust_anchors": any(TRUST_ANCHORS_EXTENSION in ids for ids in hellos[kind]),
                "resumed_only": bool(hellos[kind]) and all(
                    PRE_SHARED_KEY_EXTENSION in ids for ids in hellos[kind]),
            })
        # Imported legacy rows keep their fields outside joint captures; selection only
        # draws joint captures, so such a profile cannot be emulated as itself.
        legacy = not candidates and any(
            scope["domain"] == LEGACY_FIELD_DOMAIN for scope in profile["scopes"])
        plans.append({"user_agent": profile["key"]["user_agent"], "key": profile["key"],
                      "flows": flows, "unsupported": unsupported,
                      "unselectable": unselectable, "legacy_only": legacy})
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


def request_headers(fields, authority, scheme="https", websocket=False):
    """Request-owned fields in the browser's quantities; values are never compared, but a
    WebSocket upgrade keeps its `Connection: Upgrade`."""
    origin = scheme + "://" + authority
    headers = []
    cookies = fields.count("cookie")
    if cookies:
        headers.append("cookie: " + "; ".join(f"c{index}=1" for index in range(cookies)))
    values = {"connection": "Upgrade" if websocket else "keep-alive", "te": "trailers",
              "origin": origin,
              "referer": origin + "/",
              "content-type": "application/x-www-form-urlencoded",
              "access-control-request-method": "POST",
              "access-control-request-headers": "x-rama-custom-header-marker"}
    for name in dict.fromkeys(fields):
        if name not in TRANSPORT_FIELDS and name != "cookie":
            headers.append(f"{name}: {values.get(name, '1')}")
    return headers


def request_args(plan, flow, authority, scheme, variant, fields):
    """The per-request part of a `rama send` invocation, repeated after `--next`."""
    command = [
        *(["--emulate-request-variant", variant] if variant else []),
        "-H", "user-agent: " + plan["user_agent"],
    ]
    if flow["initiator"]:
        command += ["--emulate-initiator", flow["initiator"]]
    # The caller's Fetch metadata selects the flow; without it the capture's applies.
    for name, header in FETCH_HEADERS.items():
        value = (flow["fetch"] or {}).get(name)
        if value:
            command += ["-H", f"{header}: {value}"]
    if flow["method"] == "POST":
        command += ["-X", "POST"]
        # A variant without Content-Length framing was an empty-body POST.
        if "content-length" in fields:
            command += ["-d", FORM_BODY]
    elif flow["method"] == "OPTIONS":
        command += ["-X", "OPTIONS"]
        if "content-length" in fields:
            command += ["-H", "content-length: 0"]
    origin = "http" if flow["plaintext"] else "https"
    for header in request_headers(fields, authority, origin, flow["initiator"] == "ws"):
        command += ["-H", header]
    command.append(f"{scheme}://{authority}/report")
    return command


def send_command(args, plan, flow, port, mode="forced"):
    """The `rama send` invocation that replays one flow in one mode against its echo."""
    version = flow["version"]
    if mode in (ALT_SVC, ALT_SVC_AUTO):
        # The first request learns the alternative from the origin, the second goes
        # through it; resolving and trust are left to the defaults so learning applies.
        # Without a version flag the request variant is drawn once the version is known.
        authority = f"localhost:{port}"
        forced = mode == ALT_SVC
        each = request_args(plan, flow, authority, "https",
                            flow["alt_variant"] if forced else None,
                            flow["alt_request_fields"])
        return [str(args.rama), "send", "--emulate", *([FORCED[version]] if forced else []),
                "--cacert", str(args.ca), "--last-response-only", "--emulate-seed", DRAW,
                "--emulate-connection-key", DRAW, "--emulate-request-key", DRAW,
                *(["--tls-requested-trust-anchors", "0102"] if flow["trust_anchors"] else []),
                *each, "--next", *each]
    websocket = flow["initiator"] == "ws"
    host = f"{SERVERS[version]}.fp.ramaproxy.org"
    authority = f"{host}:{port}"
    scheme = ("ws" if websocket else "http") + (
        "" if flow["plaintext"] else "s")
    command = [
        str(args.rama), "send", "--emulate", "-k",
        *([FORCED[version]] if mode == "forced" else ["--ws-alpn"] if websocket else []),
        # Echo answers a WebSocket handshake with its report as response headers.
        *(["-v"] if websocket else []),
        "--resolve", f"{host}:{port}:127.0.0.1",
        # Pins need a fixed draw; any fixed one keeps a replay deterministic.
        "--emulate-seed", DRAW, "--emulate-connection-key", DRAW,
        "--emulate-request-key", DRAW,
    ]
    if "sec-websocket-protocol" in flow["request_fields"]:
        # Echo accepts only its own subprotocols; JA4H compares the header's name alone.
        command += ["--subprotocol", "echo"]
    if flow["trust_anchors"] and not flow["plaintext"]:
        # The IDs belong to the destination; only the extension's presence is compared.
        command += ["--tls-requested-trust-anchors", "0102"]
    # Forced runs pin the variant; an auto run draws one, as its version is negotiated later.
    variant = flow["variant"] if mode == "forced" else None
    return command + request_args(plan, flow, authority, scheme, variant,
                                  flow["request_fields"])


def slug(label):
    return re.sub(r"[^A-Za-z0-9]+", "-", label).strip("-")


def ja4h_headers(fingerprint):
    """Header names of an echoed JA4H, from its verbose form."""
    verbose = (fingerprint or {}).get("verbose") or ""
    parts = verbose.split("_")
    return [name for name in parts[1].split(",") if name] if len(parts) > 1 else None


def run_label(flow, mode):
    if mode == ALT_SVC:
        return f"{flow['label']} forced {ALT_SVC}"
    if mode == ALT_SVC_AUTO:
        return f"{flow['label']} {ALT_SVC_AUTO}"
    return f"{flow['label']} {mode}" + (" direct" if flow.get("alt_used") else "")


def echoed_headers(stderr):
    """Echo's report from the fingerprint headers `-v` prints of a handshake response."""
    facts = {}
    for line in stderr.decode(errors="replace").splitlines():
        if line.startswith("< " + FINGERPRINT_HEADER):
            name, _, value = line[2 + len(FINGERPRINT_HEADER):].partition(":")
            facts[name.strip().lower()] = value.strip()
    if "http-version" not in facts:
        return None

    def fingerprint(name):
        if name not in facts:
            return None
        matched = facts.get(name + "-matched")
        return {"hash": facts[name], "verbose": facts.get(name + "-verbose"),
                "profile": None if matched is None else {
                    "hash": facts.get(name + "-profile"), "matched": matched == "true"}}

    return {"ua": {"user_agent": facts.get("ua")},
            "http": {"version": facts["http-version"], "method": facts.get("http-method"),
                     "ja4h": fingerprint("ja4h")},
            "tls": {"ja4": fingerprint("ja4")}}


def client_error(stderr):
    """The error `rama send` exited with, if it printed one."""
    lines = [line for line in stderr.decode(errors="replace").splitlines()
             if "exit with error:" in line]
    return lines[-1].split("exit with error:", 1)[1].strip() if lines else None


def emulate(args, plan, flow, port, root, mode="forced"):
    """Replay one flow in one mode and judge what echo reports for it."""
    command = send_command(args, plan, flow, port, mode)
    log = root / (slug(run_label(flow, mode)) + ".log")
    try:
        # A WebSocket exchanges stdin lines; at end of input it closes.
        result = subprocess.run(command, capture_output=True, stdin=subprocess.DEVNULL,
                                timeout=SEND_TIMEOUT)
    except subprocess.TimeoutExpired as error:
        log.write_bytes(error.stderr or b"")
        return {"mode": mode, "kind": flow["kind"], "passed": False,
                "reason": "rama send timed out"}
    log.write_bytes(result.stderr)
    verdict = {"mode": mode, "kind": flow["kind"], "exit": result.returncode}
    websocket = flow["initiator"] == "ws"
    if websocket:
        echoed = echoed_headers(result.stderr)
    else:
        try:
            echoed = json.loads(result.stdout)
        except ValueError:
            echoed = None
    if echoed is None:
        return dict(verdict, passed=False, reason="no echo response",
                    client_error=client_error(result.stderr))

    def matched(fingerprint):
        profile = (fingerprint or {}).get("profile") or {}
        return profile.get("matched"), (fingerprint or {}).get("hash"), profile.get("hash")

    http = echoed.get("http") or {}
    verdict["ja4h"] = matched(http.get("ja4h"))
    verdict["ja4"] = matched((echoed.get("tls") or {}).get("ja4"))
    # Echo compares with the profile of the User-Agent it received: it must be this one.
    verdict["user_agent"] = (echoed.get("ua") or {}).get("user_agent")
    verdict["version"] = http.get("version")
    verdict["method"] = http.get("method")
    identity_ok = (verdict["user_agent"] == plan["user_agent"]
                   and verdict["version"] == flow["version"]
                   and verdict["method"] == flow["method"])
    # Echo accepts any recorded shape; the flow's own header list must be sent: the
    # pinned variant's when forced, one of its stored variants' in the auto form.
    headers = ja4h_headers(http.get("ja4h"))
    expected = ([flow["alt_headers"]] if mode == ALT_SVC
                else flow["alt_auto_headers"] if mode == ALT_SVC_AUTO
                else [flow["ja4h_headers"]] if mode == "forced" else flow["variant_headers"])
    verdict["ja4h_flow"] = headers in expected
    if not verdict["ja4h_flow"]:
        verdict["ja4h_headers"] = {"expected": expected, "echoed": headers}
    # A narrowed HTTP/1.1 offer has no reference unless the browser sent one itself.
    narrowed = mode == "forced" or flow["auto_narrowed"]
    h1_exempt = (narrowed and flow["version"] == "HTTP/1.1" and not flow["plaintext"]
                 and not flow["http1_reference"])
    tls_ok = (verdict["ja4"][0] is True or flow["resumed_only"] or h1_exempt
              or flow["plaintext"])
    verdict["tls"] = ("plaintext" if flow["plaintext"]
                      else "resumption-only reference" if flow["resumed_only"]
                      else "http/1.1-only offer" if h1_exempt and not verdict["ja4"][0]
                      else verdict["ja4"][0])
    # The report is on the handshake response; a client that then rejects that response
    # is reported apart, as it does not change what was sent.
    exit_ok = result.returncode == 0 or websocket
    if result.returncode != 0 and websocket:
        verdict["client_error"] = client_error(result.stderr)
    # Without a recorded shape lacking Alt-Used, only the exact header list can be judged.
    ja4h_ok = verdict["ja4h"][0] is True or bool(
        mode not in (ALT_SVC, ALT_SVC_AUTO) and flow.get("alt_used_only")
        and verdict["ja4h_flow"])
    if verdict["ja4h"][0] is not True and ja4h_ok:
        verdict["ja4h_status"] = "recorded only with Alt-Used"
    verdict["passed"] = (exit_ok and identity_ok and ja4h_ok and verdict["ja4h_flow"]
                         and tls_ok)
    return verdict


def server_name(flow, mode):
    """The echo a flow replays against in one mode."""
    if mode in (ALT_SVC, ALT_SVC_AUTO):
        return ALT_SVC if flow["version"] == "HTTP/3.0" else ALT_SVC_H2
    if flow["plaintext"]:
        return PLAINTEXT
    if flow["version"] == "HTTP/2.0" and mode == "auto":
        return BOTH
    return SERVERS[flow["version"]]


def describe(result):
    if result["passed"]:
        return "ok"
    if "reason" in result:
        return "FAIL(" + result["reason"] + ")"
    failed = [name for name, ok in (
        ("ua", result.get("user_agent") is not None),
        ("ja4h", (result.get("ja4h") or [None])[0] is True),
        ("ja4h-flow", result.get("ja4h_flow")),
        ("ja4", result.get("tls") not in (False, None)),
    ) if not ok]
    return "FAIL(" + ",".join(failed or ["identity-or-exit"]) + ")"


def main(argv=None):
    args = parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    # Alt-Svc is learned only from an authenticated origin: a fixture CA vouches for echo.
    identity = args.output / "identity"
    identity.mkdir(mode=0o700)
    key, certificate, args.ca, _ = fixture_certificate(identity)
    identity_environment = dict(
        os.environ, NO_COLOR="1",
        RAMA_TLS_KEY=base64.b64encode(key.read_bytes()).decode(),
        RAMA_TLS_CRT=base64.b64encode(certificate.read_bytes()).decode())
    plans = profile_plans(args.rama)
    if args.match:
        plans = [plan for plan in plans if args.match in plan["user_agent"]]
    reports = [dict(plan, results={}) for plan in plans]
    with ExitStack() as stack, ThreadPoolExecutor(max(1, args.jobs)) as pool:
        ports = {}
        for name, scheme, version in (*((name, "https", name) for name in SERVERS.values()),
                                      (BOTH, "https", "h1,h2"), (PLAINTEXT, "http", "h1"),
                                      (ALT_SVC, "https", "h1,h2,h3"),
                                      (ALT_SVC_H2, "https", "h1,h2")):
            port = reserve_port()
            server = [str(args.rama), "serve", "echo", "--mode", scheme,
                      "--bind", f"127.0.0.1:{port}", "--http-version", version]
            if name == ALT_SVC_H2:
                server += ["--alt-svc-h2-bind", f"127.0.0.1:{reserve_port()}"]
            elif name != ALT_SVC:
                server.append("--ws")
            log = args.output / f"echo-{name}.log"
            environment = (identity_environment if name in (ALT_SVC, ALT_SVC_H2)
                           else dict(os.environ, NO_COLOR="1"))
            process = stack.enter_context(running(server, log, environment))
            wait_ready(process, log, lambda text: bool(re.search(r"(listening|ready)", text)))
            ports[name] = port
        pending = []
        for index, report in enumerate(reports):
            root = args.output / f"{index:03d}"
            root.mkdir(exist_ok=True)
            pending.append([(run_label(flow, mode), pool.submit(
                emulate, args, report, flow, ports[server_name(flow, mode)], root, mode))
                for flow in report["flows"] for mode in flow["modes"]])
        totals = {"passed": 0, "failed": 0, "unsupported": 0, "ws_h1_offer": 0,
                  "flow_narrowed": 0, "ws_client_error": 0}
        # Per mode and flow kind.
        per_kind = {}
        per_mode = {mode: {"passed": 0, "failed": 0}
                    for mode in ("forced", "auto", ALT_SVC, ALT_SVC_AUTO)}
        counts = {"passed": 0, "failed": 0, "skipped": 0}
        # Profiles report in plan order as their flows finish, so output is deterministic.
        for index, (report, futures) in enumerate(zip(reports, pending)):
            for label, future in futures:
                result = report["results"][label] = future.result()
                outcome = "passed" if result["passed"] else "failed"
                per_mode[result["mode"]][outcome] += 1
                kind = per_kind.setdefault(f"{result['mode']} {result['kind']}",
                                           {"passed": 0, "failed": 0})
                kind[outcome] += 1
                totals["ws_client_error"] += (result["kind"] == "websocket"
                                              and "ja4h" in result and result["exit"] != 0)
                totals["ws_h1_offer"] += (" ws " in label
                                          and result.get("tls") == "http/1.1-only offer")
            totals["flow_narrowed"] += sum(flow["flow_narrowed"] for flow in report["flows"]
                                           if "auto" in flow["modes"])
            totals["unsupported"] += len(report["unsupported"])
            if not report["results"]:
                reason = ("legacy-only capture: not selectable for emulation"
                          if report["legacy_only"] else "no replayable request flow")
                report["status"], report["reason"] = "skipped", reason
                counts["skipped"] += 1
                print("SKIPPED", f"{index:03d}", reason, report["user_agent"], flush=True)
            else:
                ok = all(result["passed"] for result in report["results"].values())
                good = sum(result["passed"] for result in report["results"].values())
                totals["passed"] += good
                totals["failed"] += len(report["results"]) - good
                report["status"] = "passed" if ok else "failed"
                counts[report["status"]] += 1
                print("PASSED" if ok else "FAILED", f"{index:03d}",
                      f"{good}/{len(report['results'])} flows",
                      f"{len(report['unsupported'])} unsupported", report["user_agent"],
                      flush=True)
                for label, result in report["results"].items():
                    if not result["passed"]:
                        print("  FAIL", label, describe(result), flush=True)
            for item in report["unsupported"]:
                print("  UNSUPPORTED", item["flow"], item["reason"], flush=True)
    (args.output / "summary.json").write_text(json.dumps(reports, indent=2) + "\n")
    modes = "; ".join(f"{mode}: {count['passed']} passed, {count['failed']} failed"
                      for mode, count in per_mode.items())
    kinds = "; ".join(f"{name}: {count['passed']} passed, {count['failed']} failed"
                      for name, count in sorted(per_kind.items()))
    print(f"{counts['passed']} passed, {counts['failed']} failed, {counts['skipped']} skipped "
          f"of {len(reports)} embedded profiles; flows: {totals['passed']} passed, "
          f"{totals['failed']} failed, {totals['unsupported']} unsupported, "
          f"{totals['ws_h1_offer']} WebSocket runs on the http/1.1-only offer status, "
          f"{totals['flow_narrowed']} auto runs narrowed to their flow's version, "
          f"{totals['ws_client_error']} WebSocket runs whose client then rejected the "
          f"handshake response ({modes})", flush=True)
    print(f"per mode and kind: {kinds}",
          flush=True)
    return 0 if counts["passed"] and not counts["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
