"""Match the six browser operations to captured HTTP flow contexts."""

import difflib
from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urlsplit

FLOWS = ("navigate", "fetch", "xhr", "ws", "form", "form_get")
FLOW_NAMES = set(FLOWS)

# These safe request facts select the same captured operation, not a new draw
# across automatic navigation, user activation and cross-origin contexts.
FETCH_CONTEXT_FIELDS = (
    ("mode", "sec-fetch-mode"),
    ("site", "sec-fetch-site"),
    ("destination", "sec-fetch-dest"),
    ("user_activation", "sec-fetch-user"),
)


def flow_name(headers, *, protocol=None):
    fields = dict(headers)
    method, path = fields.get(":method"), fields.get(":path", "")
    if method == "GET" and path == "/report":
        return "navigate"
    if method == "POST" and re.fullmatch(r"/api/fetch/number/\d+", path):
        return "fetch"
    if method == "POST" and re.fullmatch(r"/api/xml/number/\d+", path):
        return "xhr"
    if path == "/api/ws" and (
        (protocol == "h1" and method == "GET")
        or (method == "CONNECT" and fields.get(":protocol") == "websocket")
    ):
        return "ws"
    if method == "POST" and path == "/form":
        return "form"
    if method == "GET" and path == "/form?source=web&turtles=yes":
        return "form_get"
    return None


def request_authority(block):
    """Read the protocol's actual authority field without changing raw spelling."""
    name = "host" if block.protocol == "h1" else ":authority"
    values = [value for field, value in block.headers if field.lower() == name]
    require(len(values) == 1, "missing or ambiguous request authority")
    return values[0]


def operation_flow(block, operations=None):
    """Classify only an explicitly declared stream when a ledger is supplied."""
    return (
        operations.role(block)
        if operations is not None
        else flow_name(block.headers, protocol=block.protocol)
    )


def scope_matches(scope, block, flow):
    context = (scope.get("flow") or {}).get("Http")
    if context is None:
        return False
    headers = {name.lower(): value for name, value in block.headers}
    versions = {"h1": "HTTP/1.1", "h2": "HTTP/2.0", "h3": "HTTP/3.0"}
    if context["version"] != versions[block.protocol]:
        return False
    if context["method"] != headers[":method"] or context["initiator"] != (
        "form" if flow == "form_get" else flow
    ):
        return False
    fetch = context["fetch"] or {}
    return all(
        fetch.get(key) == headers.get(header) for key, header in FETCH_CONTEXT_FIELDS
    )


def require(condition, message):
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class ReplayTarget:
    """Current destination and TLS policy, independently of captured metadata."""

    protocol: str
    origin: str
    certificate: Path | None = None
    trust_anchors: str | None = None
    resolve: tuple[str, ...] = ()


def replay_args(
    rama,
    archive,
    output,
    target,
    flow,
    request,
    *,
    connection_variant=None,
    warmup_variants=(),
    request_variant=None,
    preliminary_requests=(),
):
    """Plan one operation, including its preliminary connection exchanges.

    Preliminary requests run first as `--next` segments on the same client; the
    operation itself is always the last segment, so `args[-1]` is its URI.
    Authentication controls reuse this complete plan and change only the TLS
    binding being tested, so bootstrap requirements cannot mask TLS failures.
    """
    flags = {"h1": "--http1.1", "h2": "--http2", "h3": "--http3"}
    require(target.protocol in flags, "unsupported replay protocol")
    destination = urlsplit(target.origin)
    require(
        destination.scheme in ("http", "https")
        and destination.hostname is not None
        and not destination.path
        and not destination.query
        and not destination.fragment
        and destination.username is None,
        "replay target must be an HTTP(S) origin",
    )
    require(
        target.protocol == "h1" or destination.scheme == "https",
        "H2/H3 fixture replay requires TLS",
    )
    require(
        not preliminary_requests or not warmup_variants,
        "explicit preliminary requests cannot mix with GET-only warmups",
    )
    args = [
        str(rama),
        "send",
        f"--emulate={archive}",
        "--emulate-seed",
        "01" * 32,
        "--emulate-connection-key",
        "02" * 32,
        "--emulate-request-key",
        "03" * 32,
        flags[target.protocol],
    ]
    if target.certificate is not None:
        args += ["--cacert", str(target.certificate)]
    if target.trust_anchors is not None:
        args += ["--tls-requested-trust-anchors", target.trust_anchors]
    expected_resolution = f"{destination.hostname}:{destination.port or 443}:127.0.0.1"
    for resolution in target.resolve:
        require(
            resolution == expected_resolution,
            "replay fixture resolution must bind its own authority to loopback",
        )
        args += ["--resolve", resolution]
    if flow == "ws":
        protocols = [
            value.strip()
            for value in request.bindings.get("sec-websocket-protocol", "").split(",")
        ]
        require(protocols == ["a", "b"], "fixture WebSocket protocols")
        args += ["--subprotocol", ",".join(protocols)]
    else:
        args += ["--fail", "--output", str(output)]

    headers = replay_headers(target, request)
    segments = [list(segment) for segment in preliminary_requests]
    segments += [
        warmup_request(target, headers, variant) for variant in warmup_variants
    ]
    if segments:
        # The runner reads only the operation's response.
        args.append("--last-response-only")

    main = [
        "--emulate-initiator",
        "form" if flow == "form_get" else flow,
        "--request",
        request.method,
    ]
    if connection_variant is not None:
        main += ["--emulate-connection-variant", connection_variant]
    if request_variant is not None:
        main += ["--emulate-request-variant", request_variant]
    for name, value in headers:
        main += ["--header", name + ": " + value]
    if request.body:
        main += ["--data", literal_body(request.body, "literal UTF-8 fixture body")]
    origin = target.origin
    if flow == "ws":
        scheme = "wss" if destination.scheme == "https" else "ws"
        origin = scheme + "://" + destination.netloc
    main.append(origin + request.uri)

    for index, segment in enumerate(segments + [main]):
        if index:
            args.append("--next")
        args += segment
    return args


def warmup_request(target, headers, variant):
    """Open a connection variant with a bare navigation, as browsers bootstrap one."""
    args = [
        "--emulate-initiator",
        "navigate",
        "--request",
        "GET",
        "--emulate-connection-variant",
        variant,
        "--emulate-connection-bootstrap",
    ]
    # Keep only the operation's profile selector and current route.
    for name, value in headers:
        if name in ("user-agent", "alt-used"):
            args += ["--header", name + ": " + value]
    return args + [target.origin + "/"]


def literal_body(body, message):
    """Return a body `--data` sends verbatim: UTF-8, no NUL, no @file form."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(message) from None
    require("\0" not in text and not text.startswith("@"), message)
    return text


def request_segments(args):
    """Split a send command at `--next`; the first segment keeps client options."""
    segments = [[]]
    for value in args:
        if value == "--next":
            segments.append([])
        else:
            segments[-1].append(value)
    return segments


def replay_headers(target, request):
    """Supply only caller-owned context and current route/body bindings."""
    destination = urlsplit(target.origin)
    require(
        destination.scheme in ("http", "https")
        and destination.hostname
        and not destination.path
        and not destination.query
        and not destination.fragment
        and destination.username is None,
        "replay target must be an HTTP(S) origin",
    )
    headers = []
    # An omitted context is a wildcard to the profile selector. Preserve all
    # observed Fetch facts so bootstrap-only navigations cannot become normal
    # operations. In particular, never invent Sec-Fetch-User for automatic flows.
    names = {name for _key, name in FETCH_CONTEXT_FIELDS}
    context = {}
    alt_used = False
    for field in request.headers:
        # H1 keeps raw lines for casing/whitespace checks; H2/H3 keep pairs.
        if isinstance(field, str):
            name, value = field.split(":", 1)
            value = value.lstrip(" \t")
        else:
            name, value = field
        name = name.lower()
        if name == "alt-used":
            require(not alt_used, "ambiguous replay Alt-Used route")
            alt_used = True
        if name in names:
            require(name not in context, "ambiguous replay Fetch context")
            context[name] = value
    for _key, name in FETCH_CONTEXT_FIELDS:
        if name in context:
            headers.append((name, context[name]))

    # Authority is current routing input, never a retained browser value.
    if alt_used:
        headers.append(("alt-used", destination.netloc))

    for name in (
        "connection",
        "content-type",
        "content-length",
        "te",
        "origin",
        "referer",
        "sec-websocket-extensions",
    ):
        if name not in request.bindings:
            continue
        value = request.bindings[name]
        if name == "origin" and value != "null":
            value = target.origin
        headers.append((name, value))
    return tuple(headers)


def flow_counts(expected):
    """Require an explicit positive count for every shared browser operation."""
    counts = dict.fromkeys(FLOWS, expected) if type(expected) is int else dict(expected)
    require(set(counts) == FLOW_NAMES, "six-operation expected count coverage")
    require(
        all(type(count) is int and count > 0 for count in counts.values()),
        "positive replay count required for every flow",
    )
    return counts


def flow_protocols(blocks, *, operations=None):
    """Record actual per-operation protocols, without forcing WebSocket upgrades.

    A journey must still cover all six operations. Multiple observations of an
    operation may share a protocol, but silently mixing two protocols is invalid.
    """
    if operations is not None:
        operations.validate_heads(blocks)
        return operations.protocols
    protocols = {flow: set() for flow in FLOWS}
    for block in blocks:
        if not block.from_server and (
            flow := flow_name(block.headers, protocol=block.protocol)
        ):
            protocols[flow].add(block.protocol)
    require(
        all(len(values) == 1 for values in protocols.values()),
        "six-operation unambiguous protocol coverage",
    )
    return {flow: next(iter(values)) for flow, values in protocols.items()}


def compare_requests(reference, replay, *, expected_per_flow=1, operations=None):
    names = FLOWS if operations is None else operations.names
    require(
        set(reference) == set(names) == set(replay),
        "complete declared-operation comparison coverage",
    )
    counts = (
        flow_counts(expected_per_flow)
        if operations is None
        else dict.fromkeys(names, 1)
    )
    reports = []
    for flow in names:
        require(
            len(replay[flow]) == counts[flow],
            "expected replay request count per flow",
        )
        observed = replay[flow][0]
        matched = all(
            any(
                actual.wire_tuple() == candidate.wire_tuple()
                for candidate in reference[flow]
            )
            for actual in replay[flow]
        )
        reports.append(
            {
                "flow": flow,
                "match": matched,
                "requests_checked": len(replay[flow]),
                "body_match": all(
                    any(actual.body == candidate.body for candidate in reference[flow])
                    for actual in replay[flow]
                ),
                "differences": (
                    []
                    if matched
                    else list(
                        difflib.unified_diff(
                            tuple(map(str, reference[flow][0].headers)),
                            tuple(map(str, observed.headers)),
                            lineterm="",
                        )
                    )
                ),
            }
        )
    return reports
