"""Independent connection-prefix observations, correlated with retained TLS.

Tshark supplies reassembly and frame boundaries. Read raw integer spans rather
than guessing unknown SETTINGS values from their display labels. Keep the same
connection identity used by TLS and request observations; matching isolated
components from different joint variants must never prove a connection match.
"""

from capture_fields import connection_user_agents
from collections import Counter, defaultdict
from flows import FLOWS, operation_flow
from pdml import field, one, pdml_packets, values

H2_HEADERS = 1
H2_PRIORITY = 2
H2_SETTINGS = 4
H2_WINDOW_UPDATE = 8
H2_CONTINUATION = 9
H2_ACK = 1
H2_END_HEADERS = 4


def integer(node, name, width, mask=None):
    source = field(node, name)
    raw = bytes.fromhex(source.get("unmaskedvalue", source.get("value", "")))
    if len(raw) != width or int(source.get("size", "-1")) != width:
        raise ValueError("incomplete integer span: " + name)
    value = int.from_bytes(raw, "big")
    if mask is not None:
        value &= mask
    displayed = source.get("show", "")
    if int(displayed, 0 if displayed.startswith("0x") else 10) != value:
        raise ValueError("integer display/raw mismatch: " + name)
    return value


def h2_prefixes(data, server_port, *, connections=None):
    """Read the pre-HEADERS prefix and optional first-stream window policy.

    A recorded stream WINDOW_UPDATE can follow the first complete HEADERS;
    Rama replays that as a per-request window policy. Keep its independent wire
    witness separate: application dispatch can freeze before it arrives.
    Supplying request-bearing connections excludes abandoned preconnections.
    """
    prefixes = defaultdict(list)
    prefaces = defaultdict(int)
    completed = set()
    first_streams, header_open, stream_windows = {}, {}, {}
    for packet in pdml_packets(data):
        frames = [
            node for node in packet.iter("field") if node.get("name") == "http2.stream"
        ]
        if not frames:
            continue
        source, destination = int(one(packet, "tcp.srcport")), int(
            one(packet, "tcp.dstport")
        )
        if (source == server_port) == (destination == server_port):
            raise ValueError("ambiguous HTTP/2 fixture endpoint")
        if source == server_port:
            continue
        connection = int(one(packet, "tcp.stream"))
        if connections is not None and connection not in connections:
            continue
        for frame in frames:
            if connection in completed:
                continue
            if values(frame, "http2.magic"):
                prefaces[connection] += 1
                continue
            kind = integer(frame, "http2.type", 1)
            if connection in first_streams:
                # CONTINUATION frames complete one header block. A fragmented
                # first HEADERS must not hide the immediately following policy.
                stream = integer(frame, "http2.streamid", 4, 0x7FFFFFFF)
                if header_open[connection]:
                    if kind != H2_CONTINUATION or stream != first_streams[connection]:
                        raise ValueError("invalid first HEADERS continuation")
                    header_open[connection] = not bool(
                        integer(frame, "http2.flags", 1) & H2_END_HEADERS
                    )
                    continue
                if kind == H2_SETTINGS and integer(frame, "http2.flags", 1) & H2_ACK:
                    if stream != 0 or integer(frame, "http2.length", 3) != 0:
                        raise ValueError("invalid SETTINGS acknowledgement")
                    continue
                if kind == H2_WINDOW_UPDATE and stream == first_streams[connection]:
                    stream_windows[connection] = window_update(frame, stream)
                completed.add(connection)
                continue
            if kind == H2_HEADERS:
                if prefaces[connection] != 1 or not prefixes[connection]:
                    raise ValueError("incomplete HTTP/2 prefix before HEADERS")
                stream = integer(frame, "http2.streamid", 4, 0x7FFFFFFF)
                if not stream or not stream & 1:
                    raise ValueError("invalid client request stream")
                first_streams[connection] = stream
                header_open[connection] = not bool(
                    integer(frame, "http2.flags", 1) & H2_END_HEADERS
                )
                continue
            stream = integer(frame, "http2.streamid", 4, 0x7FFFFFFF)
            length = integer(frame, "http2.length", 3)
            if (
                kind == H2_SETTINGS
            ):  # SETTINGS, preserving raw IDs, duplicates and order.
                flags = integer(frame, "http2.flags", 1)
                entries = []
                for setting in frame.iter("field"):
                    if setting.get("name") != "http2.settings":
                        continue
                    children = list(setting)
                    if (
                        len(children) != 2
                        or children[0].get("name") != "http2.settings.id"
                    ):
                        raise ValueError("ambiguous SETTINGS entry")
                    entries.append(
                        {
                            "id": integer(setting, "http2.settings.id", 2),
                            "value": integer(setting, children[1].get("name"), 4),
                        }
                    )
                if (
                    stream != 0
                    or length != 6 * len(entries)
                    or (flags & H2_ACK and entries)
                ):
                    raise ValueError("invalid SETTINGS framing")
                observed = {
                    "Settings": {"ack": bool(flags & H2_ACK), "entries": entries}
                }
            elif kind == H2_WINDOW_UPDATE:
                observed = window_update(frame, stream)
            elif (
                kind == H2_PRIORITY
            ):  # Standalone PRIORITY; HEADERS priority is outside this slot.
                if length != 5:
                    raise ValueError("invalid PRIORITY length")
                dependency = integer(frame, "http2.stream_dependency", 4, 0x7FFFFFFF)
                dependency_field = field(frame, "http2.stream_dependency")
                raw = bytes.fromhex(
                    dependency_field.get(
                        "unmaskedvalue", dependency_field.get("value", "")
                    )
                )
                observed = {
                    "Priority": {
                        "stream": stream,
                        "dependency": dependency,
                        "weight": integer(frame, "http2.headers.weight", 1),
                        "exclusive": bool(raw[0] & 0x80),
                    }
                }
            else:
                raise ValueError("unmodeled early HTTP/2 frame")
            prefixes[connection].append(observed)
            if len(prefixes[connection]) > 16:
                raise ValueError("HTTP/2 prefix frame limit")
    if any(header_open.values()):
        raise ValueError("incomplete first HEADERS continuation")
    return {
        connection: {
            "completeness": "Complete",
            "frames": prefixes[connection],
            "first_request_window": stream_windows.get(connection),
        }
        for connection in first_streams
    }


def window_update(frame, stream):
    if integer(frame, "http2.length", 3) != 4:
        raise ValueError("invalid WINDOW_UPDATE length")
    increment = integer(
        frame, "http2.window_update.window_size_increment", 4, 0x7FFFFFFF
    )
    if increment == 0:
        raise ValueError("invalid zero WINDOW_UPDATE increment")
    return {"WindowUpdate": {"stream": stream, "increment": increment}}


def fingerprint_prefix(capture):
    # ACKs are generated by peer timing; Rama also excludes them from H2 replay.
    # They may be observed after HEADERS but before application dispatch.
    return {
        "completeness": capture["completeness"],
        "frames": [
            frame
            for frame in capture["frames"]
            if frame.get("Settings", {}).get("ack") is not True
        ],
    }


def compare_connection_fields(
    inspected,
    hellos,
    prefixes,
    requests,
    *,
    expected_per_variant_flow=None,
    expected_flows=FLOWS,
    operations=None,
):
    """Require TLS and HTTP/2 prefix from one retained connection joint.

    Replay supplies expected_per_variant_flow to require the full cross product.
    Original browser traffic need not draw every variant for every operation.
    """
    if inspected.get("format_version") != 1:
        raise ValueError("unsupported inspection format")
    requests = [request for request in requests if request.protocol == "h2"]
    agents = {
        connection: agent
        for (_transport, connection), agent in connection_user_agents(requests).items()
    }
    tls = defaultdict(list)
    for hello in hellos:
        if hello.capture["transport"] == "Tcp":
            tls[hello.connection].append(hello.capture)
    candidates = []
    for profile in inspected["profiles"]:
        if profile["key"]["user_agent"] not in agents.values():
            continue
        for scope in profile["scopes"]:
            for variant in scope["variants"]:
                capture = variant["capture"]
                if capture.get("level") != "Connection":
                    continue
                slots = {slot["kind"]: slot["capture"] for slot in capture["slots"]}
                if set(slots) == {"TcpTls"} or (
                    "QuicTls" in slots and "TcpTls" not in slots
                ):
                    continue  # H1 and QUIC joints have their own wire checks.
                if set(slots) != {"TcpTls", "Http2EarlyFrames"}:
                    raise ValueError("connection has unverified slots")
                slots["Http2EarlyFrames"] = fingerprint_prefix(
                    slots["Http2EarlyFrames"]
                )
                raw_id = variant["id"]
                if len(raw_id) != 32 or any(
                    type(value) is not int or not 0 <= value <= 255 for value in raw_id
                ):
                    raise ValueError("invalid retained connection variant ID")
                candidates.append(
                    (profile["key"]["user_agent"], bytes(raw_id).hex(), slots)
                )
    checked = set()
    connections = {}
    for connection, agent in agents.items():
        if len(tls[connection]) != 1 or connection not in prefixes:
            raise ValueError("incomplete or ambiguous connection evidence")
        observed = {
            "TcpTls": tls[connection][0],
            "Http2EarlyFrames": fingerprint_prefix(prefixes[connection]),
        }
        projections = [observed]
        if window := prefixes[connection].get("first_request_window"):
            with_window = {
                **observed,
                "Http2EarlyFrames": {
                    **observed["Http2EarlyFrames"],
                    "frames": [*observed["Http2EarlyFrames"]["frames"], window],
                },
            }
            projections.append(with_window)
        matches = [
            index
            for index, (identity, _variant, slots) in enumerate(candidates)
            if identity == agent and slots in projections
        ]
        if not matches:
            raise ValueError("TLS and HTTP/2 prefix have no matching retained joint")
        if len(matches) != 1:
            raise ValueError("ambiguous retained connection joint projection")
        checked.update(matches)
        connections[connection] = candidates[matches[0]][1]
    if len(checked) != len(candidates):
        raise ValueError("retained connection joint has no wire observation")
    matrix = Counter(
        (connections[request.connection], flow)
        for request in requests
        if not request.from_server
        and (flow := operation_flow(request, operations)) is not None
    )
    variants = {variant for _identity, variant, _slots in candidates}
    if expected_per_variant_flow is not None:
        check_variant_flow_matrix(
            matrix, variants, expected_per_variant_flow, flows=expected_flows
        )
    return {
        "variant_flow_counts": {
            variant: {flow: matrix[variant, flow] for flow in expected_flows}
            for variant in sorted(variants)
        },
        "expected_per_variant_flow": expected_per_variant_flow,
        "connection_joints": connections,
        "connections_checked": len(agents),
        "retained_joints_checked": len(checked),
        "scope": "correlated retained TLS and HTTP/2 SETTINGS/WINDOW_UPDATE/PRIORITY prefix",
        "excluded": "peer-driven SETTINGS acknowledgements",
        "window_policy": "recorded first-stream update must immediately follow its complete header block, allowing peer ACKs; exact dispatch cutoff is not inferred",
    }


def check_variant_flow_matrix(matrix, variants, expected, *, flows=FLOWS):
    """Prove the cross product, not separate flow and variant marginals."""
    if type(expected) is not int or expected < 1:
        raise ValueError("positive per-variant flow count required")
    flows = set(flows)
    if not flows or not flows <= set(FLOWS):
        raise ValueError("explicit known protocol flow subset required")
    if any(
        (variant not in variants or flow not in flows) and count
        for (variant, flow), count in matrix.items()
    ):
        raise ValueError("unexpected protocol flow outside replay plan")
    if any(matrix[variant, flow] != expected for variant in variants for flow in flows):
        raise ValueError("incomplete or duplicated connection variant/flow matrix")


def compare_h1_connections(
    inspected,
    hellos,
    requests,
    *,
    expected_per_variant_flow=None,
    expected_flows=FLOWS,
    operations=None,
):
    """Check H1 TLS joints and their own flow matrix beside multiplexed HTTP."""
    requests = [request for request in requests if request.protocol == "h1"]
    agents = {
        connection: agent
        for (_transport, connection), agent in connection_user_agents(requests).items()
    }
    observed = defaultdict(list)
    for hello in hellos:
        if hello.capture["transport"] == "Tcp":
            observed[hello.connection].append(hello.capture)
    candidates = []
    for profile in inspected["profiles"]:
        if profile["key"]["user_agent"] not in agents.values():
            continue
        for scope in profile["scopes"]:
            for variant in scope["variants"]:
                capture = variant["capture"]
                if capture.get("level") != "Connection":
                    continue
                slots = capture.get("slots", [])
                if {slot["kind"] for slot in slots} != {"TcpTls"}:
                    continue
                if len(slots) != 1:
                    raise ValueError("duplicate H1 TLS slot")
                raw_id = variant["id"]
                if len(raw_id) != 32 or any(
                    type(value) is not int or not 0 <= value <= 255 for value in raw_id
                ):
                    raise ValueError("invalid retained connection variant ID")
                candidates.append(
                    (
                        profile["key"]["user_agent"],
                        bytes(raw_id).hex(),
                        slots[0]["capture"],
                    )
                )
    checked, connections = set(), {}
    for connection, agent in agents.items():
        if len(observed[connection]) != 1:
            raise ValueError("incomplete or ambiguous H1 TLS evidence")
        matches = [
            index
            for index, (identity, _variant, capture) in enumerate(candidates)
            if identity == agent and capture == observed[connection][0]
        ]
        if len(matches) != 1:
            raise ValueError("H1 TLS has no unique retained connection joint")
        checked.update(matches)
        connections[connection] = candidates[matches[0]][1]
    if len(checked) != len(candidates):
        raise ValueError("retained H1 connection joint has no wire observation")
    matrix = Counter(
        (connections[request.connection], flow)
        for request in requests
        if not request.from_server
        and (flow := operation_flow(request, operations)) is not None
    )
    variants = {variant for _identity, variant, _capture in candidates}
    if expected_per_variant_flow is not None:
        check_variant_flow_matrix(
            matrix, variants, expected_per_variant_flow, flows=expected_flows
        )
    return {
        "connection_joints": connections,
        "connections_checked": len(agents),
        "retained_joints_checked": len(checked),
        "variant_flow_counts": {
            variant: {flow: matrix[variant, flow] for flow in expected_flows}
            for variant in sorted(variants)
        },
        "scope": "correlated retained H1 TCP TLS joint and actual Upgrade flow",
    }
