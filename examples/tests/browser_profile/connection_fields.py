"""Independent connection-prefix observations, correlated with retained TLS.

Tshark supplies reassembly and frame boundaries. Read raw integer spans rather
than guessing unknown SETTINGS values from their display labels. Keep the same
connection identity used by TLS and request observations; matching isolated
components from different joint variants must never prove a connection match.
"""

from collections import defaultdict

from capture_fields import connection_user_agents
from wire import one, pdml_packets, values

H2_HEADERS = 1
H2_PRIORITY = 2
H2_SETTINGS = 4
H2_WINDOW_UPDATE = 8


def field(node, name):
    found = [child for child in node.iter("field") if child.get("name") == name]
    if len(found) != 1:
        raise ValueError("ambiguous or missing " + name)
    return found[0]


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


def h2_prefixes(data, server_port):
    """Read complete client SETTINGS/WINDOW_UPDATE/PRIORITY before first HEADERS."""
    prefixes = defaultdict(list)
    prefaces = defaultdict(int)
    completed = set()
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
        for frame in frames:
            if connection in completed:
                continue
            if values(frame, "http2.magic"):
                prefaces[connection] += 1
                continue
            kind = integer(frame, "http2.type", 1)
            if (
                kind == H2_HEADERS
            ):  # HEADERS is the capture boundary, not an early frame.
                if prefaces[connection] != 1 or not prefixes[connection]:
                    raise ValueError("incomplete HTTP/2 prefix before HEADERS")
                completed.add(connection)
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
                if stream != 0 or length != 6 * len(entries) or (flags & 1 and entries):
                    raise ValueError("invalid SETTINGS framing")
                observed = {"Settings": {"ack": bool(flags & 1), "entries": entries}}
            elif kind == H2_WINDOW_UPDATE:  # WINDOW_UPDATE.
                if length != 4:
                    raise ValueError("invalid WINDOW_UPDATE length")
                observed = {
                    "WindowUpdate": {
                        "stream": stream,
                        "increment": integer(
                            frame,
                            "http2.window_update.window_size_increment",
                            4,
                            0x7FFFFFFF,
                        ),
                    }
                }
            elif (
                kind == 2
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
    return {
        connection: {"completeness": "Complete", "frames": prefixes[connection]}
        for connection in completed
    }


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


def compare_connection_fields(inspected, hellos, prefixes, requests):
    """Require TLS and HTTP/2 prefix from one retained connection joint."""
    if inspected.get("format_version") != 1:
        raise ValueError("unsupported inspection format")
    agents = connection_user_agents(requests)
    tls = defaultdict(list)
    for hello in hellos:
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
                if set(slots) != {"TcpTls", "Http2EarlyFrames"}:
                    raise ValueError("connection has unverified slots")
                slots["Http2EarlyFrames"] = fingerprint_prefix(
                    slots["Http2EarlyFrames"]
                )
                candidates.append((profile["key"]["user_agent"], slots))
    checked = set()
    for connection, agent in agents.items():
        if len(tls[connection]) != 1 or connection not in prefixes:
            raise ValueError("incomplete or ambiguous connection evidence")
        observed = {
            "TcpTls": tls[connection][0],
            "Http2EarlyFrames": fingerprint_prefix(prefixes[connection]),
        }
        matches = [
            index
            for index, (identity, slots) in enumerate(candidates)
            if identity == agent and slots == observed
        ]
        if not matches:
            raise ValueError("TLS and HTTP/2 prefix have no matching retained joint")
        checked.update(matches)
    if len(checked) != len(candidates):
        raise ValueError("retained connection joint has no wire observation")
    return {
        "connections_checked": len(agents),
        "retained_joints_checked": len(checked),
        "scope": "correlated retained TLS and HTTP/2 SETTINGS/WINDOW_UPDATE/PRIORITY prefix",
        "excluded": "peer-driven SETTINGS acknowledgements",
    }
