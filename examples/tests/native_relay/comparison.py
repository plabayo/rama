"""Compare independently decrypted native relay legs without counted UA profiles.

Functional/body preservation and full fingerprint equality are separate results.
A caller must explicitly choose how to handle a reported fingerprint difference.
"""

from collections import defaultdict
from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import sys

# Reuse the same bounded tshark/TLS decoder as the browser tests.
sys.path.append(str(Path(__file__).parents[1] / "browser_profile"))
from flows import require
from tls_wire import client_hellos
from wire import one, parse_pdml, pdml_packets, values


@dataclass(frozen=True)
class Exchange:
    method: str
    path: str
    request_headers: tuple
    response_headers: tuple
    request_trailers: tuple
    response_trailers: tuple
    request_body: bytes
    response_body: bytes

    def report(self):
        result = asdict(self)
        for name in ("request_body", "response_body"):
            body = result.pop(name)
            result[name] = dict(
                length=len(body), sha256=hashlib.sha256(body).hexdigest()
            )
        return result


def raw_bytes(field):
    value = field.get("value")
    require(value is not None or field.get("size") == "0", "missing dissector bytes")
    data = bytes.fromhex(value or "")
    require(len(data) == int(field.get("size")), "dissector byte length differs")
    return data


def header_lines(fields):
    result = []
    for field in fields:
        raw = raw_bytes(field)
        require(raw.endswith(b"\r\n"), "HTTP/1 field has no line ending")
        for line in raw[:-2].split(b"\r\n"):
            name, separator, value = line.partition(b":")
            require(name and separator, "invalid HTTP/1 field")
            result.append(
                (name.decode("latin-1"), value.lstrip(b" \t").decode("latin-1"))
            )
    return tuple(result)


def http1_exchanges(data, server_port):
    requests, responses = {}, {}
    connections = set()
    for packet in pdml_packets(data):
        for proto in packet.findall("proto"):
            if proto.get("name") != "http":
                continue
            connection = int(one(packet, "tcp.stream"))
            connections.add(connection)
            source, destination = int(one(packet, "tcp.srcport")), int(
                one(packet, "tcp.dstport")
            )
            require(
                (source == server_port) != (destination == server_port),
                "ambiguous HTTP/1 endpoint",
            )
            from_server = source == server_port
            method = values(proto, "http.request.method")
            status = values(proto, "http.response.code")
            require(
                bool(method) != bool(status), "ambiguous reassembled HTTP/1 message"
            )
            require(
                bool(status) == from_server, "HTTP/1 request/response direction differs"
            )
            prefix = "http.response.line" if from_server else "http.request.line"
            headers = header_lines(
                [field for field in proto.iter("field") if field.get("name") == prefix]
            )
            trailers = header_lines(
                [
                    field
                    for field in proto.iter("field")
                    if field.get("name") == "http.chunked_trailer_part"
                ]
            )
            body = b"".join(
                raw_bytes(field)
                for field in proto.iter("field")
                if field.get("name") == "http.file_data"
            )
            if from_server:
                require(status == ["200"], "HTTP/1 response status differs")
                identity = (connection, int(one(proto, "http.request_in")))
                require(identity not in responses, "repeated HTTP/1 final response")
                responses[identity] = (headers, trailers, body)
            else:
                identity = (connection, int(one(packet, "frame.number")))
                require(
                    identity not in requests and len(method) == 1,
                    "repeated HTTP/1 request",
                )
                requests[identity] = (
                    method[0],
                    one(proto, "http.request.uri"),
                    headers,
                    trailers,
                    body,
                )
    require(len(connections) == 1, "fixture did not reuse one HTTP/1 connection")
    require(requests.keys() == responses.keys(), "HTTP/1 response association differs")
    return [
        Exchange(
            method,
            path,
            headers,
            responses[identity][0],
            trailers,
            responses[identity][1],
            body,
            responses[identity][2],
        )
        for identity, (method, path, headers, trailers, body) in requests.items()
    ]


def multiplexed_exchanges(data, protocol, server_port):
    streams = defaultdict(list)
    blocks = parse_pdml(data, protocol, server_port, include_data=True)
    require(
        len({block.connection for block in blocks}) == 1,
        "fixture did not reuse one multiplexed connection",
    )
    for block in blocks:
        streams[block.stream].append(block)
    exchanges = []
    for frames in streams.values():
        requests = [
            frame
            for frame in frames
            if not frame.from_server
            and any(name == ":method" for name, _ in frame.headers)
        ]
        responses = [
            frame
            for frame in frames
            if frame.from_server and any(name == ":status" for name, _ in frame.headers)
        ]
        require(len(requests) == len(responses) == 1, "ambiguous multiplexed exchange")
        request, response = requests[0], responses[0]
        require(
            dict(response.headers)[":status"] == "200",
            "multiplexed response status differs",
        )
        request_trailers = tuple(
            pair
            for frame in frames
            if not frame.from_server and frame is not request
            for pair in frame.headers
        )
        response_trailers = tuple(
            pair
            for frame in frames
            if frame.from_server and frame is not response
            for pair in frame.headers
        )
        fields = dict(request.headers)
        exchanges.append(
            Exchange(
                fields[":method"],
                fields[":path"],
                request.headers,
                response.headers,
                request_trailers,
                response_trailers,
                b"".join(frame.data for frame in frames if not frame.from_server),
                b"".join(frame.data for frame in frames if frame.from_server),
            )
        )
    return exchanges


def h2_settings(data, server_port):
    settings = {"client": [], "server": []}
    for packet in pdml_packets(data):
        for frame in packet.iter("field"):
            if frame.get("name") != "http2.stream" or values(frame, "http2.type") != [
                "4"
            ]:
                continue
            if one(frame, "http2.flags.ack.settings") == "True":
                continue
            require(
                one(frame, "http2.streamid") == "0",
                "SETTINGS has an application stream",
            )
            entries = []
            for setting in frame.iter("field"):
                if setting.get("name") != "http2.settings":
                    continue
                identifier = int(one(setting, "http2.settings.id"))
                literal = [field for field in setting if field.get("size") == "4"]
                require(len(literal) == 1, "ambiguous HTTP/2 setting value")
                entries.append(
                    (identifier, int.from_bytes(raw_bytes(literal[0]), "big"))
                )
            role = (
                "server" if int(one(packet, "tcp.srcport")) == server_port else "client"
            )
            settings[role].append(entries)
    require(
        all(len(frames) >= 1 for frames in settings.values()), "missing HTTP/2 SETTINGS"
    )
    return settings


def fresh_values(data, server_port, transport):
    result = {"randoms": set(), "shares": set()}
    for packet in pdml_packets(data):
        if values(packet, transport + ".dstport") != [str(server_port)]:
            continue
        for hello in packet.iter("field"):
            if hello.get("name") != "tls.handshake" or values(
                hello, "tls.handshake.type"
            ) != ["1"]:
                continue
            for field in hello.iter("field"):
                target = {
                    "tls.handshake.random": "randoms",
                    "tls.handshake.extensions_key_share_key_exchange": "shares",
                }.get(field.get("name"))
                if target is not None and field.get("value"):
                    result[target].add(field.get("value"))
    require(all(result.values()), "missing fresh cryptographic evidence")
    return result


def compare_legs(ingress, egress, protocol, ingress_port, egress_port, expected_body):
    require(protocol in ("h1", "h2"), "TCP comparison requires H1 or H2")
    transport, tls_transport = "tcp", "Tcp"
    tls, fresh, exchanges, settings = {}, {}, {}, {}
    for name, data, port in (
        ("ingress", ingress, ingress_port),
        ("egress", egress, egress_port),
    ):
        hellos = client_hellos(data, tls_transport)
        require(
            len({hello.connection for hello in hellos}) == 1,
            "fixture has more than one TLS connection",
        )
        require(
            all(hello.capture == hellos[0].capture for hello in hellos),
            "distinct ClientHellos on one leg",
        )
        tls[name] = hellos[0].capture
        fresh[name] = fresh_values(data, port, transport)
        parsed = (
            http1_exchanges(data, port)
            if protocol == "h1"
            else multiplexed_exchanges(data, protocol, port)
        )
        exchanges[name] = {exchange.method: exchange for exchange in parsed}
        require(
            len(parsed) == 2 and set(exchanges[name]) == {"GET", "POST"},
            "GET/POST exchange coverage differs",
        )
        for method, exchange in exchanges[name].items():
            body = expected_body if method == "POST" else b""
            require(exchange.path == "/" + method, "fixture request path differs")
            require(
                exchange.request_body == exchange.response_body == body,
                "fixture body differs",
            )
            trailer_name = "X-Interop-End" if protocol == "h1" else "x-interop-end"
            require(
                exchange.response_trailers == ((trailer_name, "complete"),),
                "response trailer differs",
            )
            request_trailer = (
                "X-Interop-Request-End" if protocol == "h1" else "x-interop-request-end"
            )
            require(
                exchange.request_trailers
                == (((request_trailer, "complete"),) if method == "POST" else ()),
                "request trailer differs",
            )
        if protocol == "h2":
            settings[name] = h2_settings(data, port)
    fresh_checks = {
        name: fresh["ingress"][name].isdisjoint(fresh["egress"][name])
        for name in ("randoms", "shares")
    }
    require(all(fresh_checks.values()), "relay reused ingress cryptographic material")

    for name in ("protocol_version", "ciphers", "compression"):
        require(
            tls["ingress"][name] == tls["egress"][name],
            "mirrored TLS " + name + " differs",
        )
    mirrored_extensions = {
        0: "server name presence",
        13: "signature algorithms",
        16: "ALPN offer",
        43: "supported versions",
        51: "key share groups and lengths",
    }
    ingress_extensions = {
        field["id"]: field["value"] for field in tls["ingress"]["extensions"]
    }
    egress_extensions = {
        field["id"]: field["value"] for field in tls["egress"]["extensions"]
    }
    for identifier, name in mirrored_extensions.items():
        require(
            ingress_extensions.get(identifier) == egress_extensions.get(identifier),
            "mirrored TLS " + name + " differs",
        )

    # Report all wire differences, including hop-generated framing. Never equate
    # successful request forwarding with complete fingerprint transparency.
    header_match = all(
        exchanges["ingress"][method].request_headers
        == exchanges["egress"][method].request_headers
        and exchanges["ingress"][method].response_headers
        == exchanges["egress"][method].response_headers
        for method in ("GET", "POST")
    )
    hop_fields = {
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "transfer-encoding",
    }

    def end_to_end(headers):
        return tuple(pair for pair in headers if pair[0].lower() not in hop_fields)

    retained_headers_match = all(
        end_to_end(exchanges["ingress"][method].request_headers)
        == end_to_end(exchanges["egress"][method].request_headers)
        and end_to_end(exchanges["ingress"][method].response_headers)
        == end_to_end(exchanges["egress"][method].response_headers)
        for method in ("GET", "POST")
    )
    require(retained_headers_match, "end-to-end field spelling/order/values differ")
    tls_match = tls["ingress"] == tls["egress"]
    settings_match = settings.get("ingress") == settings.get("egress")
    return dict(
        protocol=protocol,
        exchanges_checked=2,
        connection_reuse=True,
        bodies_and_trailers_match=True,
        end_to_end_headers_match=True,
        supported_tls_facts_match=True,
        exact_header_wire_match=header_match,
        tls_fingerprint_match=tls_match,
        h2_settings_match=settings_match if protocol == "h2" else None,
        fingerprint_match=tls_match and header_match and settings_match,
        fresh_values=fresh_checks,
        tls=tls,
        settings=settings,
        exchanges={
            side: [exchanges[side][method].report() for method in ("GET", "POST")]
            for side in exchanges
        },
    )
