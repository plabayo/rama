"""Attribute measured CLI responses and recount every explicit startup request."""

from dataclasses import dataclass
import hashlib
from urllib.parse import urlsplit

from capture_fields import matching_fields
from flow_bodies import json_object
from flows import request_authority, require
from native_h3_response import native_view, response_evidence
from page_info import request_headers, request_info, response_object
from qpack_fields_wire import matching_representations, sections_from_wire
from admission import complete_responses, packet_peers, peer_socket
from request_wire import request_from_stream

MAX_OUTPUT_BYTES = 1024 * 1024


def key(head):
    return head.protocol, head.connection, head.stream


def native_request(body, flow, protocol):
    if flow in ("fetch", "xhr"):
        value = json_object(body)["fp"]
        info, headers = value["request_info"], value["http_info"]["headers"]
        require(
            isinstance(info, dict)
            and isinstance(headers, list)
            and 0 < len(headers) <= 256
            and all(
                isinstance(row, list)
                and len(row) == 2
                and all(isinstance(field, str) for field in row)
                for row in headers
            ),
            "invalid main native request/header schema",
        )
        return info, tuple(tuple(row) for row in headers), value["http_info"].get("h3")
    text = body.decode("utf-8")
    return (
        request_info(text),
        request_headers(text),
        native_view(body, "text/html; charset=utf-8") if protocol == "h3" else None,
    )


def main_head(run, frames, peers, completed, websocket_probe):
    """Require the output's own native header table, peer and request stream."""
    heads = [frame for frame in frames if frame.headers and not frame.from_server]
    if run["flow"] == "ws":
        matches = [
            head
            for head in heads
            if head.protocol == run["protocol"]
            and dict(head.headers).get(":path") == run["reference"].uri
            and [
                text
                for frame in frames
                if key(frame) == key(head) and not frame.from_server
                for text in frame.websocket_text
            ]
            == [websocket_probe]
        ]
        require(len(matches) == 1, "main WebSocket has no unique caller-known probe")
        return matches[0]
    path = run["output"]
    require(path.stat().st_size <= MAX_OUTPUT_BYTES, "main output byte limit")
    output = path.read_bytes()
    destination = urlsplit(run["target"].origin)
    matches = []
    for head in heads:
        fields = dict(head.headers)
        if (
            head.protocol != run["protocol"]
            or key(head) not in completed
            or fields.get(":method") != run["reference"].method
            or fields.get(":path") != run["reference"].uri
            or request_authority(head) != destination.netloc
        ):
            continue
        group = [frame for frame in frames if key(frame) == key(head)]
        encoded = b"".join(frame.data for frame in group if frame.from_server)
        if encoded != output:
            continue
        # The CLI writes encoded bytes unless explicitly asked to decompress.
        # Bind those exact bytes first; only this response's headers choose decoding.
        body = response_object(group)
        try:
            info, echoed, h3 = native_request(body, run["flow"], run["protocol"])
        except (KeyError, TypeError) as error:
            raise ValueError("main response lacks its native request facts") from error
        if (
            info.get("version")
            != {"h1": "HTTP/1.1", "h2": "HTTP/2.0", "h3": "HTTP/3.0"}[run["protocol"]]
            or info.get("method") != run["reference"].method
            or info.get("path") != urlsplit(run["reference"].uri).path
            or info.get("scheme") != destination.scheme
            or info.get("authority") != destination.netloc
            or peers.get((head.protocol, head.packet))
            != peer_socket(info.get("peer_addr"))
            or tuple(pair for pair in head.headers if not pair[0].startswith(":"))
            != echoed
        ):
            continue
        if head.protocol == "h3" and (
            not isinstance(h3, dict)
            or type(h3.get("request_stream_id")) is not int
            or h3["request_stream_id"] != head.stream
        ):
            continue
        matches.append(head)
    require(
        len(matches) == 1,
        "main response has no unique echoed-header/native-stream association",
    )
    return matches[0]


@dataclass(frozen=True)
class PreliminaryInventory:
    """An explicit sequential command plan; source request facts stay private."""

    runs: tuple
    operations: object
    port: int
    websocket_probe: str

    def bind(self, data, frames):
        peers = packet_peers(data, self.port)
        completed = complete_responses(data, self.port)
        endings = response_evidence(data, self.port)
        sections = sections_from_wire(data, self.port)
        heads = sorted(
            (frame for frame in frames if frame.headers and not frame.from_server),
            key=lambda frame: frame.packet,
        )
        main = [
            main_head(run, frames, peers, completed, self.websocket_probe)
            for run in self.runs
        ]
        require(
            len({key(head) for head in main}) == len(main),
            "main commands share a replay stream",
        )
        require(
            all(first.packet < second.packet for first, second in zip(main, main[1:])),
            "main request order differs from sequential command plan",
        )
        observed, previous, used = [], -1, set()
        for run, actual in zip(self.runs, main):
            before = [head for head in heads if previous < head.packet < actual.packet]
            expected = run["preliminary"]
            require(
                len(before) == len(expected),
                "missing or extra explicit preliminary operation",
            )
            for head, planned in zip(before, expected):
                require(
                    head.protocol == "h3" and key(head) in completed,
                    "preliminary HTTP response is incomplete",
                )
                ending = endings.get((head.connection, head.stream))
                require(
                    ending is not None and ending.complete_packet < actual.packet,
                    "preliminary response did not finish before the main request",
                )
                rows = [frame for frame in frames if key(frame) == key(head)]
                response = response_object(rows)
                request = request_from_stream(rows, flow=planned.flow)
                require(
                    request.method == planned.request.method
                    and request.uri == planned.request.uri
                    and request.body == planned.request.body
                    and request.headers == planned.expected_headers(run["target"]),
                    "preliminary wire tuple differs from explicit caller input",
                )
                metadata = sections.get((head.packet, head.connection, head.stream))
                require(
                    matching_fields(planned.capture, head.headers) is not None
                    and metadata is not None
                    and matching_representations(
                        planned.capture, head.headers, metadata.fields, fresh_table=True
                    ),
                    "preliminary Request pin or raw QPACK policy differs",
                )
                observed.append(
                    dict(
                        key=key(head),
                        packet=head.packet,
                        joint=planned.joint,
                        request=planned.request_pin,
                        complete_packet=ending.complete_packet,
                        response_bytes=len(response),
                        response_sha256=hashlib.sha256(response).hexdigest(),
                        **{
                            name: value
                            for name, value in planned.receipt().items()
                            if name not in ("joint", "request")
                        }
                    )
                )
                used.add(key(head))
            used.add(key(actual))
            previous = actual.packet
        require(
            {key(head) for head in heads} == used,
            "unattributed replay request outside explicit command inventory",
        )
        ledger = self.operations.with_preliminary(observed)
        return ledger, dict(
            requests=len(observed),
            main_requests=len(main),
            main_observations=[
                dict(
                    operation=run.get("name", run["flow"]),
                    key=list(key(head)),
                    packet=head.packet,
                    attribution=(
                        "caller-known WebSocket probe"
                        if run["flow"] == "ws"
                        else "exact output plus echoed headers/native peer and request stream"
                    ),
                )
                for run, head in zip(self.runs, main)
            ],
            observations=observed,
            scope="exact caller-owned preliminary requests; no measured-flow substitution",
        )
