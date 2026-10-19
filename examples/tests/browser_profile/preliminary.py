"""Plan explicit startup HTTP requests from independently bound source streams."""

from dataclasses import dataclass, field
import hashlib
from urllib.parse import urlsplit

from flows import flow_name, literal_body, replay_headers, request_segments, require
from qpack_bootstrap_wire import bootstrap_request
from qpack_fields_wire import matching_representations
from request_wire import request_from_stream

MAX_PRELIMINARY = 16
MAX_PRELIMINARY_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Preliminary:
    joint: str
    request_pin: str
    flow: str | None
    source_key: tuple
    source_packet: int
    request: object = field(repr=False)
    capture: dict = field(repr=False)

    def arguments(self, target):
        """Use current caller routing and actual observed body/context, never profile bytes."""
        require(target.protocol == "h3", "preliminary Bootstrap requires HTTP/3")
        args = ["--request", self.request.method]
        if self.flow is not None:
            args += [
                "--emulate-initiator",
                "form" if self.flow == "form_get" else self.flow,
            ]
        args += [
            "--emulate-connection-variant",
            self.joint,
            "--emulate-request-variant",
            self.request_pin,
        ]
        for name, value in replay_headers(target, self.request):
            args += ["--header", name + ": " + value]
        if self.request.body:
            args += [
                "--data",
                literal_body(
                    self.request.body,
                    "preliminary body is not representable as literal UTF-8 --data",
                ),
            ]
        return args + [target.origin + self.request.uri]

    def expected_headers(self, target):
        origin = urlsplit(target.origin)
        values = dict(replay_headers(target, self.request))
        return tuple(
            (
                name,
                (
                    origin.netloc
                    if name == ":authority"
                    else (
                        origin.scheme
                        if name == ":scheme"
                        else values.get(name.lower(), value)
                    )
                ),
            )
            for name, value in self.request.headers
        )

    def receipt(self):
        return dict(
            joint=self.joint,
            request=self.request_pin,
            flow=self.flow,
            source=list(self.source_key),
            source_packet=self.source_packet,
            method=self.request.method,
            uri=self.request.uri,
            body_bytes=len(self.request.body),
            body_sha256=hashlib.sha256(self.request.body).hexdigest(),
        )


def source_preliminary(inspected, frames, sections, ledger, joint, *, connection=None):
    """Resolve the selected source connection's exact initial Request reference."""
    profile, scope, variant = ledger.connection_recipe(inspected, joint)
    slots = {slot["kind"]: slot["capture"] for slot in variant["capture"]["slots"]}
    require(
        "Http3Bootstrap" in slots, "explicit preliminary lacks a verified Bootstrap"
    )
    if connection is None:
        # Choose an actual declared source connection; record its exact coordinates.
        choices = [
            operation
            for operation in ledger.operations
            if operation.protocol == "h3" and operation.joint == joint
        ]
        require(
            choices, "preliminary joint has no independently bound source operation"
        )
        connection = min(choices, key=lambda operation: operation.packet).connection
    require(
        any(
            operation.protocol == "h3"
            and operation.connection == connection
            and operation.joint == joint
            for operation in ledger.operations
        ),
        "preliminary connection lacks its independently verified native joint",
    )
    rows = [
        frame
        for frame in frames
        if frame.protocol == "h3" and frame.connection == connection
    ]
    head, capture = bootstrap_request(slots["Http3Bootstrap"], profile, scope, rows)
    metadata = sections.get((head.packet, head.connection, head.stream))
    require(
        metadata is not None
        and matching_representations(capture, head.headers, metadata.fields),
        "preliminary source lacks exact raw QPACK metadata",
    )
    context = dict(head.headers)
    flow = flow_name(head.headers, protocol="h3")
    if (
        flow is None
        and context.get(":method") == "GET"
        and context.get("sec-fetch-mode") == "navigate"
        and context.get("sec-fetch-dest") == "document"
    ):
        flow = "navigate"
    require(
        flow != "ws" and context.get(":protocol") != "websocket",
        "preliminary source cannot be a WebSocket",
    )
    stream = [frame for frame in rows if frame.stream == head.stream]
    request = request_from_stream(stream, flow=flow)
    return Preliminary(
        joint,
        bytes(slots["Http3Bootstrap"]["request"]).hex(),
        flow,
        ("h3", head.connection, head.stream),
        head.packet,
        request,
        capture,
    )


def plan_preliminary(inspected, frames, sections, ledger, operation, joints):
    """Materialize only the requested first exchanges; later QPACK history is not invented."""
    require(len(joints) <= MAX_PRELIMINARY, "preliminary operation count limit")
    return tuple(
        source_preliminary(
            inspected,
            frames,
            sections,
            ledger,
            joint,
            connection=operation.connection if joint == operation.joint else None,
        )
        for joint in joints
    )


def preliminary_arguments(requests, target):
    """Build bounded `--next` request segments before any command can perform I/O."""
    require(len(requests) <= MAX_PRELIMINARY, "preliminary operation count limit")
    segments = tuple(tuple(request.arguments(target)) for request in requests)
    require(
        sum(len(value.encode()) for segment in segments for value in segment)
        <= MAX_PRELIMINARY_BYTES,
        "preliminary input byte budget",
    )
    return segments


def rebind_preliminary(command, source, destination):
    """Rebind only the preliminary segments of an owned command for its hostname control."""
    segments = request_segments(command)
    require(len(segments) - 1 <= MAX_PRELIMINARY, "hostname preliminary count limit")
    require(
        sum(len(value.encode()) for segment in segments[:-1] for value in segment)
        <= MAX_PRELIMINARY_BYTES,
        "hostname preliminary byte limit",
    )
    for segment in segments[:-1]:
        uri = urlsplit(segment[-1])
        require(
            (uri.scheme, uri.netloc) == (source.scheme, source.netloc),
            "hostname preliminary belongs to a different origin",
        )
        segment[-1] = uri._replace(netloc=destination.netloc).geturl()
        headers = [
            index + 1 for index, value in enumerate(segment) if value == "--header"
        ]
        require(len(headers) <= 256, "hostname preliminary header schema")
        for index in headers:
            name, value = segment[index].split(": ", 1)
            if name.lower() == "alt-used":
                value = destination.netloc
            elif name.lower() == "origin" and value != "null":
                value = destination.scheme + "://" + destination.netloc
            segment[index] = name + ": " + value
    arguments = list(segments[0])
    for segment in segments[1:]:
        arguments += ["--next"] + segment
    return arguments
