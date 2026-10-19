"""Plan explicit startup HTTP requests from independently bound source streams."""

import base64
from dataclasses import dataclass, field
import hashlib
import json
import os
from urllib.parse import urlsplit
from pathlib import Path

from flow_bodies import json_object
from flows import flow_name, replay_headers, require
from qpack_bootstrap_wire import bootstrap_request
from qpack_fields_wire import matching_representations
from request_wire import request_from_stream

MAX_PRELIMINARY = 16


@dataclass(frozen=True)
class Preliminary:
    joint: str
    request_pin: str
    flow: str
    source_key: tuple
    source_packet: int
    request: object = field(repr=False)
    capture: dict = field(repr=False)

    def input(self, target):
        """Use current caller routing and actual observed body/context, never profile bytes."""
        require(target.protocol == "h3", "preliminary Bootstrap requires HTTP/3")
        value = dict(
            method=self.request.method,
            uri=target.origin + self.request.uri,
            headers=replay_headers(target, self.request),
            emulate_initiator="form" if self.flow == "form_get" else self.flow,
            emulate_connection_variant=self.joint,
            emulate_request_variant=self.request_pin,
        )
        if self.request.body:
            value["body_base64"] = base64.b64encode(self.request.body).decode()
        return value

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
    flow = flow_name(head.headers, protocol="h3")
    if flow is None and dict(head.headers).get(":method") == "GET":
        context = dict(head.headers)
        require(
            context.get("sec-fetch-mode") == "navigate"
            and context.get("sec-fetch-dest") == "document",
            "preliminary source has no explicit HTTP initiator",
        )
        flow = "navigate"
    require(
        flow is not None and flow != "ws", "preliminary source cannot be a WebSocket"
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


def write_preliminary(directory, requests, target):
    """Write bounded private caller plans before any command can perform I/O."""
    require(len(requests) <= MAX_PRELIMINARY, "preliminary operation count limit")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    files = []
    total = 0
    for index, request in enumerate(requests):
        data = json.dumps(request.input(target), ensure_ascii=True).encode()
        total += len(data)
        require(total <= 1024 * 1024, "preliminary input byte budget")
        path = directory / f"{index}.json"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(data)
        files.append(path)
    return tuple(files)


def rebind_preliminary(command, directory, source, destination):
    """Rebind only this test owner's explicit inputs for its hostname control."""
    arguments = list(command)
    indices = [
        index + 1 for index, value in enumerate(arguments) if value == "--pre-request"
    ]
    require(len(indices) <= MAX_PRELIMINARY, "hostname preliminary count limit")
    if not indices:
        return arguments
    directory.mkdir(mode=0o700, exist_ok=False)
    total = 0
    for ordinal, index in enumerate(indices):
        path = Path(arguments[index])
        require(
            path.resolve().is_relative_to(directory.parent.parent.resolve()),
            "hostname control can only rebind owned preliminary files",
        )
        require(path.stat().st_size <= 1024 * 1024, "hostname preliminary byte limit")
        raw = path.read_bytes()
        total += len(raw)
        require(total <= 1024 * 1024, "hostname preliminary byte limit")
        value = json_object(raw)
        uri = urlsplit(value["uri"])
        require(
            (uri.scheme, uri.netloc) == (source.scheme, source.netloc),
            "hostname preliminary belongs to a different origin",
        )
        value["uri"] = uri._replace(netloc=destination.netloc).geturl()
        headers = value["headers"]
        require(
            isinstance(headers, list)
            and len(headers) <= 256
            and all(
                isinstance(row, list)
                and len(row) == 2
                and all(isinstance(field, str) for field in row)
                for row in headers
            ),
            "hostname preliminary header schema",
        )
        value["headers"] = [
            (
                name,
                (
                    destination.netloc
                    if name.lower() == "alt-used"
                    else (
                        destination.scheme + "://" + destination.netloc
                        if name.lower() == "origin" and field != "null"
                        else field
                    )
                ),
            )
            for name, field in headers
        ]
        output = directory / f"{ordinal}.json"
        fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as file:
            json.dump(value, file, ensure_ascii=True)
        arguments[index] = str(output)
    return arguments
