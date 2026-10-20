"""Small mixed-protocol packets and their coupled retained recipes."""

from collections import Counter
from dataclasses import asdict, replace

from flows import FLOWS, FETCH_CONTEXT_FIELDS
from operations import OperationLedger
from qpack_fields_wire import Representation, Section
from test_flow_bodies import fixture

ORIGIN = "https://capture.test:18443"
FINAL = ORIGIN + "/report?h3_probe=1"
JOINTS = {"h2": "12" * 32, "h3": "34" * 32}
CONTEXT = {"resumption": "Full", "early_data": False, "token_present": False}


def frames():
    rows = []
    for index, block in enumerate(fixture("h3")):
        ordinal = index // 2
        if ordinal == 3:
            block = fixture("h2")[index]
        headers = list(block.headers)
        if not block.from_server:
            headers.insert(2, (":authority", "capture.test:18443"))
            if ordinal == 3:
                headers.append(("sec-websocket-protocol", "a,b"))
            if ordinal == 0:
                headers = [
                    (name, "/report?h3_probe=1" if name == ":path" else value)
                    for name, value in headers
                ]
                headers += [
                    ("sec-fetch-mode", "navigate"),
                    ("sec-fetch-dest", "document"),
                ]
        rows.append(
            replace(
                block,
                packet=10 + ordinal,
                connection=3 if ordinal == 3 else 7,
                stream=11 if ordinal == 3 else ordinal * 4,
                headers=tuple(headers),
            )
        )
    discovery = fixture("h2")[:2]
    return [
        replace(
            block,
            packet=1,
            connection=3,
            stream=1,
            headers=block.headers
            + (
                ((":authority", "capture.test:18443"),) if not block.from_server else ()
            ),
        )
        for block in discovery
    ] + rows


def ledger(rows=None):
    rows = frames() if rows is None else rows
    protocols = dict.fromkeys(FLOWS, "h3")
    protocols["ws"] = "h2"
    return OperationLedger.from_driver(rows, protocols, ORIGIN, FINAL)


def reports():
    return {
        protocol: {"connection_joints": {3 if protocol == "h2" else 7: joint}}
        for protocol, joint in JOINTS.items()
    }


def request_capture(block):
    occurrences = Counter()
    regular, pseudo = [], []
    representations = tuple(Representation("LiteralName") for _ in block.headers)
    for (name, value), representation in zip(block.headers, representations):
        field = {"name": name, "representation": asdict(representation)}
        if name.startswith(":"):
            pseudo.append(field)
        else:
            field.update(
                occurrence=occurrences[name],
                value={"Profile": list(value.encode("latin-1"))},
            )
            occurrences[name] += 1
            regular.append(field)
    return {
        "level": "Request",
        "slots": [
            {"kind": "Headers", "capture": {"fields": regular}},
            {"kind": "PseudoHeaders", "capture": {"fields": pseudo}},
        ],
    }, representations


def inspected(rows=None, *, bootstrap=False):
    rows = frames() if rows is None else rows
    planned = ledger(rows)
    scopes, sections = [], {}
    for protocol, joint in JOINTS.items():
        scopes.append(
            {
                "context": {"connection": dict(CONTEXT)},
                "variants": [
                    {
                        "id": list(bytes.fromhex(joint)),
                        "capture": {
                            "level": "Connection",
                            "slots": [
                                {
                                    "kind": "QuicTls" if protocol == "h3" else "TcpTls",
                                    "capture": {"extensions": []},
                                }
                            ],
                        },
                    }
                ],
            }
        )
    scopes[0]["variants"][0]["capture"]["slots"].append(
        {"kind": "Http2EarlyFrames", "capture": {}}
    )
    for index, operation in enumerate(planned.operations):
        block = next(block for block in rows if planned.name(block) == operation.name)
        capture, metadata = request_capture(block)
        fields = dict(block.headers)
        scopes.append(
            {
                "context": {"connection": dict(CONTEXT)},
                "flow": {
                    "Http": {
                        "version": "HTTP/3.0" if block.protocol == "h3" else "HTTP/2.0",
                        "method": operation.method,
                        "initiator": (
                            "form" if operation.flow == "form_get" else operation.flow
                        ),
                        "fetch": {
                            key: fields[header]
                            for key, header in FETCH_CONTEXT_FIELDS
                            if header in fields
                        },
                    }
                },
                "variants": [{"id": [80 + index] * 32, "capture": capture}],
            }
        )
        if block.protocol == "h3":
            sections[block.packet, block.connection, block.stream] = Section(
                block.packet, block.connection, block.stream, 0, False, 0, metadata
            )
    if bootstrap:
        navigate = next(
            scope
            for scope in scopes
            if scope.get("flow", {}).get("Http", {}).get("version") == "HTTP/3.0"
        )
        variant = navigate["variants"][0]
        head = next(block for block in rows if planned.name(block) == "navigate")
        scopes[1]["variants"][0]["capture"]["slots"].append(
            {
                "kind": "Http3Bootstrap",
                "capture": {
                    "request": variant["id"],
                    "method": "GET",
                    "fields": len(head.headers),
                    "bindings": {
                        "stream_id": head.stream,
                        "complete": True,
                        "insertions": [],
                    },
                },
            }
        )
    return {
        "format_version": 1,
        "profiles": [{"key": {"user_agent": "fixture"}, "scopes": scopes}],
    }, sections


def bound(*, bootstrap=False):
    rows = frames()
    value, sections = inspected(rows, bootstrap=bootstrap)
    planned = ledger(rows).with_joints(reports()).with_requests(value, rows, sections)
    return rows, planned, value, sections
