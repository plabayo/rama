"""Bound source POSTs and real-shaped packet evidence for preliminary operations."""

from dataclasses import replace
import json
from flows import ReplayTarget
from operations_tests.fixtures import JOINTS, frames, inspected, ledger, reports
from preliminary import source_preliminary
from preliminary_inventory import PreliminaryInventory
from request_wire import request_from_stream
from test_h3_sequence_wire import frame
from test_native_h3_response import document, packet


def post_source():
    rows = []
    for row in frames():
        if row.protocol == "h3" and row.stream in (0, 4):
            row = replace(
                row,
                stream=4 if row.stream == 0 else 0,
                packet=10 if row.stream == 0 else 5,
            )
        rows.append(row)
    value, sections = inspected(rows)
    source = ledger(rows).with_joints(reports()).with_requests(value, rows, sections)
    initial = next(
        operation for operation in source.operations if operation.name == "fetch"
    )
    head = next(
        row
        for row in rows
        if not row.from_server and row.stream == 0 and row.protocol == "h3"
    )
    value["profiles"][0]["scopes"][1]["variants"][0]["capture"]["slots"].append(
        dict(
            kind="Http3Bootstrap",
            capture=dict(
                request=list(bytes.fromhex(initial.request)),
                method="POST",
                fields=len(head.headers),
                bindings=dict(stream_id=0, complete=True, insertions=[]),
            ),
        )
    )
    return rows, source, value, sections


def numbered(raw, number):
    return raw.replace(
        "<packet>", f'<packet><field name="frame.number" show="{number}"/>', 1
    )


def client_packet(number, stream):
    return f"""<packet><field name="frame.number" show="{number}"/>
      <field name="udp.srcport" show="10000"/><field name="udp.dstport" show="443"/>
      <field name="ip.src" show="127.0.0.1"/>
      <field name="quic.connection.number" show="7"/></packet>"""


def inventory_fixture(directory):
    rows, source, value, sections = post_source()
    planned = source_preliminary(
        value, rows, sections, source, JOINTS["h3"], connection=7
    )
    target = ReplayTarget("h3", "https://capture.test:443")
    before = next(
        row
        for row in rows
        if not row.from_server and row.protocol == "h3" and row.stream == 0
    )
    before = replace(before, packet=10, headers=planned.expected_headers(target))
    original_main = next(row for row in rows if source.name(row) == "xhr")
    current_headers = tuple(
        (name, "capture.test:443" if name == ":authority" else value)
        for name, value in original_main.headers
    )
    main = replace(original_main, packet=20, headers=current_headers)
    body = json.dumps(
        dict(
            fp=dict(
                request_info=dict(
                    version="HTTP/3.0",
                    method="POST",
                    scheme="https",
                    authority="capture.test:443",
                    path=dict(main.headers)[":path"],
                    peer_addr="127.0.0.1:10000",
                ),
                http_info=dict(
                    headers=[
                        pair for pair in main.headers if not pair[0].startswith(":")
                    ],
                    h3=dict(request_stream_id=main.stream),
                ),
            )
        )
    ).encode()
    prefix_body = b"preliminary-response"
    frames = [
        before,
        replace(
            before,
            packet=11,
            from_server=True,
            headers=((":status", "200"), ("content-type", "application/json")),
            data=prefix_body,
        ),
        main,
        replace(
            main,
            packet=21,
            from_server=True,
            headers=((":status", "200"), ("content-type", "application/json")),
            data=body,
        ),
    ]
    prefix_raw = frame(1, b"head") + frame(0, prefix_body)
    main_raw = frame(1, b"head") + frame(0, body)
    raw = document(
        client_packet(10, 0),
        numbered(packet(prefix_raw, stream=0, fin=False), 11),
        numbered(packet(b"", stream=0, offset=len(prefix_raw)), 12),
        client_packet(20, main.stream),
        numbered(packet(main_raw, stream=main.stream), 21),
    )
    output = directory / "main.response"
    output.write_bytes(body)
    reference = request_from_stream(
        [
            row
            for row in rows
            if (row.protocol, row.connection, row.stream) == ("h3", 7, main.stream)
        ],
        flow="xhr",
    )
    runs = (
        dict(
            protocol="h3",
            flow="xhr",
            reference=reference,
            output=output,
            target=target,
            preliminary=(planned,),
        ),
    )
    section = sections[planned.source_packet, 7, 0]
    current = {(10, 7, 0): replace(section, packet=10)}
    inventory = PreliminaryInventory(runs, source.for_replay(), 443, "probe")
    return raw, frames, inventory, current, rows, source, body


def replace_main_body(raw, frames, previous, current):
    """Keep raw STREAM bytes, decoded DATA and caller output mutually consistent."""
    main = frames[2]
    old = numbered(
        packet(frame(1, b"head") + frame(0, previous), stream=main.stream), 21
    )
    new = numbered(
        packet(frame(1, b"head") + frame(0, current), stream=main.stream), 21
    )
    assert raw.count(old.encode()) == 1
    frames[3] = replace(frames[3], data=current)
    return raw.replace(old.encode(), new.encode())


def segment_fields(segment):
    """Read one `--next` request segment back into its request options."""
    options = {
        "--request": "method",
        "--emulate-initiator": "initiator",
        "--emulate-connection-variant": "connection",
        "--emulate-request-variant": "request",
        "--data": "data",
    }
    value = dict(uri=segment[-1], headers=[])
    for flag, field in zip(segment[:-1], segment[1:-1]):
        if flag in options:
            value[options[flag]] = field
    for item in segment[:-1]:
        if item.startswith("--data="):
            value["data"] = item.removeprefix("--data=")
        elif item.startswith("--header="):
            value["headers"].append(tuple(item.removeprefix("--header=").split(": ", 1)))
    value["bootstrap"] = "--emulate-connection-bootstrap" in segment
    return value
