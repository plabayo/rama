"""Attribute a bounded Client Hints retry without choosing a request by position."""

from collections import defaultdict
import re

from flows import require
from page_info import request_headers, response_object


def regular(block):
    return tuple(
        (name, value) for name, value in block.headers if not name.startswith(":")
    )


def hint_names(headers, name):
    values = [value for field, value in headers if field.lower() == name]
    require(1 <= len(values) <= 4, "missing or ambiguous Client Hints advertisement")
    names = [item.strip().lower() for value in values for item in value.split(",")]
    require(
        0 < len(names) <= 64
        and len(names) == len(set(names))
        and all(re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]{1,64}", item) for item in names),
        "invalid Client Hints advertisement",
    )
    return set(names)


def response(frames, block, completed):
    key = block.protocol, block.connection, block.stream
    require(
        completed is not None and key in completed,
        "Client Hints response completion missing",
    )
    rows = [row for row in frames if (row.protocol, row.connection, row.stream) == key]
    heads = [row for row in rows if row.from_server and row.headers]
    require(len(heads) == 1, "Client Hints response head missing or ambiguous")
    body = response_object(rows).decode("utf-8")
    require(
        request_headers(body) == regular(block),
        "Client Hints native response headers differ",
    )
    return heads[0]


def client_hint_pair(first, second, frames, completed):
    """Require the real response advertisement and newly supplied critical fields."""
    require(first.packet < second.packet, "Client Hints retry order")
    for field in (":method", ":path", ":authority", ":scheme"):
        require(
            dict(first.headers).get(field) == dict(second.headers).get(field),
            "Client Hints retry request identity differs",
        )
    head = response(frames, first, completed)
    response(frames, second, completed)
    require(head.packet < second.packet, "Client Hints advertisement follows retry")
    accepted = hint_names(head.headers, "accept-ch")
    critical = hint_names(head.headers, "critical-ch")
    require(critical <= accepted, "critical Client Hints were not advertised")
    old, new = defaultdict(list), defaultdict(list)
    for target, block in ((old, first), (new, second)):
        for name, value in regular(block):
            target[name.lower()].append(value)
    changes = {name for name in old.keys() | new.keys() if old[name] != new[name]}
    require(
        changes and changes <= accepted, "retry changed nonadvertised request fields"
    )
    require(
        any(not old[name] and new[name] for name in critical),
        "retry has no newly supplied critical Client Hint",
    )
    require(
        tuple(
            (name.lower(), value)
            for name, value in regular(first)
            if name.lower() not in accepted
        )
        == tuple(
            (name.lower(), value)
            for name, value in regular(second)
            if name.lower() not in accepted
        ),
        "Client Hints retry changed ordinary field order or context",
    )


def final_report(candidates, frames, report_html, completed):
    require(len(candidates) == 2, "bounded Client Hints retry pair required")
    witness = request_headers(report_html)
    selected = [block for block in candidates if regular(block) == witness]
    require(len(selected) == 1, "final native headers do not identify one navigation")
    final = selected[0]
    first = next(block for block in candidates if block is not final)
    client_hint_pair(first, final, frames, completed)
    return first, final
