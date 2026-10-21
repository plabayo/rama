"""Tshark PDML boundary and shared field accessors.

Parse and bound the document once per consumer. Protocol decoders retain their
own checks for complete, correctly attributed wire evidence.
"""

import xml.etree.ElementTree as ET

MAX_CAPTURE_BYTES = 40 * 1024 * 1024
MAX_PDML_BYTES = 64 * 1024 * 1024
MAX_PACKETS = 8192


def fields(node, name):
    return [item for item in node.iter("field") if item.get("name") == name]


def field(node, name):
    found = fields(node, name)
    if len(found) != 1:
        raise ValueError("ambiguous or missing " + name)
    return found[0]


def values(node, name):
    return [item.get("show", "") for item in fields(node, name)]


def one(node, name):
    found = values(node, name)
    if len(found) != 1:
        raise ValueError(f"expected one {name}, found {len(found)}")
    return found[0]


def pdml_packets(data, *, byte_limit=None, packet_limit=None):
    """Admit one bounded tshark document before protocol-specific decoding."""
    byte_limit = MAX_PDML_BYTES if byte_limit is None else byte_limit
    packet_limit = MAX_PACKETS if packet_limit is None else packet_limit
    if len(data) > byte_limit:
        raise ValueError("decoded byte limit exceeded")
    # Tshark emits UTF-8. NUL bytes must be rejected separately: an ASCII
    # UTF-16 document also decodes as UTF-8, but XML parsers detect its encoding
    # from those NULs and could expand declarations hidden from the byte scan.
    if b"\0" in data:
        raise ValueError("PDML must use UTF-8 without NUL bytes")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("PDML must use UTF-8") from error

    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ValueError("external/entity declarations are not valid tshark output")
    root = ET.fromstring(data)
    if root.tag != "pdml":
        raise ValueError("expected tshark PDML")
    packets = root.findall("packet")
    if len(packets) > packet_limit:
        raise ValueError("decoded packet limit exceeded")
    return packets


def identity(node, name):
    values = {
        item.get("show") for item in fields(node, name)
    }
    if len(values) != 1 or None in values:
        raise ValueError("ambiguous or missing " + name)
    return int(values.pop())
