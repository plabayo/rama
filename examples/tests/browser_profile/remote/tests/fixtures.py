"""Shared source packets, native response tables and owned-plan inputs."""

import json
import xml.etree.ElementTree as ET

from flows import FLOWS
from remote.config import OwnerPlan
from wire import HeaderBlock

GENERATION = "ab" * 16

IMAGE = "registry.fly.io/rama-fp@sha256:" + "34" * 32

ORIGIN = "https://h3.fp.ramaproxy.org:32543"

CAPABILITY = dict(
    browserName="chrome", browserVersion="latest", os="Windows", osVersion="11"
)


def cells(protocol="h2"):
    return dict(
        format_version=1, cells=[dict(protocol=protocol, capability=CAPABILITY)]
    )


def plan():
    return OwnerPlan(
        "rama-fp-h3", "h3.fp.ramaproxy.org", IMAGE, 32543, GENERATION, cells()["cells"]
    )


def machine(identifier, config, name="existing"):
    return dict(id=identifier, name=name, config=config)


def html_info(info):
    labels = dict(
        version="Version",
        method="Method",
        scheme="Scheme",
        authority="Authority",
        path="Path",
        peer_addr="Socket Address",
    )
    return (
        "<table>"
        + "".join(
            f"<tr><td>{label}</td><td>{info[key]}</td></tr>"
            for key, label in labels.items()
        )
        + "</table>"
    )


def admission_fixture():
    """Six operations, native driver responses and independently framed H2 completion."""
    raw = ET.Element("pdml")
    frames = []
    page = dict(
        protocols={flow: "h2" for flow in FLOWS},
        page_results={},
        user_agent="ordinary-browser",
    )
    methods_paths = {
        "navigate": ("GET", "/report"),
        "fetch": ("POST", "/api/fetch/number/42"),
        "xhr": ("POST", "/api/xml/number/43"),
        "form": ("POST", "/form"),
        "form_get": ("GET", "/form?source=web&turtles=yes"),
    }
    for number, (flow, (method, path)) in enumerate(methods_paths.items(), 1):
        stream = number * 2 - 1
        fields = (
            (":method", method),
            (":path", path),
            (":authority", "h3.fp.ramaproxy.org:32543"),
            ("user-agent", "ordinary-browser"),
        )
        frames.append(HeaderBlock("h2", number, 0, stream, False, fields))
        info = dict(
            version="HTTP/2.0",
            method=method,
            scheme="https",
            authority="h3.fp.ramaproxy.org:32543",
            path=path.split("?")[0],
            peer_addr="198.51.100.7:52442",
        )
        if flow in ("fetch", "xhr"):
            info["uri"] = ORIGIN + path
            value = dict(
                fp=dict(request_info=info), number=42 if flow == "fetch" else 43
            )
            body = json.dumps(value).encode()
            page["page_results"][flow] = value
        else:
            document = html_info(info)
            body = document.encode()
            page[
                {
                    "navigate": "report_html",
                    "form": "form_html",
                    "form_get": "get_form_html",
                }[flow]
            ] = document
        frames.append(
            HeaderBlock(
                "h2", number + 100, 0, stream, True, ((":status", "200"),), body
            )
        )
        packet = ET.SubElement(raw, "packet")
        for name, value in (
            ("frame.number", number),
            ("tcp.stream", 0),
            ("tcp.dstport", 32543),
            ("tcp.srcport", 52442),
            ("ip.src", "198.51.100.7"),
        ):
            ET.SubElement(packet, "field", name=name, show=str(value))
        packet = ET.SubElement(raw, "packet")
        for name, value in (
            ("frame.number", number + 100),
            ("tcp.srcport", 32543),
            ("tcp.stream", 0),
        ):
            ET.SubElement(packet, "field", name=name, show=str(value))
        stream_node = ET.SubElement(packet, "field", name="http2.stream")
        ET.SubElement(
            stream_node, "field", name="http2.flags", value="01", size="1", pos="0"
        )
        ET.SubElement(stream_node, "field", name="http2.streamid", show=str(stream))
    probe = "driver-known-unique-probe"
    greeting = {"version": "HTTP/2.0", "message": "hello"}
    page["page_results"]["websocket"] = dict(probe=probe, greeting=greeting)
    frames.extend(
        (
            HeaderBlock(
                "h2",
                10,
                0,
                11,
                False,
                (
                    (":method", "CONNECT"),
                    (":path", "/api/ws"),
                    (":protocol", "websocket"),
                    ("user-agent", "ordinary-browser"),
                ),
                websocket_text=(probe,),
            ),
            HeaderBlock(
                "h2", 110, 0, 11, True, (), websocket_text=(json.dumps(greeting), probe)
            ),
        )
    )
    return ET.tostring(raw), frames, page
