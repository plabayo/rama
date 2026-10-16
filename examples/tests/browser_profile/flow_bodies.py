"""Validate the fp page's request bodies and decoded WebSocket greeting.

Tshark supplies decryption, HTTP stream reassembly and WebSocket decompression.
We compare fixture semantics here, not a second implementation of those protocols.
Request bodies are replay inputs; user-agent profiles deliberately don't retain them.
"""

from collections import defaultdict
import json

from flows import FLOW_NAMES, flow_name


def check_original_bodies(blocks):
    streams = defaultdict(list)
    for block in blocks:
        streams[(block.connection, block.stream)].append(block)

    # Validate each request and its response within the same transport stream.
    checked = set()
    for frames in streams.values():
        requests = [
            frame for frame in frames if not frame.from_server and frame.headers
        ]
        relevant = [
            (frame, flow_name(frame.headers))
            for frame in requests
            if flow_name(frame.headers) is not None
        ]
        if not relevant:
            continue
        if len(relevant) != 1:
            raise ValueError("ambiguous request headers on a stream")
        request, flow = relevant[0]
        headers = dict(request.headers)
        body = b"".join(frame.data for frame in frames if not frame.from_server)
        responses = [
            dict(frame.headers)
            for frame in frames
            if frame.from_server and frame.headers
        ]
        if len(responses) != 1 or responses[0].get(":status") != "200":
            raise ValueError(flow + " response is not one successful final response")

        # Each browser operation has a distinct payload contract.
        if flow in ("fetch", "xhr"):
            payload = json.loads(body)
            expected = int(headers[":path"].rsplit("/", 1)[1])
            if payload.get("number") != expected:
                raise ValueError(flow + " body number differs from request path")
            if flow == "fetch" and payload.get("jsWebApis", {}).get(
                "navigator", {}
            ).get("userAgent") != headers.get("user-agent"):
                raise ValueError("fetch body user agent differs from request headers")
            if flow == "xhr" and set(payload) != {"number"}:
                raise ValueError("unexpected XHR body shape")
        elif flow == "form":
            if body != b"source=web&rating=3":
                raise ValueError("POST form body differs")
        elif flow == "ws":
            messages = [
                text
                for frame in frames
                if frame.from_server
                for text in frame.websocket_text
            ]
            if len(messages) != 1:
                raise ValueError("WebSocket greeting missing or repeated")
            greeting = json.loads(messages[0])
            expected_version = {"h2": "HTTP/2.0", "h3": "HTTP/3.0"}[request.protocol]
            if (
                greeting.get("initiator") != "ws"
                or greeting.get("version") != expected_version
            ):
                raise ValueError("WebSocket greeting has wrong initiator or protocol")
        elif body:
            raise ValueError(flow + " unexpectedly has a body")
        checked.add(flow)

    # A partial capture must never look like a successful complete journey.
    if checked != FLOW_NAMES:
        raise ValueError("incomplete body flow coverage")
    return {
        "flows": sorted(checked),
        "scope": "original request body semantics, final 200 responses and WebSocket greeting",
        "limits": "not replay fidelity or long-lived bidirectional WebSocket coverage",
    }
