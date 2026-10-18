"""Validate the fp page's request bodies and bidirectional WebSocket text probe.

Tshark supplies decryption, HTTP stream reassembly and WebSocket decompression.
We compare fixture semantics here, not a second implementation of those protocols.
Request bodies are replay inputs; user-agent profiles deliberately don't retain them.
"""

from collections import defaultdict
import json

from flows import FLOW_NAMES, flow_name

# Same application payload as rama-cli/assets/script.js; never stored in profiles.
WEBSOCKET_PROBE = "rama-fp echo: " + "🐢" * 32


def unique_object(pairs):
    """Reject duplicate members at every nesting level instead of taking the last."""
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON object member: " + name)
        result[name] = value
    return result


def invalid_constant(value):
    """Python accepts these tokens by default, but they are not JSON numbers."""
    raise ValueError("non-finite JSON constant: " + value)


def json_integer(token):
    """Preserve negative zero so unsigned fields cannot mistake it for zero.

    Other signed integers remain available to unrelated browser metadata.
    """
    return -0.0 if token == "-0" else int(token)


def json_object(data):
    """Decode an unambiguous object for the fp endpoint's JSON contract."""
    value = json.loads(
        data,
        object_pairs_hook=unique_object,
        parse_constant=invalid_constant,
        parse_int=json_integer,
    )
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def check_websocket_messages(protocol, incoming, outgoing):
    """Admit the same fp greeting and text echo on every HTTP transport."""
    if incoming != [WEBSOCKET_PROBE] or len(outgoing) != 2:
        raise ValueError("WebSocket round trip missing, repeated or misdirected")
    if outgoing[1] != WEBSOCKET_PROBE:
        raise ValueError("WebSocket echo differs from the client probe")

    greeting = json_object(outgoing[0])
    expected_version = {"h1": "HTTP/1.1", "h2": "HTTP/2.0", "h3": "HTTP/3.0"}[protocol]
    if greeting.get("initiator") != "ws" or greeting.get("version") != expected_version:
        raise ValueError("WebSocket greeting has wrong initiator or protocol")


def check_flow_bodies(blocks):
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
            payload = json_object(body)
            expected = int(headers[":path"].rsplit("/", 1)[1])
            # bool and float compare equal to integers in Python, but the
            # endpoint deserializes this field as an unsigned integer.
            number = payload.get("number")
            if type(number) is not int or not 0 <= number <= (1 << 64) - 1:
                raise ValueError(flow + " body number is not an unsigned integer")
            if number != expected:
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
            incoming = [
                text
                for frame in frames
                if not frame.from_server
                for text in frame.websocket_text
            ]
            check_websocket_messages(request.protocol, incoming, messages)
        elif body:
            raise ValueError(flow + " unexpectedly has a body")
        checked.add(flow)

    # A partial capture must never look like a successful complete journey.
    if checked != FLOW_NAMES:
        raise ValueError("incomplete body flow coverage")
    return {
        "flows": sorted(checked),
        "scope": "request body semantics, final 200 responses and bidirectional WebSocket text",
        "limits": "request tuple comparison is separate; one text round trip; not long-lived, binary or fragmentation coverage",
    }
