"""Match the six browser operations to captured HTTP flow contexts."""

import re

FLOWS = ("navigate", "fetch", "xhr", "ws", "form", "form_get")
FLOW_NAMES = set(FLOWS)


def flow_name(headers):
    fields = dict(headers)
    method, path = fields.get(":method"), fields.get(":path", "")
    if method == "GET" and path.split("?", 1)[0] == "/report":
        return "navigate"
    if method == "POST" and re.fullmatch(r"/api/fetch/number/\d+", path):
        return "fetch"
    if method == "POST" and re.fullmatch(r"/api/xml/number/\d+", path):
        return "xhr"
    if (
        method == "CONNECT"
        and path == "/api/ws"
        and fields.get(":protocol") == "websocket"
    ):
        return "ws"
    if method == "POST" and path == "/form":
        return "form"
    if method == "GET" and path == "/form?source=web&turtles=yes":
        return "form_get"
    return None


def scope_matches(scope, block, flow):
    context = (scope.get("flow") or {}).get("Http")
    if context is None:
        return False
    headers = dict(block.headers)
    if context["version"] != {"h2": "HTTP/2.0", "h3": "HTTP/3.0"}[block.protocol]:
        return False
    if context["method"] != headers[":method"] or context["initiator"] != (
        "form" if flow == "form_get" else flow
    ):
        return False
    fetch = context["fetch"] or {}
    return all(
        fetch.get(key) == headers.get(header)
        for key, header in (
            ("mode", "sec-fetch-mode"),
            ("site", "sec-fetch-site"),
            ("destination", "sec-fetch-dest"),
            ("user_activation", "sec-fetch-user"),
        )
    )


def require(condition, message):
    if not condition:
        raise ValueError(message)


def replay_args(rama, archive, output, port, flow, request):
    args = [
        str(rama),
        "send",
        f"--emulate={archive}",
        "--emulate-initiator",
        "form" if flow == "form_get" else flow,
        "--emulate-seed",
        "01" * 32,
        "--emulate-connection-key",
        "02" * 32,
        "--emulate-request-key",
        "03" * 32,
        "--http1.1",
        "--request",
        request.method,
    ]
    for name in (
        "connection",
        "content-type",
        "content-length",
        "origin",
        "sec-websocket-extensions",
    ):
        if name not in request.bindings:
            continue
        value = request.bindings[name]
        if name == "origin" and value != "null":
            value = f"http://127.0.0.1:{port}"
        args += ["--header", name + ": " + value]
    if request.body:
        body = request.body.decode("utf-8")
        require(
            "\0" not in body and not body.startswith("@"), "literal UTF-8 fixture body"
        )
        args += ["--data", body]
    if flow == "ws":
        protocols = [
            value.strip()
            for value in request.bindings.get("sec-websocket-protocol", "").split(",")
        ]
        require(protocols == ["a", "b"], "fixture WebSocket protocols")
        args += ["--subprotocol", ",".join(protocols)]
    else:
        args += ["--fail", "--output", str(output)]
    scheme = "ws" if flow == "ws" else "http"
    return args + [f"{scheme}://127.0.0.1:{port}" + request.uri]
