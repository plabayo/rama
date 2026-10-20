"""Read one bounded caller-owned HTTP request from its exact decoded stream."""

from flows import require
from wire import Request

BINDINGS = (
    "connection",
    "content-type",
    "content-length",
    "te",
    "origin",
    "referer",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
)


def request_from_stream(frames, *, flow):
    heads = [frame for frame in frames if frame.headers and not frame.from_server]
    require(len(heads) == 1, "one original request per stream")
    head = heads[0]
    require(
        all(
            (frame.protocol, frame.connection, frame.stream)
            == (head.protocol, head.connection, head.stream)
            for frame in frames
        ),
        "mixed request stream coordinates",
    )
    fields = {name.lower(): value for name, value in head.headers}
    require(
        not any(
            name in fields
            for name in ("cookie", "authorization", "proxy-authorization")
        ),
        "local replay fixture must remain credential-free",
    )
    bindings = {}
    for name, value in head.headers:
        name = name.lower()
        if name in BINDINGS:
            require(name not in bindings, "ambiguous current request binding")
            if name == "te":
                require(
                    value.lower() == "trailers", "only TE trailers is valid in H2/H3"
                )
            bindings[name] = value
    body = (
        b""
        if flow == "ws"
        else b"".join(frame.data for frame in frames if not frame.from_server)
    )
    require(len(body) <= 65536, "fixture request body limit")
    return Request(
        fields[":method"],
        fields[":path"],
        tuple(
            (
                name,
                (
                    "<websocket-key>"
                    if head.protocol == "h1" and name.lower() == "sec-websocket-key"
                    else value
                ),
            )
            for name, value in head.headers
        ),
        body,
        bindings,
        head.protocol,
    )
