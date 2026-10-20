"""Expected HTTP semantics and framing for the independent native relay journey.

These expectations are checked on both decrypted legs, independently of what the
Go client accepts. HTTP/1 chunking and HTTP/2/3 stream termination stay distinct.
"""

from dataclasses import dataclass

from flows import require

REPRESENTATION = b"independent response"


@dataclass(frozen=True)
class ExpectedExchange:
    method: str
    request_body: bytes = b""
    response_body: bytes = b""
    status: int = 200
    request_trailers: bool = False
    response_trailers: bool = False
    fixed_response: bool = False
    head: bool = False


def expected_exchanges(payload):
    return {
        "/GET": ExpectedExchange("GET", response_trailers=True),
        "/POST": ExpectedExchange(
            "POST", payload, payload, request_trailers=True, response_trailers=True
        ),
        "/fixed": ExpectedExchange("POST", payload, payload, fixed_response=True),
        "/empty": ExpectedExchange("POST", fixed_response=True),
        "/empty-stream": ExpectedExchange(
            "POST", request_trailers=True, response_trailers=True
        ),
        "/head": ExpectedExchange("HEAD", fixed_response=True, head=True),
        "/no-content": ExpectedExchange("GET", status=204),
        "/not-modified": ExpectedExchange("GET", status=304),
        "/stream": ExpectedExchange(
            "GET", response_body=REPRESENTATION, response_trailers=True
        ),
    }


def header_values(headers, name):
    return [value for field, value in headers if field.lower() == name]


def verify_framing(headers, protocol, *, streaming=False, length=None):
    lengths = header_values(headers, "content-length")
    transfers = header_values(headers, "transfer-encoding")
    require(
        lengths == ([] if length is None else [str(length)]),
        "Content-Length contract differs",
    )
    require(
        transfers == (["chunked"] if streaming and protocol == "h1" else []),
        "transfer framing contract differs",
    )


def verify_exchange(exchange, expected, protocol):
    require(exchange.method == expected.method, "fixture request method differs")
    require(exchange.status == expected.status, "fixture response status differs")
    require(
        exchange.request_body == expected.request_body
        and exchange.response_body == expected.response_body,
        "fixture body differs",
    )
    request_trailers = (
        (("x-interop-request-end", "complete"),) if expected.request_trailers else ()
    )
    response_trailers = (
        (("x-interop-end", "complete"),) if expected.response_trailers else ()
    )
    require(
        tuple((name.lower(), value) for name, value in exchange.request_trailers)
        == request_trailers,
        "request trailer differs",
    )
    require(
        tuple((name.lower(), value) for name, value in exchange.response_trailers)
        == response_trailers,
        "response trailer differs",
    )

    # Prove the reference really exercised exotic spelling, rather than letting
    # two endpoints agree after both canonicalized it before the capture.
    for headers, name in (
        (exchange.request_headers, "x-eXoTiC-ReQuEsT"),
        (exchange.response_headers, "x-eXoTiC-ReSpOnSe"),
    ):
        expected_name = name if protocol == "h1" else name.lower()
        actual = tuple(pair for pair in headers if pair[0].lower() == name.lower())
        require(
            actual == ((expected_name, "first"), (expected_name, "second")),
            "exotic field spelling/multiplicity differs",
        )

    # Empty POST and an empty stream deliberately exercise different framing.
    request_length = (
        len(expected.request_body)
        if expected.method == "POST" and not expected.request_trailers
        else None
    )
    verify_framing(
        exchange.request_headers,
        protocol,
        streaming=expected.request_trailers,
        length=request_length,
    )
    response_length = None
    if expected.fixed_response:
        response_length = (
            len(REPRESENTATION) if expected.head else len(expected.response_body)
        )
    verify_framing(
        exchange.response_headers,
        protocol,
        streaming=expected.response_trailers,
        length=response_length,
    )
