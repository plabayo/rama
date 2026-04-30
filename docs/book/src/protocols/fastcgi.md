# FastCGI

> FastCGI is a binary protocol for interfacing interactive programs with a web server.
> It is a variation on the earlier CGI (Common Gateway Interface). FastCGI's main aim
> is to reduce the overhead associated with interfacing the web server and CGI programs,
> allowing a server to handle more web page requests at once.
>
> Source: FastCGI Specification 1.0 (embedded at `rama-fastcgi/specifications/fastcgi_spec.txt`)

Rama supports FastCGI through the `rama-fastcgi` crate, exposed in the `rama` mono crate
at `rama::gateway::fastcgi` when the `fastcgi` feature flag is enabled.

## What FastCGI Is

FastCGI is a binary framing protocol that sits between a web server (or reverse proxy)
and a backend application process. Unlike CGI, which spawns a new process for each
request, FastCGI keeps the application process running and reuses it across many requests
over persistent TCP or Unix socket connections.

A FastCGI conversation consists of typed records, each with an 8-byte header carrying a
version, record type, request ID, and content length. The connection multiplexes three
logical streams per request — params (CGI environment variables), stdin (request body),
and stdout/stderr (response).

## Core Concepts

**Record** — The basic transport unit. Every record has an 8-byte header followed by the
content bytes and optional padding for alignment. Content is at most 65535 bytes per
record; longer data is split across multiple records of the same type.

**Record type** — Identifies what a record carries. Application record types include
`FCGI_BEGIN_REQUEST`, `FCGI_ABORT_REQUEST`, `FCGI_END_REQUEST`, `FCGI_PARAMS`,
`FCGI_STDIN`, `FCGI_STDOUT`, `FCGI_STDERR`, and `FCGI_DATA`. Management record types
include `FCGI_GET_VALUES` and `FCGI_GET_VALUES_RESULT`.

**Request ID** — A non-zero u16 that ties together all the records of one request.
The server does not support multiplexing concurrent requests on one connection; a second
request arriving on the same connection while the first is in flight receives
`FCGI_CANT_MPX_CONN`.

**Params** — A stream of CGI environment variables encoded as name-value pairs with
variable-length length prefixes. Terminated by an empty `FCGI_PARAMS` record.

**Stdin** — The request body, terminated by an empty `FCGI_STDIN` record.

**Stdout** — The application's response, typically CGI-formatted: headers followed by a
blank line and the response body. Terminated by an empty `FCGI_STDOUT` record.

**Data** — An additional input stream used only in the Filter role, carrying the raw
file data to be processed. Terminated by an empty `FCGI_DATA` record.

## Roles

The web server declares the expected role in `FCGI_BEGIN_REQUEST`. Rama supports all
three roles defined by the specification.

### Responder

The most common role. The application receives the full CGI environment via params and
the HTTP request body via stdin, and returns a CGI-formatted response via stdout. This
is what PHP-FPM, Python WSGI/ASGI bridges, and most other FastCGI backends implement.

### Authorizer

The application receives the CGI environment but no stdin. Its sole job is to decide
whether the request should be allowed to proceed:

- A **200** response means the request is permitted. The web server forwards any
  `Variable-`-prefixed response headers to the downstream handler as additional
  environment variables.
- Any **non-200** response means the request is denied; the web server returns that
  response directly to the client.

The Authorizer role does not map to rama-net's `Authorizer<C>` trait, because the
FastCGI authorizer returns a full CGI response (with headers and an optional body),
not just an allow/deny decision with metadata. The inner service receives a
`FastCgiRequest` with `role == Authorizer` and an empty stdin, and returns a normal
`FastCgiResponse` whose stdout carries the CGI-formatted outcome.

### Filter

The application receives the CGI environment, the request body via stdin, and an
additional data stream via the `FCGI_DATA` records (the `data` field on
`FastCgiRequest`). The environment includes `FCGI_DATA_LAST_MOD` and `FCGI_DATA_LENGTH`
describing the data file. The application transforms the data and writes the result to
stdout.

The Filter role is used for server-side data transformation — for example, resizing
images, transcoding documents, or applying content policies — where the web server
provides both context (params + stdin) and raw input data (the data stream).

## The Two Sides in Rama

### Application server

`FastCgiServer` accepts TCP connections and drives the FastCGI protocol framing. For
each request it assembles params, stdin, and (for Filter) data, then dispatches to the
inner service. The inner service sees a `FastCgiRequest` with the `role` field set and
must return a `FastCgiResponse` whose `stdout` bytes carry the CGI-formatted output.

`FastCgiServer` implements rama's `Service` trait over IO streams, so it plugs directly
into `TcpListener::serve`.

### Reverse proxy client

`FastCgiClient` wraps a connector service that establishes the IO connection. Given a
`FastCgiClientRequest` (params + stdin), it runs the full FastCGI exchange and returns a
`FastCgiClientResponse` with the raw stdout bytes and the application exit status.

`send_on` is a lower-level function for one-shot use on an already-established stream,
useful when you manage connection lifecycle externally.

## HTTP Adaptive Layers

The `http` feature (automatically enabled when the `fastcgi` and `http` features are
both active) adds adapters that bridge HTTP and FastCGI:

**Client side** — `FastCgiHttpClient` wraps the same connector as `FastCgiClient` but
accepts HTTP requests and returns HTTP responses. It handles CGI environment variable
construction from HTTP metadata (method, URI, headers, protocol version, remote address)
and parses the CGI stdout back into an HTTP response including status code, headers, and
body. `FastCgiHttpClientConnector` is the connector-level adapter for use in larger
service stacks.

**Server side** — `FastCgiHttpService` wraps any HTTP service and makes it serve as a
FastCGI application. It reconstructs the HTTP request from CGI params, calls the inner
service, and serialises the HTTP response back to CGI stdout format. The Filter role's
`data` stream is not exposed through this adapter; services that need it implement
`Service<FastCgiRequest>` directly.

## Management Records

The server handles `FCGI_GET_VALUES` queries and responds with actual capability values:
`FCGI_MAX_CONNS=1`, `FCGI_MAX_REQS=1`, `FCGI_MPXS_CONNS=0`. Unknown management record
types receive `FCGI_UNKNOWN_TYPE` responses.

## Feature Flag

`fastcgi = ["dep:rama-fastcgi", "tcp"]`

When `http` is also active, the HTTP adaptive layers are enabled automatically.

Crate docs: <https://ramaproxy.org/docs/rama/gateway/fastcgi/index.html>

FastCGI specification: `rama-fastcgi/specifications/fastcgi_spec.txt` (embedded in the crate).

## Example

The `fastcgi_reverse_proxy` example in the `examples/` directory demonstrates both
sides of the HTTP adaptive layer in a single binary:

- A FastCGI application server wrapping a plain HTTP echo handler via
  `FastCgiHttpService`, listening for FastCGI connections from the proxy.
- An HTTP reverse proxy using `FastCgiHttpClient` to translate incoming HTTP requests
  into FastCGI requests and forward them to the backend.

```sh
cargo run --example fastcgi_reverse_proxy --features=http-full,fastcgi
```
