# Binary Bodies and Multipart Uploads

Two related kinds of HTTP bodies sit outside the comfortable text-and-JSON
mainstream: opaque binary blobs sent as `application/octet-stream`, and
compound payloads such as file uploads sent as `multipart/form-data`. Rama
supports both, on the client side and the server side.

## Octet-Stream

`application/octet-stream` is the catch-all media type for "raw bytes you
should not assume anything about". User agents typically treat it as a
download — offering a "Save As" prompt — and servers reach for it when
serving binary content of unknown structure or when accepting an arbitrary
upload.

It is what you want when:

- you need to upload or download a binary file as a single payload
- the bytes carry a format the server understands but the wire shouldn't
- you want a permissive default that doesn't reject when no `Content-Type`
  is set (per RFC 9110 §8.3, a missing content type may be treated as
  `application/octet-stream`)

Rama supports octet-stream bodies on both sides: as a request extractor and
client builder helper for sending raw bytes, and as a response builder that
can attach a filename, advertise an exact content size, and serve range
requests for partial downloads. See
[`http_octet_stream.rs`](https://github.com/plabayo/rama/blob/main/examples/http_octet_stream.rs)
for a runnable example, and the rustdoc under
[`rama::http::service::web`](https://ramaproxy.org/docs/rama/http/service/web/index.html)
for the full surface.

## Multipart

`multipart/form-data` is the format browsers send when an HTML form
includes a file input. A request body is divided into parts, each part
carrying its own headers and payload, separated by a boundary string
declared in the request's `Content-Type`.

Compared to a JSON or form-urlencoded body, multipart is the right choice
when:

- a single request carries a mix of text fields and one or more files
- one or more parts are large or binary and benefit from being streamed
  rather than buffered
- you're integrating with browsers, curl, httpie, or any tool that already
  speaks the convention

### Rama support

Rama treats multipart as a first-class HTTP feature. With the `multipart`
cargo feature enabled (it's part of `http-full`), you can:

- accept multipart uploads on the server, iterating fields one at a time
  and reading each as bytes, text, or a stream of chunks
- bound memory use by capping the body globally (the standard mechanism)
  and per field individually, so a single oversized field can't exhaust
  the request budget
- build multipart bodies on the client from text, raw bytes, files, or
  arbitrary streams, with predictable `Content-Length` whenever every
  part has a known size

Because multipart, like the rest of Rama's HTTP layer, is built from the
same request and response types used by client, server, and middleware,
it composes naturally with tracing, compression, retries, and any custom
layer you stack on top.

### Examples

- [`http_multipart.rs`](https://github.com/plabayo/rama/blob/main/examples/http_multipart.rs)
  — a server that accepts an HTML upload form and reports back what it
  received
- the [paired integration test](https://github.com/plabayo/rama/blob/main/tests/integration/examples/example_tests/http_multipart.rs)
  drives the same endpoint with the rama client builder, end-to-end
- the public `http-test.ramaproxy.org` service exposes a `/multipart`
  endpoint backed by the same code, useful as a quick sanity-check target
  for any HTTP client

The full API lives under
[`rama::http::service::web::extract::multipart`](https://ramaproxy.org/docs/rama/http/service/web/extract/multipart/index.html)
on the server side and
[`rama::http::service::client::multipart`](https://ramaproxy.org/docs/rama/http/service/client/multipart/index.html)
on the client side.

### Spec compliance

Rama's multipart support targets RFC 7578 (`multipart/form-data`) on top
of RFC 2046 framing, with the related Content-Disposition rules from
RFC 6266 and ext-value encoding from RFC 8187. The relevant RFCs are
vendored under
[`rama-http/specifications`](https://github.com/plabayo/rama/tree/main/rama-http/specifications).

The receiving side leans accept-friendly: it handles the various
non-ASCII filename forms surveyed in RFC 7578 §5.1.3, tolerates the
linear-whitespace transport padding RFC 2046 §5.1.1 allows around boundary
delimiters, and ignores preamble and epilogue bytes. The sending side
sticks to the strict subset RFC 7578 mandates for senders — no
`filename*` ext-value, no `Content-Transfer-Encoding`, and a fresh random
boundary per form within the byte budget RFC 2046 prescribes.

### CLI support

The `rama` CLI accepts multipart uploads via the curl-compatible `-F` /
`--form-data` flag on `rama send`. Multiple `-F` flags compose into
multiple parts, with the same micro-syntax curl users expect (`name=value`,
`name=@file`, `name=<file`, optional `;type=…` and `;filename=…`
modifiers). See `rama send --help` for the full surface.
