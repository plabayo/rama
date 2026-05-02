# Binary Bodies and Multipart Uploads

This page covers two related ways to send and receive non-textual HTTP bodies in
Rama: the `application/octet-stream` content type for opaque binary payloads,
and the `multipart/form-data` content type for compound payloads such as file
uploads.

## Octet-Stream

`application/octet-stream` is the default content type for arbitrary binary
data. User agents typically treat it as if `Content-Disposition: attachment`
had been set and offer a "Save As" prompt; servers use it for downloads of
unknown or unstructured binary content.

### Server side

Two complementary types live in `rama_http::service::web`:

- `extract::OctetStream` — request extractor. Validates the
  `Content-Type` header is `application/octet-stream`, collects the body
  into `Bytes`, and rejects with `415 Unsupported Media Type` on mismatch.
- `response::OctetStream` — response builder. Wraps a stream of `Bytes`,
  sets `Content-Type: application/octet-stream`, and supports an optional
  filename via `Content-Disposition: attachment` and an optional content
  size for `Content-Length` or `Content-Range`. It can also produce a
  `206 Partial Content` response with `try_into_range_response` and
  serve files directly with `try_from_path`.

`Option<OctetStream>` is supported on the request side for endpoints that
treat a missing body as valid input.

### Client side

`RequestBuilder::octet_stream(bytes)` sets the request body and the
`Content-Type` header. The header is left untouched if you set it earlier in
the chain.

### Example

[`http_octet_stream.rs`](https://github.com/plabayo/rama/blob/main/examples/http_octet_stream.rs)
demonstrates serving a binary response with and without an attachment
filename.

## Multipart

`multipart/form-data` carries compound bodies — typically a mix of text fields
and file uploads — separated by a boundary string declared in the
`Content-Type` header. It is the format browsers send when a form contains a
`<input type="file">` element.

Rama provides full client and server support, gated behind the `multipart`
feature on the umbrella `rama` crate. The feature is included in `http-full`,
so projects that already enable `http-full` get multipart support
automatically.

### Server side

The `extract::Multipart` extractor parses an incoming `multipart/form-data`
body. It enforces field exclusivity at compile time: each `Field` borrows
from `&mut Multipart`, so only one field is live at a time. Iterate fields
with `next_field`, then read each field's body via `bytes`, `text`,
`chunk`, or by treating the field as a `Stream` of byte chunks.

Per-field byte limits can be applied through `MultipartConfig`, attached as
a request extension by a layer or composed in handler code. When more than
one source contributes a limit for the same field, the lowest value wins.
The total payload size is independently bounded by the standard `BodyLimit`
mechanism.

Failure modes are reported via `MultipartError` (per-field parse and size
errors, mapped to `400` or `413`) and `MultipartRejection::InvalidBoundary`
(missing or malformed `Content-Type` boundary, `400`).

### Client side

`rama_http::service::client::multipart` exposes a `Form` builder. Add named
parts with `text`, `bytes`, `file`, or `part`. Each `Part` can carry an
optional filename, MIME type, content size, and custom headers.

When every part has a known size — text, bytes, files (via filesystem
metadata), or a stream that has been told its size — the form has a
predictable `Content-Length`. Mixing in any unsized streaming part downgrades
the form to chunked transfer encoding.

`RequestBuilder::multipart(form)` sets the body, the
`Content-Type: multipart/form-data; boundary=…` header, and the
`Content-Length` header when available.

### Example

[`http_multipart.rs`](https://github.com/plabayo/rama/blob/main/examples/http_multipart.rs)
demonstrates a server that accepts an HTML upload form and prints the parts
it received. Its [integration test](https://github.com/plabayo/rama/blob/main/tests/integration/examples/example_tests/http_multipart.rs)
uses the rama client `Form` to drive the same endpoint end-to-end.
