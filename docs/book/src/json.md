# Streaming JSON

Proxies and gateways often need to look at, or change, a few values inside a JSON
body: drop a secret field, rewrite a model name, read an account id for routing.
Parsing the whole document into a tree for that costs memory and latency, and it
gives an untrusted peer control over how much you buffer.

Rama's JSON support works on the byte stream instead. It reads JSON in chunks as
they arrive, matches values by JSONPath, and forwards everything else as it goes.

> 📚 Rust Docs: <https://ramaproxy.org/docs/rama/json/index.html>

`rama::json` is available with the default `std` feature. The HTTP layers described
below need the `http` feature.

## What Rama offers

- **Tokenizer** (`rama::json::tokenizer`): a strict, incremental JSON tokenizer.
  Feed it byte chunks with `write` and call `end` once the input is done. It emits
  borrowed tokens, including whitespace and punctuation, so an identity sink
  reproduces the input byte for byte.
- **JSONPath** (`rama::json::path`): `JsonPath` can be parsed from a string such as
  `$.items[*].id` or built in code with `JsonPath::builder()`. The syntax follows
  RFC 9535, limited to the selectors a forward streaming parser can match: member
  names, non-negative indexes and slices, wildcards, selector lists and descendant
  (`..`) segments. Filters and negative indexes are rejected with an error rather
  than silently ignored.
- **Selection** (`rama::json::select`): report the tokens of every value that
  matches one or more paths, together with the concrete path of the value.
- **Rewriting** (`rama::json::rewrite`): replace or remove matched values, scalars
  as well as whole objects and arrays. Removed or replaced subtrees are skipped as
  they stream through, so they are not buffered. Replacements can be raw JSON,
  Rust scalars or any `serde::Serialize` value.
- **Capture** (`rama::json::capture`): copy out small matched values, as raw bytes,
  typed scalars or deserialized through `serde`, while the rest of the input
  streams past.

## Resource limits

Each stage has an explicit bound, and exceeding it is an error rather than
unbounded growth:

- The tokenizer limits how many bytes it buffers while a single token is still
  incomplete (8 MiB by default, see `DEFAULT_MAX_BUFFERED_BYTES`). Raise it when
  you expect very large strings or numbers.
- Capture takes a `max_capture_bytes` limit for each selected value.

## HTTP integration

`rama::http::layer::json_rewrite` provides `JsonRewriteLayer` for response bodies
and `JsonRequestRewriteLayer` for request bodies. They only touch bodies with a JSON
`Content-Type` that are not content-encoded, and drop the `Content-Length` header
because the length changes. Place them after a decompression layer if you need to
rewrite compressed bodies. A custom rewrite policy can narrow which messages are
rewritten.

`rama::http::layer::json_capture::JsonCaptureBody` captures selected values while
forwarding the body unchanged. For a one-off read, `BodyExtractExt::try_capture_json`
collects the matches of a set of paths without buffering the whole body.

[`JsonRewriteLayer::new`](https://ramaproxy.org/docs/rama/http/layer/json_rewrite/struct.JsonRewriteLayer.html)
takes the [`JsonPath`](https://ramaproxy.org/docs/rama/json/path/struct.JsonPath.html)
selectors (for example `$.user.token`) and a
[`JsonValueHandler`](https://ramaproxy.org/docs/rama/json/rewrite/trait.JsonValueHandler.html),
which can be a closure. The handler gets the index of the matching selector and a
[`JsonValue`](https://ramaproxy.org/docs/rama/json/rewrite/struct.JsonValue.html) to `replace`
(for example with `"[redacted]"`) or `remove`.

The rama CLI uses the same selection code: `rama send --select-json '$.data[*].id' <URL>`
prints each matching value of a JSON response on its own line.

## Examples

There is no dedicated example program yet. The closest references are:

- [rama-http/src/layer/json_rewrite/tests.rs](https://github.com/plabayo/rama/blob/main/rama-http/src/layer/json_rewrite/tests.rs):
  complete HTTP services wrapped in the JSON rewrite layers.
- [rama-http/src/layer/json_capture/tests.rs](https://github.com/plabayo/rama/blob/main/rama-http/src/layer/json_capture/tests.rs):
  capturing values from streamed bodies.
- [/examples/src/http_nd_json.rs](https://github.com/plabayo/rama/blob/main/examples/src/http_nd_json.rs)
  and [/examples/src/tcp_nd_json.rs](https://github.com/plabayo/rama/blob/main/examples/src/tcp_nd_json.rs):
  newline-delimited JSON streams. These use `rama::stream::json`, a separate framing
  utility, not the JSONPath tools above.

API docs:

- <https://ramaproxy.org/docs/rama/json/index.html>
- <https://ramaproxy.org/docs/rama/http/layer/json_rewrite/index.html>
- <https://ramaproxy.org/docs/rama/http/layer/json_capture/index.html>
