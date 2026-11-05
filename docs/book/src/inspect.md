# Inspection

An inspecting proxy does more than forward traffic. It records requests,
responses and messages, shows them to a person or a program, and can hold a
message until someone approves, edits or drops it. Those parts are the same
whether the interface is a web UI, a terminal UI or an API, and whether the
traffic is HTTP, WebSocket or something else.

`rama::inspect` holds these protocol-independent parts. Protocol adapters live in
the crates that own the protocol. Enable the `inspect` feature together with the
protocol features you use (`http`, `ws`, `tls`, ...).

> 📚 Rust Docs: <https://ramaproxy.org/docs/rama/inspect/index.html>

For the proxy side of interception, such as TLS termination and certificate
issuing, see the [MITM chapter](./proxies/mitm.md).

## Building blocks

- **Lifecycle**: `InspectionState` is one shared switch for the whole process.
  Pausing it stops new captures, cancels running MITM sessions and waits until
  ongoing capture writes finish, so a successful pause is a clean boundary.
  `InspectionGate` is a `Service` that routes each input to an inspecting service
  while inspection is enabled, and to a pass-through service while paused.
- **Interception** (`rama::inspect::intercept`): `Interception` is a bounded queue
  of messages that wait for a decision. A protocol service enqueues a message and
  waits on its ticket with a timeout; a UI or API resolves it. The adapter decides
  what a message and a decision look like. `QueueLimits` bounds the number of
  waiting messages and their size.
- **Subscriptions** (`rama::inspect::subscription`): `subscribe` turns a query
  service and a change counter into a stream of fresh results. A slow consumer
  skips intermediate revisions instead of building up a queue.
- **Storage** (`rama::inspect::storage`): captured bodies and messages are
  appended as streams and read back as streams, optionally by byte range.
  `MemoryStore` and `FileStore` are included, both bounded by `StorageLimits`
  (64 MiB total and 8 MiB per record by default). Storage is a Rama service, so
  it can be wrapped in layers.
- **Timeline** (`rama::inspect::timeline`): a format-independent view model for a
  recorded capture, used to build viewers for HAR or qlog files.

For encrypted capture files, wrap a
[`FileStore`](https://ramaproxy.org/docs/rama/inspect/storage/struct.FileStore.html) (for
example from `FileStore::temporary`) in
[`EncryptStorageLayer`](https://ramaproxy.org/docs/rama/crypto/inspect/struct.EncryptStorageLayer.html)
and box the result as a
[`Storage`](https://ramaproxy.org/docs/rama/inspect/storage/type.Storage.html). The rama CLI
does this in
[`capture.rs`](https://github.com/plabayo/rama/blob/main/rama-cli/src/cmd/serve/proxy/capture.rs).

## Protocol adapters

| Adapter | Module |
|---|---|
| HTTP capture, queries, replay and runtime traffic control | [`rama::http::inspect`][http-inspect] |
| WebSocket messages on top of an HTTP upgrade capture | [`rama::http::ws::inspect`][ws-inspect] |
| TLS parameters observed on a connection | [`rama::tls::inspect`][tls-inspect] |
| Transport observations and connection ids | [`rama::net::inspect`][net-inspect] |
| User-agent profiles observed in traffic | [`rama::ua::inspect`][ua-inspect] |
| Captured exchanges converted to HAR | [`rama::http::layer::har::inspect`][har-inspect] |
| Encrypted storage (needs `boring`) | [`rama::crypto::inspect`][crypto-inspect] |

The HTTP adapter shows how the pieces fit: `CaptureHttpLayer` records exchanges
into a `CaptureStore` that writes to a `Storage`, the control module uses an
`Interception` queue for requests that wait for approval, and `MitmPolicy`
decides which hosts are intercepted at all.

## In the rama CLI

`rama serve proxy --mitm` is built on these modules. It captures HTTP, WebSocket
and TLS details into encrypted temporary file storage, serves a live web UI and
an authenticated JSON API from the proxy itself, and with `--intercept` holds
requests until they are approved. `rama inspect <FILE>` uses the timeline model
to show HAR and qlog files in the terminal. See the
[rama CLI chapter](./deploy/rama-cli.md) for usage.

## Examples

There is no dedicated example program for `rama::inspect` yet. The rama CLI proxy
is the reference user:

- [rama-cli/src/cmd/serve/proxy](https://github.com/plabayo/rama/tree/main/rama-cli/src/cmd/serve/proxy):
  capture storage setup (`capture.rs`) and the web UI and API (`dashboard/`).
- [/examples/src/http_mitm_proxy_boring.rs](https://github.com/plabayo/rama/blob/main/examples/src/http_mitm_proxy_boring.rs):
  a MITM proxy that does not use `rama::inspect` yet, a starting point to add the
  layers above to.

[http-inspect]: https://ramaproxy.org/docs/rama/http/inspect/index.html
[ws-inspect]: https://ramaproxy.org/docs/rama/http/ws/inspect/index.html
[tls-inspect]: https://ramaproxy.org/docs/rama/tls/inspect/index.html
[net-inspect]: https://ramaproxy.org/docs/rama/net/inspect/index.html
[ua-inspect]: https://ramaproxy.org/docs/rama/ua/inspect/index.html
[har-inspect]: https://ramaproxy.org/docs/rama/http/layer/har/inspect/index.html
[crypto-inspect]: https://ramaproxy.org/docs/rama/crypto/inspect/index.html
