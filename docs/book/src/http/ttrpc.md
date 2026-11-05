# ttRPC

ttRPC ("gRPC for low-memory environments") is the RPC protocol used by container
runtimes such as containerd and their plugins (shims, the kata-agent, NRI). It keeps
gRPC's ideas: Protobuf messages, a service/method model, unary and streaming calls
and a status model. It drops the HTTP/2 substrate in favour of a small
length-prefixed frame directly on the byte stream. It is therefore a sibling to
[gRPC](./grpc.md), not a flavour of HTTP.

> 📚 Rust Docs: <https://ramaproxy.org/docs/rama/ttrpc/index.html>

Rama ships it as its own crate pair, mirroring the gRPC ones:
[`rama-ttrpc`](https://crates.io/crates/rama-ttrpc) (runtime) and
[`rama-ttrpc-build`](https://crates.io/crates/rama-ttrpc-build) (codegen). Through the
`rama` crate it is available as `rama::ttrpc` with the `ttrpc` feature.

## Code generation

Services are defined in `.proto` files and compiled from a `build.rs` with
`rama-ttrpc-build`: `compile_protos` for the simple case, or `configure()` for options
such as a custom output directory. With the `ttrpc` feature the same API is also
available as `rama::ttrpc::build`. Include the generated code with
`rama::ttrpc::include_proto!`.

For each service the generator produces a trait with one async method per RPC. You
implement that trait for your server type, and the generated code implements it for
`Client`, so a client calls the same methods.

## Transport

As with `rama-grpc` there is no transport layer of its own. ttRPC needs a connected
byte stream: any `AsyncRead + AsyncWrite` type, such as a `rama-tcp` or `rama-unix`
stream, optionally wrapped in TLS, or an in-memory pipe. UDP is not a byte stream and
cannot be used directly.

## Server and client

`TtrpcServer` is a Rama `Service` that serves one connection per accepted stream, so
you can hand it straight to a TCP or Unix listener. For a single connection that is
already established, use `ServerConnection` directly.

On the client side, `Client::new` wraps a connected stream; all calls made through
a client and its clones share that one connection. `TtrpcConnector` wraps an inner
connector so a connector stack yields a ready `Client` instead of a raw stream.
Per-call metadata and timeouts are set through `ClientExt`.

A server is built with
[`TtrpcServer::new`](https://ramaproxy.org/docs/rama/ttrpc/struct.TtrpcServer.html) and
`register`, which takes the generated service wrapper around your implementation (code
included with [`include_proto!`](https://ramaproxy.org/docs/rama/ttrpc/macro.include_proto.html)).
The result can be passed to
[`TcpListener::serve`](https://ramaproxy.org/docs/rama/tcp/server/struct.TcpListener.html), as
the [`ttrpc_server`](https://github.com/plabayo/rama/blob/main/examples/src/ttrpc_server.rs)
example does.

## Differences from gRPC

- No HTTP: metadata and timeouts travel inside the request frame, and there is no
  HTTP router, no gRPC-Web and no message compression.
- ttRPC has no per-stream flow control. Backpressure applies to the whole
  connection, so a response stream that is not consumed stalls the other calls on
  that connection. Consume or drop streams promptly.
- A server connection limits how many requests run at once (1024 by default,
  `DEFAULT_MAX_CONCURRENT_STREAMS`). Requests over the limit are rejected with
  `RESOURCE_EXHAUSTED`.

## Examples

- [/examples/src/ttrpc_server.rs](https://github.com/plabayo/rama/blob/main/examples/src/ttrpc_server.rs):
  serve a ttRPC `Greeter` over a rama-tcp connection. Run it with
  `cargo run -p rama-examples --bin ttrpc_server --features=ttrpc,tcp`.
