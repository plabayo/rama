# gRPC

gRPC is an RPC protocol and ecosystem built around strongly typed service contracts, most often defined using Protocol Buffers. In practice it is commonly carried over HTTP/2, but conceptually it is not "just HTTP with another content type". It is an application protocol with its own method model, framing rules, status model, streaming semantics and code generation flow.

That distinction matters in Rama.

Rama exposes gRPC in a way that fits its overall design:

- gRPC often rides on top of HTTP/2, so it integrates naturally with Rama's HTTP stack
- gRPC is still treated as its own protocol layer, with its own service types, routing, codecs and middleware
- because Rama works from transport up, you can reason about gRPC together with TCP, TLS, HTTP/2, proxying and telemetry without those boundaries disappearing

> [!TIP]
> In episode 9 of Netstack.FM (_gRPC with Lucio Franco_)
> found at <https://netstack.fm/#episode-9>:
>
> We introduced gRPC and Tonic, a gRPC implementation in Rust (and from which rama-grpc forked).
> We Also touched on the future of some of these ecosystems and where it all might be heading next,
> and thus also what might be changing in rama-grpc in the future.

## Description

> Official website: <https://grpc.io/>
>
> Protocol guide: <https://grpc.io/docs/what-is-grpc/>

gRPC gives you:

- strongly typed request and response messages
- generated clients and servers from `.proto` contracts
- unary, client-streaming, server-streaming and bidirectional-streaming RPCs
- a clear status model and metadata mechanism
- efficient binary framing

It is often chosen when you want machine-to-machine APIs with:

- explicit contracts
- backwards-compatible schema evolution
- streaming support
- high throughput and low overhead
- generated client code for multiple languages

## gRPC and HTTP

gRPC is frequently described as "running over HTTP/2", which is true in the common case, but incomplete.

HTTP/2 provides the transport-level application substrate:

- request and response exchange
- multiplexed streams
- header compression
- flow control
- long-lived connections

gRPC adds its own semantics on top:

- service and method naming
- message framing
- `grpc-status` and gRPC error mapping
- metadata conventions
- protobuf-based message codecs
- streaming RPC shapes

So the practical relationship is:

- **gRPC commonly depends on HTTP/2 as a transport**
- **Rama's gRPC support is implemented to integrate with the HTTP stack**
- **the protocol model you program against is still gRPC, not raw HTTP**

This is also why the chapter lives in the HTTP section of the book while still being worth discussing separately. There's also nothing stopping you from running gRPC on top of
another transport layer.

## Rama Support

> 📚 Rust Docs: <https://ramaproxy.org/docs/rama/http/grpc/index.html>

Rama provides gRPC support through [`rama-grpc`](https://crates.io/crates/rama-grpc), re-exported from the main `rama` crate behind the appropriate feature flags.

At a high level Rama supports:

- gRPC servers
- gRPC clients
- unary and streaming RPCs
- compression
- health checking (behind the `protobuf` flag)
- interceptors and service composition
- protobuf code generation via [`rama-grpc-build`](https://crates.io/crates/rama-grpc-build)
- an opentelemetry exporter (behind the `opentelemetry` feature flag)

Because this is Rama, gRPC does not live in an isolated framework box. You can compose it with:

- transport selection such as TCP or Unix domain sockets
- TLS termination or client-side TLS
- observability layers
- request and response middleware
- proxy-aware network stacks
- the same `Service` and `Layer` abstractions used everywhere else in the project

## Mental Model in Rama

The easiest way to understand gRPC in Rama is to separate the stack into layers:

1. **Transport**  
   Usually TCP, sometimes with TLS.
2. **HTTP substrate**  
   Most commonly HTTP/2 for native gRPC.
3. **gRPC protocol**  
   Method dispatch, framing, metadata, statuses and streaming.
4. **Your service logic**  
   The actual application methods you implement.

Rama lets you work at any of these levels when needed. That means you can keep a simple gRPC service simple, but also drop lower when you need to control the network path, proxying behavior, or connection setup.

## Practical Server Example

The smallest server example in the repository is the hello world server:

- [`examples/grpc/src/helloworld/server.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/helloworld/server.rs)

This example already shows an important Rama idea:

- you still use an HTTP server to serve the connection
- the application service plugged into that server is a gRPC service

That is the integration point between the transport/HTTP layers and the gRPC protocol layer.

## Practical Client Example

The matching client lives here:

- [`examples/grpc/src/helloworld/client.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/helloworld/client.rs)

It uses a regular Rama HTTP client as the transport-capable client
substrate and then wraps it in the generated gRPC client,
this is another good example to help better understand Rama's spirit:

- the lower networking machinery remains reusable
- the gRPC layer gives you typed RPC ergonomics on top

## Code Generation and Protobuf

If you work with protobuf-defined services,
you will usually generate Rust code from `.proto` files at build time.

Rama supports that through `rama-grpc-build`.

See:

- [`examples/grpc/build.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/build.rs)

Typical building blocks include:

- `rama::http::grpc::build::protobuf::configure()`
- `rama::http::grpc::build::protobuf::compile_protos(...)`
- `rama::http::grpc::include_proto!(...)`

This gives you generated service traits, client stubs and message types that fit directly into Rama's service model.

## Health Checking

gRPC defines a standard health checking protocol, and Rama supports it directly.

See:

- [`examples/grpc/src/health/server.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/health/server.rs)
- [`examples/grpc/README.md`](https://github.com/plabayo/rama/blob/main/examples/grpc/README.md)

The health example combines:

- your application service
- the generated health service
- a `GrpcRouter`

This is a good real-world pattern because production deployments often need more than a single bare service.

## Compression and Streaming

gRPC is not only about unary RPCs.

Rama supports features such as:

- compressed requests and responses
- server streaming
- client streaming
- bidirectional streaming

For concrete examples, see:

- [`examples/grpc/src/compression/server.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/compression/server.rs)
- [`examples/grpc/src/compression/client.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/compression/client.rs)
- [`examples/grpc/src/shared/tests/compression/server_stream.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/shared/tests/compression/server_stream.rs)
- [`examples/grpc/src/shared/tests/compression/client_stream.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/shared/tests/compression/client_stream.rs)
- [`examples/grpc/src/shared/tests/compression/bidirectional_stream.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/shared/tests/compression/bidirectional_stream.rs)

The test-backed examples in `examples/grpc/src/shared/tests` are especially useful if you want to understand the behavior beyond the hello-world path.

## gRPC-Web

If you need browser compatibility, plain native gRPC is often not enough on its own. Browsers do not expose raw HTTP/2 framing in the same way native gRPC clients expect.

Rama also has support in this space. See:

- [`examples/grpc/src/shared/tests/web/grpc.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/shared/tests/web/grpc.rs)
- [`examples/grpc/src/shared/tests/web/grpc_web.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/shared/tests/web/grpc_web.rs)

This is a useful reminder that "gRPC" in the wild often means a family of deployment patterns, not only one exact wire usage.

## Where it Fits in Rama

If you are already reading the Rama book from top to bottom, gRPC sits at an interesting intersection:

- from [Transport Protocols](../transport.md) you inherit the idea that transport is configurable
- from [Web Servers](../web_servers.md) you inherit the server-side composition model
- from [Http Clients](./http_clients.md) you inherit the client-side stack model
- from the intro chapters you inherit the core `Service` and `Layer` abstractions

That combination is what makes Rama's gRPC story feel different from a narrower RPC framework.

You are not forced to choose between:

- a nice typed RPC surface
- full control over the lower networking stack

Rama gives you both.

## More examples

The most relevant example entry points are:

- [`examples/grpc/README.md`](https://github.com/plabayo/rama/blob/main/examples/grpc/README.md): overview of the gRPC example suite
- [`examples/grpc/src/helloworld/server.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/helloworld/server.rs): minimal gRPC server
- [`examples/grpc/src/helloworld/client.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/helloworld/client.rs): minimal gRPC client
- [`examples/grpc/src/health/server.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/health/server.rs): health reporting and `GrpcRouter`
- [`examples/grpc/src/compression/server.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/compression/server.rs): compression support
- [`examples/grpc/src/compression/client.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/compression/client.rs): compression-aware client
- [`examples/grpc/src/gcp/README.md`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/gcp/README.md): more realistic remote API usage

If you want to start with the shortest path:

1. run the hello world server
2. run the hello world client
3. inspect the health example
4. move on to the streaming and compression examples

That sequence gives you a practical ramp from "typed RPC over the network" to "production-leaning gRPC service composition in Rama".
