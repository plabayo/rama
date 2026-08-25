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

A slightly modified client which uses dns loadbalancing and a connection pool live here:
- [`examples/grpc/src/shared/tests/helloworld_loadbalance/mod.rs](https://github.com/plabayo/rama/blob/main/examples/grpc/src/shared/tests/helloworld_loadbalance/mod.rs)

## Code Generation and Protobuf

If you work with protobuf-defined services,
you will usually generate Rust code from `.proto` files at build time.

Rama supports that through `rama-grpc-build`.

See:

- [`examples/proto/echo.proto`](https://github.com/plabayo/rama/blob/main/examples/proto/echo.proto): the contract, compiled by [`examples/build.rs`](https://github.com/plabayo/rama/blob/main/examples/build.rs)
- [`examples/src/grpc_echo/echo.rs`](https://github.com/plabayo/rama/blob/main/examples/src/grpc_echo/echo.rs): including the generated stubs
- [`examples/src/grpc_echo/server.rs`](https://github.com/plabayo/rama/blob/main/examples/src/grpc_echo/server.rs) and [`examples/src/grpc_echo/client.rs`](https://github.com/plabayo/rama/blob/main/examples/src/grpc_echo/client.rs): serving and calling it
- [`examples/grpc/build.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/build.rs)

Typical building blocks include:

- `rama::http::grpc::build::protobuf::configure()`
- `rama::http::grpc::build::protobuf::compile_protos(...)`
- `rama::http::grpc::include_proto!(...)`

This gives you generated service traits, client stubs and message types that fit directly into Rama's service model.

## Without Protobuf: Services Defined in Rust

Protobuf is the common case, not a requirement. Two pieces let you define and serve a gRPC service without a `.proto` file or a build script:

- `rama::http::grpc::define_service!` generates the same client and server stubs, from a service definition written directly in Rust (without any build.rs).
- `rama::http::grpc::serde::SerdeCodec` (de)serializes messages with [serde], so the stubs work with your own types. Note that any custom codec is possible here, so [serde] is not a requirement.

```rust,ignore
rama::http::grpc::define_service! {
    package = "rama.examples.echo.v1";
    codec = JsonCodec;

    /// Echoes back what it is given.
    service Echo {
        /// Echo a message once.
        rpc UnaryEcho(EchoRequest) -> EchoResponse;
        /// Echo a message once per word it contains.
        rpc ServerStreamingEcho(EchoRequest) -> stream EchoResponse;
    }
}
```

### Choosing a Codec

`JsonCodec` ships with rama and is what the examples use, but do not read that as a recommendation. It is used because you can read JSON on the wire, which makes the example easy to `curl` and a service easy to debug. JSON is also the slowest and most verbose option.

Any format with a [serde] implementation can be used instead. Implementing `SerdeFormat` for one takes about ten lines:

- **JSON**: readable on the wire, easy to debug, slow and verbose
- **MessagePack**: same types and derives, binary, much smaller and faster, and still easy to read from other languages
- **Rust-native formats** such as postcard or bincode: smaller and faster again, but only Rust can read them

All of these can stay backwards compatible: use optional fields, defaults, and ignore unknown fields. The difference with protobuf is that protobuf enforces this with field numbers, while here it is up to you.

### Protobuf or Not

Use serde when your types are Rust types. You derive `Serialize` and `Deserialize` on the types you already have, and those go on the wire as they are.

With protobuf every message is a generated type. If you already have your own types, you write conversion code both ways and keep it in sync. Rust enums show this best: an enum where some variants carry data works out of the box with serde, while protobuf needs a `oneof` next to an enum, which is more schema and more conversion code.

Skipping protobuf also means no build step: no `protoc`, no build script, no generated files. That makes a service quicker to change.

Use protobuf when other languages talk to your service. A `.proto` file is a contract they can generate code from, and that is worth a lot. It is the one thing serde cannot give you.

Either way, gRPC does not negotiate content types, so both ends of a route need the same codec.

In short: Rust on both ends is easier without protobuf, anything polyglot wants protobuf.

See:

- [`examples/src/grpc_json_echo/echo.rs`](https://github.com/plabayo/rama/blob/main/examples/src/grpc_json_echo/echo.rs): the service definition
- [`examples/src/grpc_json_echo/server.rs`](https://github.com/plabayo/rama/blob/main/examples/src/grpc_json_echo/server.rs): serving it
- [`examples/src/grpc_json_echo/client.rs`](https://github.com/plabayo/rama/blob/main/examples/src/grpc_json_echo/client.rs): calling it

Its sibling [`examples/src/grpc_echo`](https://github.com/plabayo/rama/tree/main/examples/src/grpc_echo) defines the very same `Echo` service from a `.proto` contract, which makes the two flows easy to compare.

[serde]: https://serde.rs

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

## HTTP and gRPC on One Web Router

An internal service often needs two different interfaces: generated gRPC APIs for machine
clients, and ordinary HTTP endpoints for operators, infrastructure probes or a small dashboard.
Rama can serve both from the same `rama_http::service::web::Router` and the same
`HttpServer::auto` listener.

Import `rama::http::grpc::service::web::RouterExt` to register each generated service
directly alongside the router's ordinary HTTP routes. Its `with_grpc_service` method consumes
and returns the router, while `set_grpc_service` is available when building a router mutably.

`with_grpc_service` derives `/<package>.<Service>/{method}` from `NamedService::NAME`.
It uses a regular POST route so the generated server receives the complete canonical gRPC URI;
there is no artificial `/grpc` prefix to configure and no nested prefix is stripped.

See the complete job-service example:

- [`examples/proto/jobs.proto`](https://github.com/plabayo/rama/blob/main/examples/proto/jobs.proto): generated job API with unary and server-streaming RPCs
- [`examples/src/http_grpc_job/jobs.rs`](https://github.com/plabayo/rama/blob/main/examples/src/http_grpc_job/jobs.rs): generated protobuf types and service stubs
- [`examples/src/http_grpc_job/common.rs`](https://github.com/plabayo/rama/blob/main/examples/src/http_grpc_job/common.rs): typed HTTP contracts, shared route constants and URI construction
- [`examples/src/http_grpc_job/server.rs`](https://github.com/plabayo/rama/blob/main/examples/src/http_grpc_job/server.rs): HTTP endpoints, job and standard gRPC health services on one router
- [`examples/src/http_grpc_job/client.rs`](https://github.com/plabayo/rama/blob/main/examples/src/http_grpc_job/client.rs): CLI for exploring the ordinary HTTP and generated gRPC APIs

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
- [`examples/src/http_grpc_job/server.rs`](https://github.com/plabayo/rama/blob/main/examples/src/http_grpc_job/server.rs): HTTP and multiple gRPC services on one web router and listener
- [`examples/src/http_grpc_job/client.rs`](https://github.com/plabayo/rama/blob/main/examples/src/http_grpc_job/client.rs): unary and server-streaming calls against the mixed router
- [`examples/grpc/src/compression/server.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/compression/server.rs): compression support
- [`examples/grpc/src/compression/client.rs`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/compression/client.rs): compression-aware client
- [`examples/grpc/src/gcp/README.md`](https://github.com/plabayo/rama/blob/main/examples/grpc/src/gcp/README.md): more realistic remote API usage

If you want to start with the shortest path:

1. run the hello world server
2. run the hello world client
3. inspect the health example
4. run the combined HTTP and gRPC job service
5. move on to the streaming and compression examples

That sequence gives you a practical ramp from "typed RPC over the network" to "production-leaning gRPC service composition in Rama".

## ttRPC: a sibling protocol

For low-overhead environments there is also **ttRPC** ("gRPC for low-memory environments"), the RPC
protocol used by container runtimes such as containerd and their plugins (shims, the kata-agent, NRI).
It keeps gRPC's ideas — Protobuf messages, a service/method model, unary and streaming calls, a status
model — but drops the HTTP/2 substrate in favour of a tiny length-prefixed frame directly on the byte
stream. It is therefore a sibling to gRPC, not a flavour of HTTP.

Rama ships it as its own crate pair, mirroring the gRPC ones: [`rama-ttrpc`](https://crates.io/crates/rama-ttrpc)
(runtime) and [`rama-ttrpc-build`](https://crates.io/crates/rama-ttrpc-build) (codegen). As with
`rama-grpc` there is no transport layer of its own — you bring the connection from any rama transport
(`rama-tcp` / `rama-unix` / `rama-udp`) and hand the stream to a `Client` or `ServerConnection`. See the
runnable example:

- [`examples/src/ttrpc_server.rs`](https://github.com/plabayo/rama/blob/main/examples/src/ttrpc_server.rs): serve a ttRPC `Greeter` over a rama-tcp connection
