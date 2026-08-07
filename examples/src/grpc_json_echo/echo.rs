//! The `Echo` service definition, shared by the server and client examples.
//!
//! Two rama capabilities come together here:
//!
//! - [`rama::http::grpc::define_service!`] generates the same client and server stubs the
//!   `.proto` driven codegen does, but from a definition written directly in Rust: no
//!   `.proto` file, no build script;
//! - [`rama::http::grpc::serde::JsonCodec`] serializes the messages with [serde], so the
//!   stubs work with your own types instead of generated protobuf messages.
//!
//! JSON is not a good default. It is used here because you can read it on the wire, which
//! makes this example easy to `curl` and easy to follow. It is also the slowest and most
//! verbose option.
//!
//! Pick the codec your service needs instead. MessagePack uses the same types and derives
//! but is binary, so it is smaller and faster. Rust-native formats such as postcard or
//! bincode are smaller and faster again, but only Rust can read them. Any format with a
//! [serde] implementation works: implementing `SerdeFormat` for one takes about ten lines.
//!
//! gRPC does not negotiate content types, so both ends of a route need the same codec.
//!
//! The `grpc_echo` example next to this one defines the same `Echo` service with a `.proto`
//! file and a build script. Use that when other languages talk to your service. The cost is
//! generated message types you convert to and from, plus `protoc` in your build.
//!
//! [serde]: https://serde.rs

#![allow(
    unreachable_pub,
    clippy::allow_attributes,
    reason = "generated gRPC stubs are exempt from rama's lints"
)]

use rama::http::grpc::serde::JsonCodec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchoRequest {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchoResponse {
    pub message: String,
}

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
