//! # rama-grpc
//!
//! gRPC modules and support for Rama.
//!
//! This crate provides a Rust implementation of [gRPC], an RPC framework built
//! on HTTP/2. `rama-grpc` is a fork of
//! [`tonic`](https://github.com/hyperium/tonic), adapted to integrate with
//! the Rama ecosystem.
//!
//! ## Examples
//!
//! Examples can be found under examples within [the rama repository].
//!
//! ## Structure
//!
//! ### Generic implementation
//!
//! The main goal of `rama-grpc` is to provide a generic gRPC implementation over HTTP/2
//! framing. This means at the lowest level this library provides the ability to use
//! a generic HTTP/2 implementation with different types of gRPC encodings formats. Generally,
//! some form of codegen should be used instead of interacting directly with the items in
//! [`client`] and [`server`].
//!
//! ### Transport
//!
//! There are no transport layers in rama-grpc.
//! Use rama's http/tls/unix/udp capabilities for that.
//!
//! ### gRPC-web
//!
//! You can find gRPC-web support in the [web] module.
//!
//! ## Code generated client/server configuration
//!
//! ### Max Message Size
//!
//! Currently, both servers and clients can be configured to set the max message encoding and
//! decoding size. This will ensure that an incoming gRPC message will not exhaust the systems
//! memory. By default, the decoding message limit is `4MB` and the encoding limit is `usize::MAX`.
//!
//! ## Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>
//!
//! [gRPC]: https://grpc.io
//! [the rama repository]: https://github.com/plabayo/rama
//! [`tokio`]: https://docs.rs/tokio

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]
#![recursion_limit = "256"]
#![allow(clippy::disallowed_types)] // for interfacing with protobuf it is easier to allow things like std HashMap

// TODO: support https://connectrpc.com/

pub mod client;
pub mod codec;
pub mod metadata;
pub mod server;
pub mod service;

pub mod web;

mod extensions;
mod macros;
mod request;
mod response;
mod status;
mod util;

#[doc(inline)]
pub use codec::Streaming;
pub use extensions::GrpcMethod;
pub use request::{IntoRequest, IntoStreamingRequest, Request};
pub use response::Response;
pub use status::{Code, ConnectError, Status, TimeoutExpired};

#[cfg(feature = "protobuf")]
pub mod protobuf;

#[doc(hidden)]
pub mod codegen;

pub use ::rama_grpc_build as build;

/// `Result` is a type that represents either success ([`Ok`]) or failure ([`Err`]).
/// By default, the Err value is of type [`Status`] but this can be overridden if desired.
pub type Result<T, E = Status> = std::result::Result<T, E>;
