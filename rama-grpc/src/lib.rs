//! Grpc modules and support for Rama.
//!
//! This Rust implementation of [gRPC], a high performance, open source, general
//! RPC framework that puts mobile and HTTP/2 first.
//!
//! `rama-grpc` is a fork of [`tonic`], adapted for use within the rama ecosystem,
//! being `tonic` derived it is a gRPC over HTTP/2 implementation focused on **high
//! performance**, **interoperability**, and **flexibility**. This library was
//! created to have first class support of async/await and to act as a core building
//! block for production systems written in Rust.
//!
//! # Examples
//!
//! Examples can be found under examples within [the rama repository].
//!
//! # Getting Started
//!
//! Follow the instructions in the [`rama-grpc-build`] crate documentation.
//!
//! # Structure
//!
//! ## Generic implementation
//!
//! The main goal of `rama-grpc` is to provide a generic gRPC implementation over HTTP/2
//! framing. This means at the lowest level this library provides the ability to use
//! a generic HTTP/2 implementation with different types of gRPC encodings formats. Generally,
//! some form of codegen should be used instead of interacting directly with the items in
//! [`client`] and [`server`].
//!
//! ## Transport
//!
//! The [`transport`] module contains a fully featured HTTP/2.0 [`Channel`] (gRPC terminology)
//! and [`Server`]. These implementations are built on top of [`tokio`], and rama.
//! It also provides many of the features that the core gRPC libraries provide such as load balancing,
//! tls, timeouts, and many more. This implementation can also be used as a reference implementation
//! to build even more feature rich clients and servers. This module also provides the ability to
//! enable TLS using one of the `rama-tls-boring`, `rama-tls-rustls` or your own implementation.
//!
//! # Code generated client/server configuration
//!
//! ## Max Message Size
//!
//! Currently, both servers and clients can be configured to set the max message encoding and
//! decoding size. This will ensure that an incoming gRPC message will not exhaust the systems
//! memory. By default, the decoding message limit is `4MB` and the encoding limit is `usize::MAX`.
//!
//! # Rama
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
//! [`rama-grpc-build`]: https://github.com/plabayo/rama/rama-grpc-build
//! [`tokio`]: https://docs.rs/tokio
//! [`Channel`]: transport/struct.Channel.html
//! [`Server`]: transport/struct.Server.html

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
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tokio-rs/website/master/public/img/icons/tonic.svg"
)]
#![doc(issue_tracker_base_url = "https://github.com/hyperium/tonic/issues/")]
#![doc(test(no_crate_inject, attr(deny(rust_2018_idioms))))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![allow(clippy::disallowed_types)] // for interfacing with protobuf it is easier to allow things like std HashMap

pub mod client;
pub mod codec;
pub mod metadata;
pub mod server;
pub mod service;

#[cfg(feature = "transport")]
pub mod transport;

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

pub mod codegen;

/// `Result` is a type that represents either success ([`Ok`]) or failure ([`Err`]).
/// By default, the Err value is of type [`Status`] but this can be overridden if desired.
pub type Result<T, E = Status> = std::result::Result<T, E>;
