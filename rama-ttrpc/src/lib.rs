//! ttRPC support for Rama.
//!
//! # ttRPC
//!
//! ttRPC ("gRPC for low-memory environments") is a lightweight RPC protocol used by
//! container runtimes and their plugins — containerd shims, the kata-agent, and the
//! containerd Node Resource Interface (NRI). Where gRPC rides on HTTP/2, ttRPC replaces
//! the whole HTTP/2 stack with a simple length-prefixed framing directly on the byte
//! stream, so it is a sibling to [`rama-grpc`], not part of it.
//!
//! Messages are encoded with [`prost`]; service stubs are generated at build time by
//! [`rama-ttrpc-build`] (see [`include_proto!`]).
//!
//! ## Transport
//!
//! Like `rama-grpc`, this crate has **no transport layer**. A [`Client`] or
//! [`ServerConnection`] is built from any already-connected stream (anything that is
//! `AsyncRead + AsyncWrite`). Establish that stream with rama's `rama-tcp` / `rama-unix` /
//! `rama-udp` capabilities (or an in-memory `tokio::io::duplex` pair), then hand it over:
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
//! [`rama-grpc`]: https://crates.io/crates/rama-grpc
//! [`rama-ttrpc-build`]: https://crates.io/crates/rama-ttrpc-build
//! [`prost`]: https://crates.io/crates/prost

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod client;
mod context;
mod id_pool;
mod io;
mod macros;
mod server;
mod service;
mod types;

/// Result type used throughout `rama-ttrpc`, defaulting the error to [`Status`].
pub type Result<T, E = Status> = std::result::Result<T, E>;

pub use client::{Client, ClientExt, TtrpcConnector};
pub use context::metadata::Metadata;
pub use context::timeout::Timeout;
pub use context::{Context, get_context, get_server, try_get_context, try_get_server};
pub use server::{ServerConnection, ServerController, TtrpcServer};
pub use types::protos::status::StatusExt;
pub use types::protos::{Code, Status};

#[doc(hidden)]
pub mod __codegen_prelude {
    pub use crate::client::request_handlers::RequestHandler;
    pub use crate::server::method_handlers::MethodHandler;
    pub use crate::service::{
        ClientStreamingMethod, DuplexStreamingMethod, ServerStreamingMethod, Service, UnaryMethod,
    };
}

#[doc(hidden)]
pub mod prelude {
    pub use std::future::Future;

    pub use rama_core::futures::stream::Stream;

    pub use crate::Result;
}

pub mod stream {
    //! Streaming helpers re-exported for generated service code.
    pub use rama_core::futures::StreamExt;
    pub use rama_core::futures::async_stream::{stream_fn, try_stream_fn};
    pub use rama_core::futures::stream::{Stream, once};
}

/// ttRPC code generation (`rama-ttrpc-build`), re-exported so a `build.rs` can run codegen
/// through the `rama-ttrpc` facade (mirrors `rama-grpc`'s `build` re-export).
///
/// Enable the `protobuf` feature to use it, e.g. `rama_ttrpc::build::compile_protos(...)`.
#[cfg(feature = "protobuf")]
#[cfg_attr(docsrs, doc(cfg(feature = "protobuf")))]
#[doc(inline)]
pub use ::rama_ttrpc_build as build;

/// Protobuf support re-exported so generated ttRPC code does not require the consumer to
/// depend on `prost` directly (mirrors `rama-grpc`'s `protobuf::prost`).
///
/// Gated on the `protobuf` feature: this re-export only exists to back generated code, and
/// generating code requires that feature. (`prost` itself is always a dependency, since the
/// ttRPC wire format is protobuf-framed — unlike `rama-grpc` where the gate also makes the
/// `prost` dependency optional.)
#[cfg(feature = "protobuf")]
#[cfg_attr(docsrs, doc(cfg(feature = "protobuf")))]
pub mod protobuf {
    /// Re-export of [`prost`](https://docs.rs/prost) and
    /// [`prost-types`](https://docs.rs/prost-types).
    pub mod prost {
        pub use ::prost::*;
        pub use ::prost_types as types;
    }
}
