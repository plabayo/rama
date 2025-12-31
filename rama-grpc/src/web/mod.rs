//! grpc-web protocol translation for `rama-grpc` services.
//!
//! This module enables `rama-grpc` servers to handle requests from [grpc-web] clients directly,
//! without the need of an external proxy. It achieves this by wrapping individual rama-grpc services
//! with a rama service that performs the translation between protocols and handles `cors`
//! requests.
//!
//! ## Limitations
//!
//! * `rama-grpc` web server is designed to work with grpc-web-compliant clients only. It is not expected to
//!   handle arbitrary HTTP/x.x requests or bespoke protocols.
//! * Similarly, the cors support implemented  by this module will *only* handle grpc-web and
//!   grpc-web preflight requests.
//! * Currently, grpc-web clients can only perform `unary` and `server-streaming` calls. These
//!   are the only requests this module is designed to handle. Support for client and bi-directional
//!   streaming will be officially supported when clients do.
//! * There is no support for web socket transports.
//!
//! [grpc-web]: https://github.com/grpc/grpc-web

mod call;
mod client;
mod layer;
mod service;

pub use call::GrpcWebCall;
pub use client::{GrpcWebClientLayer, GrpcWebClientService};
pub use layer::GrpcWebLayer;
pub use service::GrpcWebService;
