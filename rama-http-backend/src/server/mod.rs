//! Rama HTTP server module,
//! which provides the [`HttpServer`] type to serve HTTP requests.

/// Result type of [`HttpServer::serve`].
pub type HttpServeResult = Result<(), rama_core::error::BoxError>;

pub mod service;
pub use service::HttpServer;

mod hyper_conn;

pub mod layer;
