//! Rama HTTP server module,
//! which provides the [`HttpServer`] type to serve HTTP requests.

/// Result type of [`HttpServer::serve`].
pub type HttpServeResult = Result<(), crate::error::Error>;

mod service;
pub use service::HttpServer;

mod hyper_conn;
