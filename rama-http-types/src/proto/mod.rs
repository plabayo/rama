//! High level pertaining to the HTTP message protocol.
//!
//! For low-level proto details you can refer to the `proto` module
//! in the `rama-http-core` crate.

pub mod h1;
pub mod h2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Byte length of the raw bytes of the request/response headers (excl. trailers).
pub struct HeaderByteLength(pub usize);
