//! Http server utility types and services.
//!
//! - [`HttpPeekRouter`] allows you to detect http/1x and h2 traffic. H3 traffic
//!   is not covered by this router as this is done via sidechannel information instead (e.g. ALPN in TLS).

pub mod peek;
pub use peek::{HttpPeekRouter, HttpPeekStream, NoHttpRejectError};
