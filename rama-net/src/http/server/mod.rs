//! Http server utility types and services.
//!
//! - [`HttpPeekRouter`] allows you to detect http/1x and h2 traffic. H3 traffic
//!   is not covered by this router as this is done via sidechannel information instead (e.g. ALPN in TLS).

pub mod peek;
pub use peek::{
    DEFAULT_HTTP_PEEK_READ_BUFFER_SIZE, DEFAULT_HTTP1_REQUEST_LINE_MAX_SIZE, HttpPeekConfig,
    HttpPeekRouter, HttpPeekVersion, HttpPrefixedIo, NoHttpRejectError, peek_http_input,
    peek_http_input_with_config,
};
