//! HTTP/3 connection-scoped codecs (RFC 9114, RFC 9204).
//!
//! This module holds the stateful pieces that sit above the pure wire vocabulary in
//! [`rama_http_types::proto::h3`]: the bounded incremental frame reader and the stateful QPACK
//! encoder/decoder with their dynamic tables and blocked-section accounting.
//!
//! Connection, stream and async transport driving are not here — they arrive with the H3 engine in
//! a later change. These codecs are synchronous: bytes in, typed units (or a "need more" signal)
//! out.

pub mod frame;
pub mod qpack;
