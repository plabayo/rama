//! HTTP/3 client/server engine and connection-scoped codecs (RFC 9114, RFC 9204).
//!
//! This module holds the stateful pieces that sit above the pure wire vocabulary in
//! [`rama_http_types::proto::h3`]: the bounded incremental frame reader and the stateful QPACK
//! encoder/decoder with their dynamic tables and blocked-section accounting.
//!
//! [`client`] and [`server`] expose Rama requests, responses and the common
//! [`crate::body::Incoming`] body. Run their accompanying [`connection::Driver`]
//! concurrently to drive control and QPACK streams independently of application bodies.
//! The underlying frame and compression codecs also remain usable synchronously.
//!
//! The frame decoder accepts owned [`rama_core::bytes::Bytes`] through
//! [`frame::FrameDecoder::feed_bytes`]. Drain `poll` until it needs more input before feeding the
//! next chunk; rejected input stays with the caller. Contiguous payloads share their input storage,
//! and only fragmented known payloads are coalesced. Input chunk and frame limits are independent.
//!
//! QPACK encoders accept ordinary name/value tuples or [`qpack::EncodeField`] inputs preserving
//! sensitivity. [`qpack::EncodeField::from_header`] carries Rama header sensitivity across the
//! boundary, and decoded [`qpack::FieldPair`] values can be forwarded directly. Optional dynamic
//! compression falls back to literals when reference or encoder-output budgets are exhausted.
//!
//! Drain both QPACK instruction outputs regularly. [`qpack::QpackError::OutputBlocked`] is local
//! backpressure with no wire error code; retry after draining (or split an oversized input batch).
//! Other errors expose their wire code and stream/connection scope. A driver abandoning a field
//! section must also arrange stream cancellation so the remote encoder can release references.
//! Plain decoded literals share section storage. Blocked sections and dynamic-table literals use
//! compact owned storage instead, so small retained slices cannot pin unrelated large buffers.

pub mod frame;
pub mod qpack;

mod control;
mod error;
pub use error::Error;

mod quic;

mod headers;

pub mod connection;

pub(crate) mod body;
mod stream;

pub mod client;

pub mod server;

#[cfg(test)]
mod tests;

mod priority;
pub use priority::PriorityHandle;

mod upgrade;

pub mod push;

#[cfg(feature = "fuzz-utils")]
#[doc(hidden)]
pub mod fuzz;
