//! Rama middleware services that operate directly on network [`rama_core::stream::Stream`] types.
//!
//! Examples are services that can operate directly on a `TCP`, `TLS` or `UDP` stream.

mod tracker;
#[doc(inline)]
pub use tracker::{
    BytesRWTrackerHandle, IncomingBytesTrackerLayer, IncomingBytesTrackerService,
    OutgoingBytesTrackerLayer, OutgoingBytesTrackerService,
};

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "opentelemetry")]
pub mod opentelemetry;
