//! Rama middleware services that operate directly on [`crate::stream::Stream`] types.
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

pub mod opentelemetry;
