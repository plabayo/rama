//! Rama middleware services that operate directly on [`crate::stream::Stream`] types.
//!
//! Examples are services that can operate directly on a `TCP`, `TLS` or `UDP` stream.

mod tracker;
#[doc(inline)]
pub use tracker::{BytesRWTrackerHandle, BytesTrackerLayer, BytesTrackerService};

pub mod http;

#[cfg(feature = "telemetry")]
pub mod opentelemetry;
