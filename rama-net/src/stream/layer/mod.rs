//! Rama middleware services that operate directly on network [`rama_core::io::Io`] types.
//!
//! Examples are services that can operate directly on a `TCP`, `TLS` or `UDP` stream.

mod throttle;
#[doc(inline)]
pub use throttle::{
    OutgoingThrottleLayer, OutgoingThrottleService, ThrottleLayer, ThrottleMode, ThrottleService,
    ThrottledIo,
};

mod tracker;
#[doc(inline)]
pub use tracker::{
    BytesRWTracker, BytesRWTrackerHandle, IncomingBytesTrackerLayer, IncomingBytesTrackerService,
    OutgoingBytesTrackerLayer, OutgoingBytesTrackerService,
};

#[cfg(feature = "opentelemetry")]
#[cfg_attr(docsrs, doc(cfg(feature = "opentelemetry")))]
pub mod opentelemetry;
