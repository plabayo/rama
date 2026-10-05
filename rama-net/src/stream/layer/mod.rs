//! Rama middleware services that operate directly on network [`rama_core::io::Io`] types.
//!
//! Examples are services that can operate directly on a `TCP`, `TLS` or `UDP` stream.

mod throttle;
#[doc(inline)]
pub use throttle::{
    OutgoingThrottleLayer, OutgoingThrottleService, ThrottleBudget, ThrottleConfig, ThrottleGates,
    ThrottleLayer, ThrottleMode, ThrottleService, Throttleable, ThrottledIo,
};

mod tcp_options;
#[doc(inline)]
pub use tcp_options::{TcpStreamOptions, TcpStreamOptionsLayer, TcpStreamOptionsService};

mod tracker;
#[doc(inline)]
pub use tracker::{
    BytesRWTracker, BytesRWTrackerHandle, IncomingBytesTrackerLayer, IncomingBytesTrackerService,
    OutgoingBytesTrackerLayer, OutgoingBytesTrackerService,
};

#[cfg(feature = "opentelemetry")]
#[cfg_attr(docsrs, doc(cfg(feature = "opentelemetry")))]
pub mod opentelemetry;
