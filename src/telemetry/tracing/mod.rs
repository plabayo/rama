//! Tracing re-exports and subscriber utilities.

#[doc(inline)]
pub use ::rama_core::telemetry::tracing::*;

pub use ::tracing_subscriber as subscriber;

#[cfg(any(target_vendor = "apple", docsrs))]
#[cfg_attr(docsrs, doc(cfg(target_vendor = "apple")))]
pub mod apple;
