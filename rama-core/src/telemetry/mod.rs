//! Rama telemetry modules.

#[cfg(feature = "opentelemetry")]
#[cfg_attr(docsrs, doc(cfg(feature = "opentelemetry")))]
pub mod opentelemetry;

#[macro_use]
pub mod tracing;
