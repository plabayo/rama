//! Rama telemetry modules.

#[cfg(feature = "opentelemetry")]
#[cfg_attr(docsrs, doc(cfg(target_os = "opentelemetry")))]
pub mod opentelemetry;

#[macro_use]
pub mod tracing;
