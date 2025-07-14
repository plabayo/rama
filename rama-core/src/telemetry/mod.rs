//! Rama telemetry modules.

#[cfg(feature = "opentelemetry")]
pub mod opentelemetry;

#[macro_use]
pub mod tracing;
