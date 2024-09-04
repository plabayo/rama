//! openelemetry module re-exports
//!
//! This module re-exports the crates supported and used by rama for (open) telemetry,
//! such that you can make use of it for custom metrics, registries and more.

pub use ::opentelemetry::*;

#[doc(inline)]
pub use ::opentelemetry_semantic_conventions as semantic_conventions;

#[doc(inline)]
pub use ::opentelemetry_sdk as sdk;
