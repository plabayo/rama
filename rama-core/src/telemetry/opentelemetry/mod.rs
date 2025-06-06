//! openelemetry module re-exports
//!
//! This module re-exports the crates supported and used by rama for (open) telemetry,
//! such that you can make use of it for custom metrics, registries and more.

#[doc(inline)]
pub use ::opentelemetry::*;

#[doc(inline)]
pub use ::opentelemetry_semantic_conventions as semantic_conventions;

#[doc(inline)]
pub use ::opentelemetry_sdk as sdk;

#[doc(inline)]
pub use ::tracing_opentelemetry as tracing;

mod attributes;
#[doc(inline)]
pub use attributes::AttributesFactory;

#[derive(Debug, Clone, Default)]
/// Options that can be used to customize a meter (middleware) provided by `rama`.
pub struct MeterOptions {
    /// Service info, by default `rama`'s info is used.
    pub service: Option<ServiceInfo>,
    /// Optional attributes to be added to every metric.
    pub attributes: Option<Vec<KeyValue>>,
    /// Prefix that is optionally added to to each metric pushed by the middleware.
    pub metric_prefix: Option<String>,
}

#[derive(Debug, Clone)]
/// Information about the service producing the metrics.
pub struct ServiceInfo {
    /// name of the service
    pub name: String,
    /// version of the service (e.g. semver)
    pub version: String,
}
