//! basic web service

mod service;
#[doc(inline)]
pub use service::{match_service, WebService};

mod endpoint;
#[doc(inline)]
pub use endpoint::{extract, EndpointServiceFn, IntoEndpointService};

pub mod k8s;
#[doc(inline)]
pub use k8s::{k8s_health, k8s_health_builder};

#[cfg(feature = "telemetry")]
mod prometheus;
#[doc(inline)]
#[cfg(feature = "telemetry")]
pub use prometheus::PrometheusMetricsHandler;
