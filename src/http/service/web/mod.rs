//! basic web service

mod service;
pub use service::WebService;

mod endpoint;
pub use endpoint::{extract, EndpointServiceFn, IntoEndpointService};

pub mod matcher;

pub mod k8s;
pub use k8s::{k8s_health, k8s_health_builder};

mod prometheus;
pub use prometheus::prometheus_metrics;
