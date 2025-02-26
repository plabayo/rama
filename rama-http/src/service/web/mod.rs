//! basic web service

mod service;
#[doc(inline)]
pub use service::{WebService, match_service};

mod endpoint;
#[doc(inline)]
pub use endpoint::{EndpointServiceFn, IntoEndpointService, extract};

pub mod k8s;
#[doc(inline)]
pub use k8s::{k8s_health, k8s_health_builder};
