//! basic web service

mod service;
#[doc(inline)]
pub use service::{WebService, match_service};

mod endpoint;
#[doc(inline)]
pub use endpoint::{
    EndpointServiceFn, EndpointServiceFnWrapper, IntoEndpointService, IntoEndpointServiceWithState,
    MapResponseServie, StaticService, extract, response,
};

pub mod k8s;
#[doc(inline)]
pub use k8s::{k8s_health, k8s_health_builder};

mod router;
#[doc(inline)]
pub use router::Router;
