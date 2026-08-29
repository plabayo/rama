//! HTTP request and response adaptation through an ICAP service.

mod endpoint;
pub(in crate::http) mod headers;
mod service;

pub use endpoint::{ServiceEndpoint, ServiceEndpointError, ServiceEndpointRequestError};
pub use service::{
    Adaptation, AdaptationLayer, NoOptionsDiscovery, ReqmodResult, RespmodResult,
    UnsupportedMethodPolicy,
};

#[cfg(test)]
use crate::http::headers::SanitizedHttpHead;
#[cfg(test)]
use headers::normalize_request_authority;
#[cfg(test)]
use service::{effective_policy, request_target_extension, validate_success_status};
#[cfg(test)]
mod tests;
