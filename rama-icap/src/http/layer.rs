//! HTTP request and response adaptation through an ICAP service.

mod endpoint;
mod headers;
mod service;

pub use endpoint::ServiceEndpoint;
pub use service::{Adaptation, AdaptationLayer, ReqmodResult, RespmodResult};

#[cfg(test)]
use headers::{normalize_request_authority, sanitize_http_headers};
#[cfg(test)]
use service::validate_success_status;
#[cfg(test)]
mod tests;
