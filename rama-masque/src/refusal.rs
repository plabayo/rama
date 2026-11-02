//! HTTP refusal rendering shared by MASQUE services.
use rama_http::{
    Body, HeaderValue, Request, Response, StatusCode, Version, header,
    headers::{HeaderMapExt as _, ProxyErrorType, ProxyStatus, ProxyStatusEntry},
};
use rama_net::address::HostWithOptPort;
use std::sync::Arc;

pub(crate) fn admission_error(refused: &crate::limits::Refused) -> ProxyErrorType {
    match refused {
        crate::limits::Refused::LimitReached => ProxyErrorType::ConnectionLimitReached,
        crate::limits::Refused::NoPrincipal => ProxyErrorType::HttpRequestDenied,
        crate::limits::Refused::Keyer => ProxyErrorType::ProxyInternalError,
    }
}

pub(crate) fn response(
    version: Version,
    status: StatusCode,
    error: Option<ProxyErrorType>,
    name: Option<&str>,
) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    if let Some(error) = error
        && let Some(name) = name
    {
        response
            .headers_mut()
            .typed_insert(ProxyStatus::new(ProxyStatusEntry::error(name, error)));
    }
    if version == Version::HTTP_11 {
        // Optimistic tunnel bytes must not become another HTTP request.
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

pub(crate) fn addressed_host<B>(request: &Request<B>) -> Option<Arc<str>> {
    if let Some(host) = request.uri().host() {
        return Some(host.to_string().into());
    }
    let host = request.headers().get(header::HOST)?.to_str().ok()?;
    let host = HostWithOptPort::try_from(host).ok()?.host;
    Some(host.to_string().into())
}
