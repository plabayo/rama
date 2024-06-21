//! Middleware for removing headers from requests and responses.
//!
//! See [request] and [response] for more details.

use crate::http::{header, HeaderMap};

pub mod request;
pub mod response;

#[doc(inline)]
pub use self::{
    request::{RemoveRequestHeader, RemoveRequestHeaderLayer},
    response::{RemoveResponseHeader, RemoveResponseHeaderLayer},
};

fn remove_headers_by_prefix(headers: &mut HeaderMap, prefix: &str) {
    let keys: Vec<_> = headers
        .keys()
        // this assumes that `HeaderName::as_str` returns as lowercase
        .filter(|key| key.as_str().starts_with(prefix))
        .cloned()
        .collect();

    for key in keys {
        headers.remove(key);
    }
}

fn remove_headers_by_exact_name(headers: &mut HeaderMap, name: &str) {
    headers.remove(name);
}

fn remove_hop_by_hop_request_headers(headers: &mut HeaderMap) {
    for header in [
        &header::CONNECTION,
        &header::PROXY_CONNECTION,
        &header::PROXY_AUTHORIZATION,
        &header::TE,
        &header::TRAILER,
        &header::TRANSFER_ENCODING,
        &header::UPGRADE,
        &header::X_FORWARDED_FOR,
        &header::X_FORWARDED_HOST,
        &header::X_FORWARDED_PROTO,
        &header::FORWARDED,
        &header::VIA,
        &header::CF_CONNECTING_IP,
        &header::X_REAL_IP,
        &header::X_CLIENT_IP,
        &header::CLIENT_IP,
        &header::TRUE_CLIENT_IP,
    ] {
        headers.remove(header);
    }
}

fn remove_hop_by_hop_response_headers(headers: &mut HeaderMap) {
    for header in [
        &header::CONNECTION,
        &header::KEEP_ALIVE,
        &header::PROXY_AUTHENTICATE,
        &header::TRAILER,
        &header::TRANSFER_ENCODING,
        &header::UPGRADE,
    ] {
        headers.remove(header);
    }
}
