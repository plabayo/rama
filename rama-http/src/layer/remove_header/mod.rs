//! Middleware for removing headers from requests and responses.
//!
//! See [request] and [response] for more details.

use rama_core::telemetry::tracing;
use rama_http_headers::{Connection, HeaderMapExt};

use crate::{HeaderMap, HeaderName, header};

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
        .filter(|key| {
            let s = key.as_str();
            s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix)
        })
        .cloned()
        .collect();

    for key in keys {
        headers.remove(key);
    }
}

fn remove_headers_by_exact_name(headers: &mut HeaderMap, name: &HeaderName) {
    headers.remove(name);
}

fn remove_hop_by_hop_request_headers(headers: &mut HeaderMap) {
    while let Some(c) = headers.typed_get::<Connection>() {
        for header in c.iter_headers() {
            while headers.remove(header).is_some() {
                tracing::trace!(
                    "removed hop-by-hop request header listed in Connection header for name: {header}"
                );
            }
        }
        let _ = headers.remove(header::CONNECTION);
    }
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
        while headers.remove(header).is_some() {
            tracing::trace!("removed hop-by-hop request header for name: {header}");
        }
    }
}

fn remove_hop_by_hop_response_headers(headers: &mut HeaderMap) {
    while let Some(c) = headers.typed_get::<Connection>() {
        for header in c.iter_headers() {
            while headers.remove(header).is_some() {
                tracing::trace!(
                    "removed hop-by-hop response header listed in Connection header for name: {header}"
                );
            }
        }
        let _ = headers.remove(header::CONNECTION);
    }
    for header in [
        &header::CONNECTION,
        &header::KEEP_ALIVE,
        &header::PROXY_AUTHENTICATE,
        &header::TRAILER,
        &header::TRANSFER_ENCODING,
        &header::UPGRADE,
    ] {
        while headers.remove(header).is_some() {
            tracing::trace!("removed hop-by-hop response header for name: {header}");
        }
    }
}
