//! Middleware for removing headers from requests and responses.
//!
//! See [request] and [response] for more details.

use rama_core::telemetry::tracing;
use rama_http_headers::{Connection, HeaderMapExt};
use rama_utils::str::{any_submatch_ignore_ascii_case, starts_with_ignore_ascii_case};

use crate::{HeaderMap, HeaderName, HeaderValue, header};

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
        .filter(|key| starts_with_ignore_ascii_case(key, prefix))
        .cloned()
        .collect();

    for key in keys {
        headers.remove(key);
    }
}

fn remove_headers_by_exact_name(headers: &mut HeaderMap, name: &HeaderName) {
    headers.remove(name);
}

/// Remove hop by hop headers from an outbound request.
///
/// This function applies the rules from RFC 9110 for hop by hop headers
/// before forwarding a request to another hop.
///
/// This should be called when acting as a forward proxy, reverse proxy,
/// or gateway that forwards requests to an upstream server.
pub fn remove_hop_by_hop_request_headers(headers: &mut HeaderMap) {
    while let Some(c) = headers.typed_get::<Connection>() {
        for header in c.iter_headers() {
            while headers.remove(header).is_some() {
                tracing::trace!(
                    "removed hop-by-hop request header listed in Connection header for name: {header}"
                );
            }
        }
        _ = headers.remove(header::CONNECTION);
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

/// Remove hop by hop headers from an outbound response.
///
/// This function applies the rules from RFC 9110 for hop by hop headers
/// before forwarding a response to a downstream client.
///
/// This should be called when relaying responses received from an upstream
/// server to a client.
pub fn remove_hop_by_hop_response_headers(headers: &mut HeaderMap) {
    while let Some(c) = headers.typed_get::<Connection>() {
        for header in c.iter_headers() {
            while headers.remove(header).is_some() {
                tracing::trace!(
                    "removed hop-by-hop response header listed in Connection header for name: {header}"
                );
            }
        }
        _ = headers.remove(header::CONNECTION);
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

/// Remove headers that are illegal on an HTTP/2 (or HTTP/3) request.
///
/// HTTP/2 forbids connection-specific (hop-by-hop) header fields: the only
/// exception is `TE`, and even then only with the value `trailers`
/// (RFC 9113 §8.2.2). This removes the connection-specific headers (including
/// any named by a `Connection` header), plus `Host` (replaced by the
/// `:authority` pseudo-header) and `Sec-WebSocket-Key` (unused in the HTTP/2
/// WebSocket handshake per RFC 8441 §5.1).
pub fn remove_illegal_h2_request_headers(headers: &mut HeaderMap) {
    while let Some(c) = headers.typed_get::<Connection>() {
        for header in c.iter_headers() {
            while headers.remove(header).is_some() {
                tracing::trace!(
                    header = %header,
                    "removed connection-specific request header listed in Connection header for name"
                );
            }
        }
        _ = headers.remove(header::CONNECTION);
    }
    for header in [
        &header::CONNECTION,
        &header::PROXY_CONNECTION,
        &header::KEEP_ALIVE,
        &header::TRANSFER_ENCODING,
        &header::UPGRADE,
        &header::SEC_WEBSOCKET_KEY,
        &header::HOST,
    ] {
        while headers.remove(header).is_some() {
            tracing::trace!(
                header = %header,
                "removed illegal (~http1) header from h2 request for name"
            );
        }
    }

    // `TE` is the one connection-specific header permitted in HTTP/2 and HTTP/3, but
    // only with the exact value `trailers` (RFC 9113 §8.2.2). Strip any other use.
    let te_is_legal = headers
        .get_all(header::TE)
        .iter()
        .all(|v| v.as_bytes().trim_ascii().eq_ignore_ascii_case(b"trailers"));
    if !te_is_legal {
        while headers.remove(header::TE).is_some() {
            tracing::trace!(
                "removed illegal TE header (only `TE: trailers` is valid) from h2 request"
            );
        }
    }
}

/// Remove headers that are illegal on an HTTP/2 (or HTTP/3) response.
///
/// HTTP/2 forbids connection-specific (hop-by-hop) header fields (RFC 9113 §8.2.2).
/// This removes only those headers (including any named by a `Connection` header) so
/// that a response can be (re)serialized over HTTP/2.
///
/// Unlike [`remove_hop_by_hop_response_headers`], this is a pure protocol-legality
/// operation, not a proxy forwarding policy: it leaves headers that are perfectly
/// legal in HTTP/2 such as `Trailer` and `Proxy-Authenticate`. Use this when merely
/// changing a message's HTTP version (which may happen on the same server, with no
/// downstream hop), and use `remove_hop_by_hop_response_headers` when actually
/// relaying a response across a connection hop.
pub fn remove_illegal_h2_response_headers(headers: &mut HeaderMap) {
    while let Some(c) = headers.typed_get::<Connection>() {
        for header in c.iter_headers() {
            while headers.remove(header).is_some() {
                tracing::trace!(
                    header = %header,
                    "removed connection-specific response header listed in Connection header for name"
                );
            }
        }
        _ = headers.remove(header::CONNECTION);
    }
    for header in [
        &header::CONNECTION,
        &header::PROXY_CONNECTION,
        &header::KEEP_ALIVE,
        &header::TRANSFER_ENCODING,
        &header::UPGRADE,
    ] {
        while headers.remove(header).is_some() {
            tracing::trace!(
                header = %header,
                "removed illegal (~http1) header from h2 response for name"
            );
        }
    }
}

/// Remove sensitive headers from an outbound request.
///
/// This function removes headers that may contain credentials,
/// authentication material, or security tokens.
///
/// This is typically used when:
/// - Forwarding requests across trust boundaries
/// - Logging or persisting request metadata
/// - Sending requests to untrusted upstreams
pub fn remove_sensitive_request_headers(headers: &mut HeaderMap) {
    for header in [
        &header::AUTHORIZATION,
        &header::PROXY_AUTHORIZATION,
        &header::COOKIE,
    ] {
        while headers.remove(header).is_some() {
            tracing::trace!("removed sensitive request header for name: {header}");
        }
    }
    remove_headers_if(
        headers,
        |name, _value| is_sensitive_header_name(name),
        "sensitive request header",
    );
}

/// Remove sensitive headers from an outbound response.
///
/// This function removes headers that may expose session identifiers
/// or user specific state.
///
/// This is typically used when responses should not propagate
/// authentication state or tracking information.
pub fn remove_sensitive_response_headers(headers: &mut HeaderMap) {
    for header in [&header::SET_COOKIE] {
        while headers.remove(header).is_some() {
            tracing::trace!("removed sensitive response header for name: {header}");
        }
    }
}

/// Remove headers that describe or affect payload framing.
///
/// This function removes headers that are no longer valid when the
/// payload has been transformed, reencoded, or regenerated.
///
/// This should be called after modifying a request or response body,
/// such as decompression, aggregation, or content rewriting.
pub fn remove_payload_metadata_headers(headers: &mut HeaderMap) {
    for header in [
        &header::CONTENT_ENCODING,
        &header::TRANSFER_ENCODING,
        &header::ACCEPT_RANGES,
        &header::CONTENT_LENGTH,
    ] {
        while headers.remove(header).is_some() {
            tracing::trace!("removed payload header for name: {header}");
        }
    }
}

/// Remove cache validation and conditional request headers.
///
/// These headers influence conditional requests and partial responses.
/// They are typically removed when the proxy may change representation
/// semantics or body bytes, or when the proxy wants to force a fresh
/// upstream response.
///
/// Call this when you rewrite, decompress, aggregate, or otherwise
/// transform the response body, or when you want to disable conditional
/// requests through this hop.
pub fn remove_cache_validation_request_headers(headers: &mut HeaderMap) {
    for header in [
        &header::IF_NONE_MATCH,
        &header::IF_MODIFIED_SINCE,
        &header::IF_MATCH,
        &header::IF_UNMODIFIED_SINCE,
        &header::IF_RANGE,
        &header::RANGE,
    ] {
        while headers.remove(header).is_some() {
            tracing::trace!("removed cache validation request header for name: {header}");
        }
    }
}

/// Remove cache validators and representation range metadata from a response.
///
/// These headers describe validators or byte range capabilities of the
/// response representation. They may become invalid if the response body
/// is transformed, reencoded, or regenerated.
///
/// Call this after changing the response body, changing content encoding,
/// or otherwise making the downstream representation differ from the
/// upstream representation.
pub fn remove_cache_validation_response_headers(headers: &mut HeaderMap) {
    for header in [
        &header::ETAG,
        &header::LAST_MODIFIED,
        &header::ACCEPT_RANGES,
        &header::CONTENT_RANGE,
    ] {
        while headers.remove(header).is_some() {
            tracing::trace!("removed cache validation response header for name: {header}");
        }
    }
}

/// Remove caching policy headers.
///
/// These headers control how requests and responses may be cached by
/// clients and intermediaries. Removing them can be useful when the proxy
/// wants to enforce its own caching policy or prevent caching entirely.
///
/// Call this when you want to disable or normalize caching behavior
/// across a trust boundary.
pub fn remove_cache_policy_headers(headers: &mut HeaderMap) {
    for header in [
        &header::CACHE_CONTROL,
        &header::PRAGMA,
        &header::EXPIRES,
        &header::AGE,
        &header::WARNING,
    ] {
        while headers.remove(header).is_some() {
            tracing::trace!("removed cache policy header for name: {header}");
        }
    }
}

#[inline(always)]
fn is_sensitive_header_name(name: &HeaderName) -> bool {
    any_submatch_ignore_ascii_case(
        name.as_str(),
        ["api-key", "auth-token", "access-token", "security-token"],
    )
}

fn remove_headers_if<F>(headers: &mut HeaderMap, mut remove: F, log_context: &str)
where
    F: FnMut(&HeaderName, &HeaderValue) -> bool,
{
    loop {
        let name_to_remove: Option<HeaderName> = headers
            .iter()
            .find_map(|(name, value)| remove(name, value).then(|| name.clone()));

        let Some(name) = name_to_remove else { break };

        while headers.remove(&name).is_some() {
            tracing::trace!("{log_context}: removed header: {name}");
        }
    }
}
