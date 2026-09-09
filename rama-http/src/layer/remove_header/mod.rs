//! Middleware for removing headers from requests and responses.
//!
//! For an HTTP intermediary, the context-aware hop-by-hop pair is the
//! recommended default. When using transform middleware, place the request
//! layer outside it and the response layer inside it. This consumes fields
//! belonging to each incoming hop before the middleware handles the message,
//! while fields originated by the middleware remain available to the next
//! hop:
//!
//! ```
//! use rama_core::{Layer, service::service_fn};
//! use rama_http::{Body, Request, Response};
//! use rama_http::layer::remove_header::{
//!     RemoveRequestHeaderLayer, RemoveResponseHeaderLayer,
//! };
//!
//! let client = service_fn(async |_request: Request| {
//!     Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
//! });
//! let proxy = (
//!     RemoveRequestHeaderLayer::hop_by_hop(),
//!     // transform middleware goes here
//!     RemoveResponseHeaderLayer::hop_by_hop(),
//! ).into_layer(client);
//! # let _ = proxy;
//! ```
//!
//! Use the `hop_by_hop_strict` layer constructors only when upgrade and
//! trailer capabilities are intentionally unsupported. See [request] and
//! [response] for the other removal policies.

use rama_core::bytes::BytesMut;
use rama_core::telemetry::tracing;
use rama_utils::str::{any_submatch_ignore_ascii_case, starts_with_ignore_ascii_case};

use crate::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode, Version, header};

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

#[doc(inline)]
pub use rama_http_types::header::hop_by_hop::{
    HopByHopHeaderContext, HopByHopResponseDisposition, connection_header_names,
    hop_by_hop_header_names, remove_hop_by_hop_headers, remove_hop_by_hop_request_headers,
    remove_hop_by_hop_response_headers, sanitize_hop_by_hop_request_headers,
    sanitize_hop_by_hop_response_headers,
};
pub use rama_http_types::header::proxy_auth::{
    remove_proxy_auth_request_headers, remove_proxy_auth_response_headers,
};

/// Sanitize a response for forwarding to the next hop.
///
/// An invalid or uncorrelated protocol upgrade is replaced with a `502 Bad
/// Gateway` response. HTTP/1.1 responses also instruct the next hop to close,
/// because forwarding a stripped `101 Switching Protocols` response would
/// desynchronize the connection.
pub fn sanitize_hop_by_hop_response<B>(
    response: &mut Response<B>,
    request_context: &HopByHopHeaderContext,
) {
    let disposition = sanitize_hop_by_hop_response_headers(response, request_context);
    if disposition != HopByHopResponseDisposition::RejectUpgrade {
        return;
    }

    let version = response.version();
    tracing::debug!(
        http.response.status = %response.status(),
        http.version = %version,
        response.header_count = response.headers().len(),
        "replacing rejected HTTP protocol upgrade with a bad gateway response"
    );
    *response.status_mut() = StatusCode::BAD_GATEWAY;
    response.headers_mut().clear();
    if version == Version::HTTP_11 {
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
}

/// Remove request headers that describe the forwarding chain or client address.
///
/// Unlike hop-by-hop headers, these fields are normally preserved or appended to by
/// intermediaries. Remove them explicitly when crossing a trust boundary or before
/// deriving fresh forwarding metadata. This includes `Forwarded`, `Via`, the
/// `X-Forwarded-*` family, and common client-IP aliases.
///
/// This function only modifies the supplied header map. Forwarding information
/// already parsed into request extensions is unaffected.
pub fn remove_forwarding_metadata_request_headers(headers: &mut HeaderMap) {
    for header in [
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
            tracing::trace!("removed forwarding metadata request header for name: {header}");
        }
    }
}

/// Coalesce multiple `Cookie` request header fields into a single field.
///
/// Values retain their original order and are joined using `; `, matching
/// [RFC 6265 section 5.4](https://github.com/plabayo/rama/blob/main/rama-http/specifications/rfc6265.txt#section-5.4)
/// serialization and [RFC 9113 section 8.2.3](https://github.com/plabayo/rama/blob/main/rama-http-core/specifications/rfc9113.txt#section-8.2.3)
/// reassembly rules.
pub fn coalesce_cookie_headers(headers: &mut HeaderMap) {
    let crate::header::Entry::Occupied(mut cookie_headers) = headers.entry(header::COOKIE) else {
        return;
    };

    let Some((bytes_count, header_count, is_sensitive)) = cookie_headers
        .iter()
        .map(|value| (value.as_bytes().len(), 1usize, value.is_sensitive()))
        .reduce(|a, b| (a.0 + b.0, a.1 + b.1, a.2 || b.2))
    else {
        return;
    };
    if header_count <= 1 {
        return;
    }

    let mut buffer = BytesMut::with_capacity(bytes_count + ((header_count - 1) * 2));
    let mut header_values = cookie_headers.iter();
    if let Some(header_value) = header_values.next() {
        buffer.extend_from_slice(header_value.as_bytes());
    }
    for header_value in header_values {
        buffer.extend_from_slice(b"; ");
        buffer.extend_from_slice(header_value.as_bytes());
    }

    // Every input is already a valid HeaderValue and the separator is valid as well.
    let Ok(mut header_value) = HeaderValue::from_maybe_shared(buffer.freeze()) else {
        tracing::error!("failed to coalesce valid Cookie header values");
        return;
    };
    header_value.set_sensitive(is_sensitive);
    cookie_headers.insert(header_value);
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
    for header in connection_header_names(headers) {
        while headers.remove(&header).is_some() {
            tracing::trace!(
                %header,
                "removed connection-specific request header listed in Connection header for name"
            );
        }
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
    for header in connection_header_names(headers) {
        while headers.remove(&header).is_some() {
            tracing::trace!(
                %header,
                "removed connection-specific response header listed in Connection header for name"
            );
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Request, Response, StatusCode, Version};

    fn values<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Vec<&'a [u8]> {
        headers
            .get_all(name)
            .iter()
            .map(HeaderValue::as_bytes)
            .collect()
    }

    const FORWARDING_METADATA_HEADERS: [&str; 10] = [
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "forwarded",
        "via",
        "cf-connecting-ip",
        "x-real-ip",
        "x-client-ip",
        "client-ip",
        "true-client-ip",
    ];

    #[test]
    fn hop_by_hop_request_cleanup_preserves_forwarding_metadata() {
        let mut headers = HeaderMap::new();
        for name in FORWARDING_METADATA_HEADERS {
            headers.append(name, HeaderValue::from_static("metadata"));
        }
        headers.insert(header::CONNECTION, HeaderValue::from_static("x-hop"));
        headers.insert("x-hop", HeaderValue::from_static("remove me"));
        headers.insert(header::KEEP_ALIVE, HeaderValue::from_static("timeout=5"));
        headers.insert(
            header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic dGVzdA=="),
        );

        remove_hop_by_hop_request_headers(&mut headers);

        for name in FORWARDING_METADATA_HEADERS {
            assert!(
                headers.contains_key(name),
                "expected {name} to be preserved"
            );
        }
        for name in ["connection", "x-hop", "keep-alive"] {
            assert!(!headers.contains_key(name), "expected {name} to be removed");
        }
        assert!(headers.contains_key(header::PROXY_AUTHORIZATION));
    }

    #[test]
    fn hop_by_hop_request_cleanup_removes_metadata_named_by_connection() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("forwarded"));
        headers.insert(header::FORWARDED, HeaderValue::from_static("for=192.0.2.1"));
        headers.insert(header::VIA, HeaderValue::from_static("1.1 proxy"));

        remove_hop_by_hop_request_headers(&mut headers);

        assert!(!headers.contains_key(header::FORWARDED));
        assert!(headers.contains_key(header::VIA));
    }

    #[test]
    fn strict_cleanup_removes_valid_nominations_beside_obs_text() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_bytes(b"close, x-hop, \xff").unwrap(),
        );
        headers.insert("x-hop", HeaderValue::from_static("secret"));

        remove_hop_by_hop_headers(&mut headers);

        assert!(headers.is_empty());
    }

    #[test]
    fn strict_cleanup_is_consistent_and_preserves_proxy_auth() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic"),
        );
        remove_hop_by_hop_request_headers(&mut request_headers);
        assert!(request_headers.contains_key(header::PROXY_AUTHENTICATE));

        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic dGVzdA=="),
        );
        response_headers.insert(header::PROXY_CONNECTION, HeaderValue::from_static("close"));
        response_headers.insert(header::TE, HeaderValue::from_static("trailers"));
        remove_hop_by_hop_response_headers(&mut response_headers);
        assert!(response_headers.contains_key(header::PROXY_AUTHORIZATION));
        assert!(!response_headers.contains_key(header::PROXY_CONNECTION));
        assert!(!response_headers.contains_key(header::TE));

        remove_hop_by_hop_headers(&mut response_headers);
        assert_eq!(response_headers.len(), 1);
        assert!(response_headers.contains_key(header::PROXY_AUTHORIZATION));
    }

    #[test]
    fn proxy_auth_cleanup_is_explicit() {
        let mut request = HeaderMap::new();
        request.insert(
            header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic dGVzdA=="),
        );
        remove_proxy_auth_request_headers(&mut request);
        assert!(request.is_empty());

        let mut response = HeaderMap::new();
        response.insert(
            header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic"),
        );
        response.insert(
            header::PROXY_AUTHENTICATION_INFO,
            HeaderValue::from_static("nextnonce=abc"),
        );
        remove_proxy_auth_response_headers(&mut response);
        assert!(response.is_empty());
    }

    #[test]
    fn request_sanitizer_preserves_only_next_hop_metadata() {
        let mut request = Request::builder()
            .version(Version::HTTP_11)
            .header("connection", "keep-alive, UpGrAdE, x-hop")
            .header("upgrade", "WebSocket, example/1")
            .header("keep-alive", "timeout=5")
            .header("trailer", "x-checksum")
            .header("x-hop", "secret")
            .header("proxy-authorization", "Basic dGVzdA==")
            .header("accept", "application/json")
            .body(())
            .unwrap();

        let context = sanitize_hop_by_hop_request_headers(&mut request);

        assert_eq!(values(request.headers(), &header::CONNECTION), [b"UpGrAdE"]);
        assert_eq!(
            values(request.headers(), &header::UPGRADE),
            [b"WebSocket, example/1"]
        );
        assert_eq!(request.headers()[header::TRAILER], "x-checksum");
        assert!(!request.headers().contains_key(header::KEEP_ALIVE));
        assert!(!request.headers().contains_key("x-hop"));
        assert!(request.headers().contains_key(header::PROXY_AUTHORIZATION));
        assert_eq!(request.headers()[header::ACCEPT], "application/json");
        assert_eq!(
            context.nominated_headers(),
            [
                header::KEEP_ALIVE,
                header::UPGRADE,
                HeaderName::from_static("x-hop")
            ]
        );
    }

    #[test]
    fn invalid_or_non_http11_upgrade_is_not_preserved() {
        for (version, upgrade) in [
            (Version::HTTP_10, "websocket"),
            (Version::HTTP_2, "websocket"),
            (Version::HTTP_3, "websocket"),
            (Version::HTTP_11, "websocket, invalid protocol"),
        ] {
            let mut request = Request::builder()
                .version(version)
                .header("connection", "upgrade")
                .header("upgrade", upgrade)
                .body(())
                .unwrap();

            let _context = sanitize_hop_by_hop_request_headers(&mut request);

            assert!(request.headers().is_empty(), "version: {version:?}");
        }
    }

    #[test]
    fn malformed_connection_does_not_preserve_upgrade() {
        let mut request = Request::builder()
            .version(Version::HTTP_11)
            .body(())
            .unwrap();
        request.headers_mut().insert(
            header::CONNECTION,
            HeaderValue::from_bytes(b"upgrade, \xff").unwrap(),
        );
        request
            .headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static("websocket"));

        let _context = sanitize_hop_by_hop_request_headers(&mut request);

        assert!(request.headers().is_empty());
    }

    #[test]
    fn connection_nomination_suppresses_trailer_restoration() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("trailer"));
        headers.insert(header::TRAILER, HeaderValue::from_static("x-checksum"));

        let context = HopByHopHeaderContext::take(&mut headers, Version::HTTP_11);
        context.restore_response(&mut headers, Version::HTTP_11, &[]);

        assert!(headers.is_empty());
    }

    #[test]
    fn response_sanitizer_requires_matching_request_and_switch_status() {
        let request = Request::builder()
            .version(Version::HTTP_11)
            .header("connection", "upgrade")
            .header("upgrade", "websocket, example/1")
            .body(())
            .unwrap();
        let request_context = HopByHopHeaderContext::capture(request.headers(), request.version());

        for (status, protocol, preserved) in [
            (StatusCode::SWITCHING_PROTOCOLS, "WebSocket", true),
            (StatusCode::SWITCHING_PROTOCOLS, "example/1", true),
            (
                StatusCode::SWITCHING_PROTOCOLS,
                "WebSocket, example/1",
                true,
            ),
            (StatusCode::SWITCHING_PROTOCOLS, "example/2", false),
            (
                StatusCode::SWITCHING_PROTOCOLS,
                "WebSocket, example/2",
                false,
            ),
            (StatusCode::OK, "websocket", false),
        ] {
            let mut response = Response::builder()
                .version(Version::HTTP_11)
                .status(status)
                .header("connection", "keep-alive, upgrade, x-hop")
                .header("upgrade", protocol)
                .header("keep-alive", "timeout=5")
                .header("x-hop", "secret")
                .header("proxy-authenticate", "Basic")
                .body(())
                .unwrap();

            let disposition = sanitize_hop_by_hop_response_headers(&mut response, &request_context);

            assert_eq!(response.headers().contains_key(header::UPGRADE), preserved);
            assert_eq!(
                response.headers().contains_key(header::CONNECTION),
                preserved
            );
            assert!(!response.headers().contains_key(header::KEEP_ALIVE));
            assert!(!response.headers().contains_key("x-hop"));
            assert!(response.headers().contains_key(header::PROXY_AUTHENTICATE));
            assert_eq!(
                disposition,
                if status == StatusCode::SWITCHING_PROTOCOLS && !preserved {
                    HopByHopResponseDisposition::RejectUpgrade
                } else {
                    HopByHopResponseDisposition::Forward
                }
            );
        }
    }

    #[test]
    fn unsolicited_switching_protocols_upgrade_is_removed() {
        let request_context = HopByHopHeaderContext::default();
        let mut response = Response::builder()
            .version(Version::HTTP_11)
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .body(())
            .unwrap();

        let disposition = sanitize_hop_by_hop_response_headers(&mut response, &request_context);

        assert!(response.headers().is_empty());
        assert_eq!(disposition, HopByHopResponseDisposition::RejectUpgrade);
    }

    #[test]
    fn forwarding_metadata_cleanup_is_independent() {
        let mut headers = HeaderMap::new();
        for name in FORWARDING_METADATA_HEADERS {
            headers.append(name, HeaderValue::from_static("metadata"));
        }
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));

        remove_forwarding_metadata_request_headers(&mut headers);

        for name in FORWARDING_METADATA_HEADERS {
            assert!(!headers.contains_key(name), "expected {name} to be removed");
        }
        assert!(headers.contains_key(header::CONNECTION));
    }

    #[test]
    fn coalesce_cookies_preserves_order_and_sensitivity() {
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("a=1"));
        let mut sensitive = HeaderValue::from_static("b=2");
        sensitive.set_sensitive(true);
        headers.append(header::COOKIE, sensitive);

        coalesce_cookie_headers(&mut headers);

        let cookies: Vec<_> = headers.get_all(header::COOKIE).iter().collect();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].as_bytes(), b"a=1; b=2");
        assert!(cookies[0].is_sensitive());
    }
}
