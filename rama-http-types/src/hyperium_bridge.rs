//! Lossless-ish bridges between the native `rama-net` `Uri`/`Version` types
//! (now the public `rama_http_types::{Uri, Version}`) and the hyperium `http`
//! crate equivalents still used by the underlying `http::{Request, Response}`
//! machinery.
//!
//! These exist solely so the `From`/`Into` conversions between
//! `rama_http_types::{Request, Response}` and their hyperium counterparts keep
//! compiling after the URI/Version flip. They are an internal implementation
//! detail.

use crate::dep::hyperium::http;
use crate::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};

/// Convert a vendored [`Method`] into the hyperium `http::Method`.
///
/// Both are byte-identical forks, so this round-trips losslessly through the
/// method bytes (standard methods hit the fast path; extension methods copy).
pub(crate) fn method_to_hyperium(m: &Method) -> http::Method {
    http::Method::from_bytes(m.as_str().as_bytes()).unwrap_or(http::Method::GET)
}

/// Convert a hyperium `http::Method` into the vendored [`Method`].
pub(crate) fn method_from_hyperium(m: &http::Method) -> Method {
    Method::from_bytes(m.as_str().as_bytes()).unwrap_or(Method::GET)
}

/// Convert a vendored [`StatusCode`] into the hyperium `http::StatusCode`.
pub(crate) fn status_to_hyperium(s: StatusCode) -> http::StatusCode {
    http::StatusCode::from_u16(s.as_u16()).unwrap_or(http::StatusCode::OK)
}

/// Convert a hyperium `http::StatusCode` into the vendored [`StatusCode`].
pub(crate) fn status_from_hyperium(s: http::StatusCode) -> StatusCode {
    StatusCode::from_u16(s.as_u16()).unwrap_or(StatusCode::OK)
}

/// Convert a vendored [`HeaderMap`] into the hyperium `http::HeaderMap`.
///
/// Both are byte-identical forks; this round-trips each name/value through its
/// bytes, preserving multi-value ordering and the sensitivity flag.
///
/// Temporarily `pub` (doc-hidden, re-exported at the crate root) so the
/// `http-body`/`multer` trailer boundaries in rama-http/grpc/http-core can
/// bridge until `http-body` is forked.
pub fn headers_to_hyperium(headers: HeaderMap) -> http::HeaderMap {
    let mut out = http::HeaderMap::with_capacity(headers.len());
    let mut last: Option<http::header::HeaderName> = None;
    for (name, value) in headers {
        let mut hv = http::header::HeaderValue::from_bytes(value.as_bytes())
            .unwrap_or_else(|_| http::header::HeaderValue::from_static(""));
        hv.set_sensitive(value.is_sensitive());
        match name {
            Some(name) => {
                let name = http::header::HeaderName::from_bytes(name.as_str().as_bytes())
                    .expect("vendored header name is valid");
                out.append(name.clone(), hv);
                last = Some(name);
            }
            // `None` name repeats the previous name (multi-value).
            None => {
                if let Some(name) = &last {
                    out.append(name.clone(), hv);
                }
            }
        }
    }
    out
}

/// Convert a hyperium `http::HeaderMap` into the vendored [`HeaderMap`].
///
/// See [`headers_to_hyperium`] — temporary trailer-boundary bridge.
pub fn headers_from_hyperium(headers: http::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(headers.len());
    let mut last: Option<HeaderName> = None;
    for (name, value) in headers {
        let mut hv = HeaderValue::from_bytes(value.as_bytes())
            .unwrap_or_else(|_| HeaderValue::from_static(""));
        hv.set_sensitive(value.is_sensitive());
        match name {
            Some(name) => {
                let name = HeaderName::from_bytes(name.as_str().as_bytes())
                    .expect("hyperium header name is valid");
                out.append(name.clone(), hv);
                last = Some(name);
            }
            None => {
                if let Some(name) = &last {
                    out.append(name.clone(), hv);
                }
            }
        }
    }
    out
}

/// Convert a native [`Version`] into the hyperium `http::Version`.
pub(crate) fn version_to_hyperium(v: Version) -> http::Version {
    match v {
        Version::HTTP_09 => http::Version::HTTP_09,
        Version::HTTP_10 => http::Version::HTTP_10,
        Version::HTTP_11 => http::Version::HTTP_11,
        Version::HTTP_2 => http::Version::HTTP_2,
        Version::HTTP_3 => http::Version::HTTP_3,
    }
}

/// Convert a hyperium `http::Version` into the native [`Version`].
pub(crate) fn version_from_hyperium(v: http::Version) -> Version {
    match v {
        http::Version::HTTP_09 => Version::HTTP_09,
        http::Version::HTTP_10 => Version::HTTP_10,
        http::Version::HTTP_2 => Version::HTTP_2,
        http::Version::HTTP_3 => Version::HTTP_3,
        // HTTP/1.1 plus any future/unknown hyperium version.
        _ => Version::HTTP_11,
    }
}

/// Convert a native [`Uri`](crate::Uri) into the hyperium `http::Uri`.
///
/// Round-trips through the canonical string form. A native `Uri` is always a
/// valid RFC-3986 URI, so the reparse only fails for the HTTP asterisk-form
/// (`*`), which has no `http::Uri` representation other than `*` itself —
/// handled explicitly.
pub(crate) fn uri_to_hyperium(uri: &crate::Uri) -> http::Uri {
    if uri.is_asterisk() {
        return http::Uri::from_static("*");
    }
    let s = uri.as_str();
    http::Uri::try_from(s.as_ref()).unwrap_or_else(|_| http::Uri::from_static("/"))
}

/// Convert a hyperium `http::Uri` into the native [`Uri`](crate::Uri).
///
/// Round-trips through the string form. Falls back to the root path (`/`) if
/// the (already-valid) hyperium URI somehow fails native parsing.
pub(crate) fn uri_from_hyperium(uri: &http::Uri) -> crate::Uri {
    if *uri == http::Uri::from_static("*") {
        return crate::Uri::from_static("*");
    }
    let s = uri.to_string();
    crate::Uri::parse(s.as_str()).unwrap_or_else(|_| crate::Uri::from_static("/"))
}
