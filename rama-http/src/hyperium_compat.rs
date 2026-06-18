//! Temporary hyperium-`http` compatibility shims.
//!
//! `http-body` trailers and the external `multer` crate still expose the
//! hyperium `http::HeaderMap`, whereas rama now owns a vendored
//! [`HeaderMap`](crate::HeaderMap). These convert at those boundaries. The
//! `http-body` ones are removed once that crate is forked (Phase 3); the
//! `multer` one stays until/unless multipart parsing is replaced.

use crate::{HeaderMap, HeaderName, HeaderValue};

/// Convert a borrowed hyperium `http::HeaderMap` into the vendored
/// [`HeaderMap`], preserving multi-value ordering and the sensitivity flag.
pub(crate) fn rama_headers_from_http(headers: &http::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, http_value) in headers {
        let Ok(name) = HeaderName::from_bytes(name.as_str().as_bytes()) else {
            continue;
        };
        let Ok(mut value) = HeaderValue::from_bytes(http_value.as_bytes()) else {
            continue;
        };
        value.set_sensitive(http_value.is_sensitive());
        out.append(name, value);
    }
    out
}
