//! Lossless-ish bridges between the native `rama-net` `Uri`/`Version` types
//! (now the public `rama_http_types::{Uri, Version}`) and the hyperium `http`
//! crate equivalents still used by the underlying `http::{Request, Response}`
//! machinery.
//!
//! These exist solely so the `From`/`Into` conversions between
//! `rama_http_types::{Request, Response}` and their hyperium counterparts keep
//! compiling after the URI/Version flip. They are an internal implementation
//! detail.

use crate::Version;
use crate::dep::hyperium::http;

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
        http::Version::HTTP_11 => Version::HTTP_11,
        http::Version::HTTP_2 => Version::HTTP_2,
        http::Version::HTTP_3 => Version::HTTP_3,
        _ => Version::HTTP_11,
    }
}

/// Convert a native [`Uri`](crate::Uri) into the hyperium `http::Uri`.
///
/// Round-trips through the canonical string form. A native `Uri` is always a
/// valid RFC-3986 URI, so the reparse only fails for the HTTP asterisk-form
/// (`*`), which has no `http::Uri` representation other than `*` itself —
/// handled explicitly.
pub(crate) fn uri_to_hyperium(uri: crate::Uri) -> http::Uri {
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
pub(crate) fn uri_from_hyperium(uri: http::Uri) -> crate::Uri {
    if uri == http::Uri::from_static("*") {
        return crate::Uri::from_static("*");
    }
    let s = uri.to_string();
    crate::Uri::parse(s.as_str()).unwrap_or_else(|_| crate::Uri::from_static("/"))
}
