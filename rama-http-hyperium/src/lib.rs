//! Conversions between the native `rama-http-types` types and the hyperium
//! [`http`] crate equivalents, for interop with the wider `http`/`tower`/`hyper`
//! ecosystem.
//!
//! `rama-http-types` is `http`-free; this crate is the opt-in bridge, exposed as
//! two **sealed**, **fallible** extension traits: [`TryIntoHyperiumHttp`]
//! (rama → `http`) and [`TryIntoRamaHttp`] (`http` → rama). They are local
//! traits, so they implement the foreign `http` types directly (no orphan rule,
//! no conversion marker) and are callable as plain methods.
//!
//! The conversions are fallible by design: an invalid method/status, an
//! unrepresentable URI, or an invalid header name/value is surfaced as an error
//! (the direction's natural catch-all — [`http::Error`] one way,
//! [`rama_http_types::Error`] the other) rather than silently coerced.
//!
//! Bodies are bridged (not copied) by [`HyperiumBody`] / [`RamaBody`], which
//! wrap rama's [`Body`](rama_http_types::body::http_body::Body) ↔ the external
//! [`http_body::Body`], converting only trailer frames.
//!
//! ```
//! use rama_http_hyperium::{TryIntoHyperiumHttp, TryIntoRamaHttp};
//!
//! let hyper_req = http::Request::builder().uri("http://example.com/").body(()).unwrap();
//! let rama_req: rama_http_types::Request<()> = hyper_req.try_into_rama_http().unwrap();
//! assert_eq!(rama_req.uri().to_string(), "http://example.com/");
//!
//! let back: http::Request<()> = rama_req.try_into_hyperium_http().unwrap();
//! assert_eq!(back.uri(), "http://example.com/");
//! ```
//!
//! [`http`]: https://docs.rs/http

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use rama_core::extensions::Extension;
use rama_http_types::{
    HeaderMap, Method, Request, Response, StatusCode, Version, request, response,
};
use rama_net::uri::Uri;

mod into_hyperium;
mod into_rama;

#[doc(inline)]
pub use into_hyperium::{HyperiumBody, HyperiumBodyError, TryIntoHyperiumHttp};
#[doc(inline)]
pub use into_rama::{RamaBody, RamaBodyError, TryIntoRamaHttp};

mod sealed {
    //! Seals the conversion traits so the implemented set stays a closed set
    //! defined by this crate, never extended downstream.
    pub trait Sealed {}
}

macro_rules! impl_sealed {
    ($($ty:ty),* $(,)?) => {
        $( impl crate::sealed::Sealed for $ty {} )*
    };
}

impl_sealed!(
    Method,
    StatusCode,
    Version,
    Uri,
    HeaderMap,
    request::Parts,
    response::Parts,
    http::Method,
    http::StatusCode,
    http::Version,
    http::Uri,
    http::HeaderMap,
    http::request::Parts,
    http::response::Parts,
);
impl<T> sealed::Sealed for Request<T> {}
impl<T> sealed::Sealed for Response<T> {}
impl<T> sealed::Sealed for http::Request<T> {}
impl<T> sealed::Sealed for http::Response<T> {}
impl sealed::Sealed for &http::HeaderMap {}

/// Stash for the hyperium `http::Extensions` carried across a rama round-trip,
/// so `rama → http → rama` preserves http-only extensions.
#[derive(Clone, Debug, Extension)]
pub(crate) struct HyperExtensions(pub(crate) http::Extensions);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let hyper = http::Request::builder()
            .method("POST")
            .uri("https://example.com:8443/path?q=1")
            .header("x-test", "v")
            .body(())
            .unwrap();
        let rama: Request<()> = hyper.try_into_rama_http().unwrap();
        assert_eq!(rama.method().as_str(), "POST");
        assert_eq!(rama.uri().to_string(), "https://example.com:8443/path?q=1");
        assert_eq!(rama.headers().get("x-test").unwrap().as_bytes(), b"v");

        let back: http::Request<()> = rama.try_into_hyperium_http().unwrap();
        assert_eq!(back.method(), "POST");
        assert_eq!(back.uri(), "https://example.com:8443/path?q=1");
        assert_eq!(back.headers().get("x-test").unwrap(), "v");
    }

    #[test]
    fn request_round_trip_preserves_rama_extension() {
        use rama_core::extensions::ExtensionsRef as _;

        #[derive(Debug, Clone, PartialEq, Eq, Extension)]
        struct Label(u32);

        let rama = Request::builder().uri("http://x/").body(()).unwrap();
        rama.extensions().insert(Label(7));

        // rama → http stashes the rama extensions; http → rama restores them.
        let hyper: http::Request<()> = rama.try_into_hyperium_http().unwrap();
        let back: Request<()> = hyper.try_into_rama_http().unwrap();
        assert_eq!(*back.extensions().get_ref::<Label>().unwrap(), Label(7));
    }

    #[test]
    fn response_round_trip() {
        let hyper = http::Response::builder()
            .status(404)
            .header("x-y", "z")
            .body(())
            .unwrap();
        let rama: Response<()> = hyper.try_into_rama_http().unwrap();
        assert_eq!(rama.status().as_u16(), 404);

        let back: http::Response<()> = rama.try_into_hyperium_http().unwrap();
        assert_eq!(back.status(), 404);
        assert_eq!(back.headers().get("x-y").unwrap(), "z");
    }

    #[test]
    fn http_uri_authority_form_preserves_host() {
        // A CONNECT-style authority-form http::Uri must keep its host when
        // converted to rama (it must not be misread as `scheme:path`).
        let mut parts = http::uri::Parts::default();
        parts.authority = Some("example.com:443".parse().unwrap());
        let hyper_uri = http::Uri::from_parts(parts).unwrap();
        assert!(hyper_uri.scheme().is_none() && hyper_uri.authority().is_some());

        let rama_uri: Uri = hyper_uri.try_into_rama_http().unwrap();
        assert_eq!(
            rama_uri.host(),
            Some(rama_net::address::Host::EXAMPLE_NAME.view())
        );
        assert_eq!(rama_uri.port_u16(), Some(443));
    }
}
