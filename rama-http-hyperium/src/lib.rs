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
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]

use rama_core::extensions::{Extension, Extensions, ExtensionsRef as _};
use rama_http_types::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
    request, response,
};

mod private {
    /// Seals [`TryIntoHyperiumHttp`](super::TryIntoHyperiumHttp) and
    /// [`TryIntoRamaHttp`](super::TryIntoRamaHttp): the conversions are a closed
    /// set defined by this crate, never implemented downstream.
    pub trait Sealed {}
}

macro_rules! impl_sealed {
    ($($ty:ty),* $(,)?) => {
        $( impl private::Sealed for $ty {} )*
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
impl<T> private::Sealed for Request<T> {}
impl<T> private::Sealed for Response<T> {}
impl<T> private::Sealed for http::Request<T> {}
impl<T> private::Sealed for http::Response<T> {}
impl private::Sealed for &http::HeaderMap {}

/// Fallibly convert a rama-http-types value into its hyperium [`http`]-crate
/// equivalent. Sealed; the implemented set is fixed by this crate.
///
/// [`http`]: https://docs.rs/http
pub trait TryIntoHyperiumHttp: private::Sealed {
    /// The hyperium `http` type produced.
    type Output;
    /// The conversion error.
    type Error;

    /// Convert `self` into its hyperium `http` equivalent.
    fn try_into_hyperium_http(self) -> Result<Self::Output, Self::Error>;
}

/// Fallibly convert a hyperium [`http`]-crate value into its rama-http-types
/// equivalent. Sealed; the implemented set is fixed by this crate.
///
/// [`http`]: https://docs.rs/http
pub trait TryIntoRamaHttp: private::Sealed {
    /// The rama-http-types type produced.
    type Output;
    /// The conversion error.
    type Error;

    /// Convert `self` into its rama-http-types equivalent.
    fn try_into_rama_http(self) -> Result<Self::Output, Self::Error>;
}

/// Stash for the hyperium `http::Extensions` carried across a rama round-trip,
/// so `rama → http → rama` preserves http-only extensions.
#[derive(Clone, Debug, Extension)]
struct HyperExtensions(http::Extensions);

// --- leaf types -------------------------------------------------------------

impl TryIntoHyperiumHttp for Method {
    type Output = http::Method;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::Method, http::Error> {
        // Both are byte-identical forks; round-trip through the method bytes.
        Ok(http::Method::from_bytes(self.as_str().as_bytes())?)
    }
}

impl TryIntoRamaHttp for http::Method {
    type Output = Method;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<Method, rama_http_types::Error> {
        Ok(Method::from_bytes(self.as_str().as_bytes())?)
    }
}

impl TryIntoHyperiumHttp for StatusCode {
    type Output = http::StatusCode;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::StatusCode, http::Error> {
        Ok(http::StatusCode::from_u16(self.as_u16())?)
    }
}

impl TryIntoRamaHttp for http::StatusCode {
    type Output = StatusCode;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<StatusCode, rama_http_types::Error> {
        Ok(StatusCode::from_u16(self.as_u16())?)
    }
}

impl TryIntoHyperiumHttp for Version {
    type Output = http::Version;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::Version, http::Error> {
        // Total: rama and hyperium expose the same five versions.
        Ok(match self {
            Self::HTTP_09 => http::Version::HTTP_09,
            Self::HTTP_10 => http::Version::HTTP_10,
            Self::HTTP_11 => http::Version::HTTP_11,
            Self::HTTP_2 => http::Version::HTTP_2,
            Self::HTTP_3 => http::Version::HTTP_3,
        })
    }
}

impl TryIntoRamaHttp for http::Version {
    type Output = Version;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<Version, rama_http_types::Error> {
        Ok(match self {
            Self::HTTP_09 => Version::HTTP_09,
            Self::HTTP_10 => Version::HTTP_10,
            Self::HTTP_2 => Version::HTTP_2,
            Self::HTTP_3 => Version::HTTP_3,
            // `http::Version` exposes no other variant; defensive for its
            // `#[non_exhaustive]` future-proofing.
            _ => Version::HTTP_11,
        })
    }
}

impl TryIntoHyperiumHttp for Uri {
    type Output = http::Uri;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::Uri, http::Error> {
        // The HTTP asterisk-form has no `http::Uri` representation beyond `*`.
        if self.is_asterisk() {
            return Ok(http::Uri::from_static("*"));
        }
        Ok(http::Uri::try_from(self.as_str().as_ref())?)
    }
}

impl TryIntoRamaHttp for http::Uri {
    type Output = Uri;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<Uri, rama_http_types::Error> {
        if self == Self::from_static("*") {
            return Ok(Uri::from_static("*"));
        }
        Ok(Uri::parse(self.to_string().as_str())?)
    }
}

impl TryIntoHyperiumHttp for HeaderMap {
    type Output = http::HeaderMap;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::HeaderMap, http::Error> {
        // Both are byte-identical forks; round-trip each name/value through its
        // bytes, preserving multi-value ordering and the sensitivity flag.
        let mut out = http::HeaderMap::with_capacity(self.len());
        let mut last: Option<http::header::HeaderName> = None;
        for (name, hv) in self {
            let mut out_hv = http::header::HeaderValue::from_bytes(hv.as_bytes())?;
            out_hv.set_sensitive(hv.is_sensitive());
            match name {
                Some(name) => {
                    let name = http::header::HeaderName::from_bytes(name.as_str().as_bytes())?;
                    out.append(name.clone(), out_hv);
                    last = Some(name);
                }
                // `None` name repeats the previous name (multi-value).
                None => {
                    if let Some(name) = &last {
                        out.append(name.clone(), out_hv);
                    }
                }
            }
        }
        Ok(out)
    }
}

impl TryIntoRamaHttp for http::HeaderMap {
    type Output = HeaderMap;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<HeaderMap, rama_http_types::Error> {
        let mut out = HeaderMap::with_capacity(self.len());
        let mut last: Option<HeaderName> = None;
        for (name, hv) in self {
            let mut out_hv = HeaderValue::from_bytes(hv.as_bytes())?;
            out_hv.set_sensitive(hv.is_sensitive());
            match name {
                Some(name) => {
                    let name = HeaderName::from_bytes(name.as_str().as_bytes())?;
                    out.append(name.clone(), out_hv);
                    last = Some(name);
                }
                None => {
                    if let Some(name) = &last {
                        out.append(name.clone(), out_hv);
                    }
                }
            }
        }
        Ok(out)
    }
}

impl TryIntoRamaHttp for &http::HeaderMap {
    type Output = HeaderMap;
    type Error = rama_http_types::Error;
    /// Borrowing variant, for boundaries that only hand out a `&http::HeaderMap`
    /// (e.g. a `multer` multipart field). Iterating by reference already repeats
    /// the name per value, so no multi-value bookkeeping is needed.
    fn try_into_rama_http(self) -> Result<HeaderMap, rama_http_types::Error> {
        let mut out = HeaderMap::with_capacity(self.len());
        for (name, hv) in self {
            let name = HeaderName::from_bytes(name.as_str().as_bytes())?;
            let mut out_hv = HeaderValue::from_bytes(hv.as_bytes())?;
            out_hv.set_sensitive(hv.is_sensitive());
            out.append(name, out_hv);
        }
        Ok(out)
    }
}

// --- request ----------------------------------------------------------------

impl<T> TryIntoRamaHttp for http::Request<T> {
    type Output = Request<T>;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<Request<T>, rama_http_types::Error> {
        let (mut parts, body) = self.into_parts();
        // Pull any previously-stashed rama extensions back out; stash the
        // remaining http extensions so a later rama → http hop restores them.
        let rama_extensions = parts.extensions.remove::<Extensions>().unwrap_or_default();
        rama_extensions.insert(HyperExtensions(parts.extensions));

        let mut req = Request::new(body);
        *req.method_mut() = parts.method.try_into_rama_http()?;
        *req.uri_mut() = parts.uri.try_into_rama_http()?;
        *req.version_mut() = parts.version.try_into_rama_http()?;
        *req.headers_mut() = parts.headers.try_into_rama_http()?;
        req.extensions().extend(&rama_extensions);
        Ok(req)
    }
}

impl<T> TryIntoHyperiumHttp for Request<T> {
    type Output = http::Request<T>;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::Request<T>, http::Error> {
        let (parts, body) = self.into_parts();

        let mut hyper_extensions = parts
            .extensions
            .get_ref::<HyperExtensions>()
            .map(|ext| ext.0.clone())
            .unwrap_or_default();
        hyper_extensions.insert(parts.extensions);

        let mut req = http::Request::new(body);
        *req.method_mut() = parts.method.try_into_hyperium_http()?;
        *req.uri_mut() = parts.uri.try_into_hyperium_http()?;
        *req.version_mut() = parts.version.try_into_hyperium_http()?;
        *req.headers_mut() = parts.headers.try_into_hyperium_http()?;
        *req.extensions_mut() = hyper_extensions;
        Ok(req)
    }
}

impl TryIntoRamaHttp for http::request::Parts {
    type Output = request::Parts;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<request::Parts, rama_http_types::Error> {
        // `request::Parts::new` is private + non-exhaustive, so build via a
        // `Request<()>` and split it back out.
        Ok(http::Request::from_parts(self, ())
            .try_into_rama_http()?
            .into_parts()
            .0)
    }
}

impl TryIntoHyperiumHttp for request::Parts {
    type Output = http::request::Parts;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::request::Parts, http::Error> {
        Ok(Request::from_parts(self, ())
            .try_into_hyperium_http()?
            .into_parts()
            .0)
    }
}

// --- response ---------------------------------------------------------------

impl<T> TryIntoRamaHttp for http::Response<T> {
    type Output = Response<T>;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<Response<T>, rama_http_types::Error> {
        let (mut parts, body) = self.into_parts();
        let rama_extensions = parts.extensions.remove::<Extensions>().unwrap_or_default();
        rama_extensions.insert(HyperExtensions(parts.extensions));

        let mut res = Response::new(body);
        *res.status_mut() = parts.status.try_into_rama_http()?;
        *res.version_mut() = parts.version.try_into_rama_http()?;
        *res.headers_mut() = parts.headers.try_into_rama_http()?;
        res.extensions().extend(&rama_extensions);
        Ok(res)
    }
}

impl<T> TryIntoHyperiumHttp for Response<T> {
    type Output = http::Response<T>;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::Response<T>, http::Error> {
        let (parts, body) = self.into_parts();

        let mut hyper_extensions = parts
            .extensions
            .get_ref::<HyperExtensions>()
            .map(|ext| ext.0.clone())
            .unwrap_or_default();
        hyper_extensions.insert(parts.extensions);

        let mut res = http::Response::new(body);
        *res.status_mut() = parts.status.try_into_hyperium_http()?;
        *res.version_mut() = parts.version.try_into_hyperium_http()?;
        *res.headers_mut() = parts.headers.try_into_hyperium_http()?;
        *res.extensions_mut() = hyper_extensions;
        Ok(res)
    }
}

impl TryIntoRamaHttp for http::response::Parts {
    type Output = response::Parts;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<response::Parts, rama_http_types::Error> {
        Ok(http::Response::from_parts(self, ())
            .try_into_rama_http()?
            .into_parts()
            .0)
    }
}

impl TryIntoHyperiumHttp for response::Parts {
    type Output = http::response::Parts;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::response::Parts, http::Error> {
        Ok(Response::from_parts(self, ())
            .try_into_hyperium_http()?
            .into_parts()
            .0)
    }
}

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
        use rama_core::extensions::{Extension, ExtensionsRef as _};

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
}
