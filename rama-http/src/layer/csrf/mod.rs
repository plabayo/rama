//! Modern protection against [cross-site request forgery] (CSRF) attacks.
//!
//! This middleware implements the stateless CSRF protection scheme [introduced in Go 1.25][go]
//! and described in [Filippo Valsorda's blog post][filippo]. It relies on the [`Sec-Fetch-Site`]
//! and [`Origin`] request headers and requires no per-request token state.
//!
//! Unlike the Go reference, rama compares origins **structurally** using
//! [`rama_net::uri::Uri`]: hosts are matched case-insensitively and a default port (`80` for
//! `http`, `443` for `https`) compares equal whether it is written out explicitly or omitted.
//!
//! Requests are allowed if any of the following hold:
//!
//! 1. The method is `GET`, `HEAD`, or `OPTIONS`.
//! 2. [`Sec-Fetch-Site`] is `same-origin` or `none`.
//! 3. The request's `Origin` matches an allow-listed trusted origin.
//! 4. Neither a usable `Sec-Fetch-Site` nor a non-empty `Origin` is present.
//! 5. The `Origin`'s authority (host + port) matches the request's effective host — the
//!    request-target authority if present (RFC 7230 §5.3), else the `Host` header.
//!
//! Rejected requests receive a `403 Forbidden` response. The originating [`ProtectionError`] is
//! attached to the response's extensions — on every rejection, including those from a custom
//! builder — so surrounding layers can distinguish explicit cross-origin rejections from
//! conservative fallback rejections (e.g. requests from old browsers without `Sec-Fetch-Site`).
//! Use [`CsrfLayer::with_rejection_response`] to replace the rejection response.
//!
//! # Example
//!
//! ```
//! use std::convert::Infallible;
//!
//! use rama_core::{Layer, service::service_fn};
//! use rama_http::layer::csrf::CsrfLayer;
//! use rama_http::{Body, Request, Response};
//!
//! async fn handle(_: Request) -> Result<Response, Infallible> {
//!     Ok(Response::new(Body::empty()))
//! }
//!
//! // Same-origin (and `https://app.example.com`) requests pass through; cross-origin
//! // state-changing requests are rejected with `403 Forbidden`.
//! let layer = CsrfLayer::new()
//!     .add_trusted_origin("https://app.example.com")
//!     .expect("valid trusted origin");
//! let service = layer.into_layer(service_fn(handle));
//! # let _ = service;
//! ```
//!
//! # Deployment caveat
//!
//! The middleware trusts whatever `Origin` and `Host` reach it. Reverse proxies and load
//! balancers that rewrite `Host` (e.g. to an internal hostname) or strip `Origin` silently
//! degrade the protection: the `Origin`/`Host` fallback can no longer match and `Sec-Fetch-Site`
//! becomes the only remaining line of defense. Configure intermediaries to forward both headers
//! unchanged.
//!
//! [cross-site request forgery]: https://developer.mozilla.org/en-US/docs/Glossary/CSRF
//! [filippo]: https://words.filippo.io/csrf/
//! [go]: https://pkg.go.dev/net/http#CrossOriginProtection
//! [`Sec-Fetch-Site`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site
//! [`Origin`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin

use std::fmt::{self, Debug, Formatter};

use crate::{Method, Uri};
use rama_core::extensions::Extension;

mod layer;
mod origin;
mod response;
mod service;

pub use self::layer::CsrfLayer;
pub use self::response::{DefaultResponseForProtectionError, ResponseForProtectionError};
pub use self::service::Csrf;

/// Errors that can occur while configuring [`CsrfLayer`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// The origin string could not be parsed as a URI.
    InvalidOrigin {
        /// The offending origin string.
        origin: Box<str>,
        /// The parser error message.
        message: Box<str>,
    },

    /// The trusted origin carried a userinfo, path, query, or fragment component; an origin is
    /// `scheme://host[:port]` only.
    InvalidOriginComponents {
        /// The offending origin string.
        origin: Box<str>,
    },

    /// The origin had a scheme other than `http`/`https`, or no host, so it can never match a
    /// browser-supplied request `Origin`.
    OpaqueOrigin {
        /// The offending origin string.
        origin: Box<str>,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOrigin { origin, message } => {
                write!(f, "invalid origin {origin:?}: {message}")
            }
            Self::InvalidOriginComponents { origin } => write!(
                f,
                "invalid origin {origin:?}: userinfo, path, query, and fragment are not allowed"
            ),
            Self::OpaqueOrigin { origin } => {
                write!(f, "invalid origin {origin:?}: scheme must be http or https")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Reason a request was rejected by [`Csrf`].
///
/// Retrieve the category with [`ProtectionError::kind`]. [`Csrf`] attaches it to every
/// `403 Forbidden` rejection response's extensions so surrounding layers can distinguish explicit
/// cross-origin rejections from conservative fallback rejections.
///
/// This is an opaque struct rather than an enum so future variants can carry additional context
/// without a breaking change; match on [`kind`] instead.
///
/// [`kind`]: ProtectionError::kind
#[derive(Clone, Debug, Extension)]
#[extension(tags(http))]
pub struct ProtectionError {
    kind: ProtectionErrorKind,
}

impl ProtectionError {
    pub(crate) fn new(kind: ProtectionErrorKind) -> Self {
        Self { kind }
    }

    /// The category of rejection.
    #[must_use]
    pub fn kind(&self) -> ProtectionErrorKind {
        self.kind
    }
}

impl fmt::Display for ProtectionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.kind {
            ProtectionErrorKind::CrossOriginRequest => f.write_str("cross-origin request detected"),
            ProtectionErrorKind::CrossOriginRequestFromOldBrowser => {
                f.write_str("cross-origin request from old browser detected")
            }
        }
    }
}

impl std::error::Error for ProtectionError {}

/// The category of a [`ProtectionError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtectionErrorKind {
    /// A cross-origin request was detected via `Sec-Fetch-Site`.
    CrossOriginRequest,

    /// A request without a usable `Sec-Fetch-Site` failed the `Origin`/`Host` fallback check.
    /// Modern browsers always send `Sec-Fetch-Site`, so this typically means the request came
    /// from an old browser or a non-browser client.
    CrossOriginRequestFromOldBrowser,
}

type BypassFn = dyn Fn(&Method, &Uri) -> bool + Send + Sync + 'static;

struct DebugFn;

impl Debug for DebugFn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("<fn>")
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use crate::{Body, Request, Response, StatusCode, body::util::BodyExt, header};
    use rama_core::extensions::ExtensionsRef;
    use rama_core::{Layer, Service, service::service_fn};

    impl PartialEq for ProtectionError {
        fn eq(&self, other: &Self) -> bool {
            self.kind == other.kind
        }
    }

    fn echo() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
        service_fn(async |req: Request| {
            let body = match req.uri().path().map(|p| p.as_raw_str()).unwrap_or("/") {
                "/foo" => Body::from("foo"),
                "/bar" => Body::from("bar"),
                _ => Body::empty(),
            };
            Ok::<_, Infallible>(Response::new(body))
        })
    }

    async fn body_string(res: Response) -> String {
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn allows_safe_method() {
        let svc = CsrfLayer::new()
            .add_trusted_origin("https://example.com")
            .unwrap()
            .into_layer(echo());
        let req = Request::builder()
            .method("GET")
            .uri("/foo")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_string(res).await, "foo");
    }

    #[tokio::test]
    async fn allows_post_from_trusted_origin() {
        let svc = CsrfLayer::new()
            .add_trusted_origin("https://example.com")
            .unwrap()
            .into_layer(echo());
        let req = Request::builder()
            .method("POST")
            .uri("/bar")
            .header(header::ORIGIN, "https://example.com")
            .header("sec-fetch-site", "cross-site")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_string(res).await, "bar");
    }

    #[tokio::test]
    async fn rejects_post_from_untrusted_origin() {
        let svc = CsrfLayer::new()
            .add_trusted_origin("https://example.com")
            .unwrap()
            .into_layer(echo());
        let req = Request::builder()
            .method("POST")
            .uri("/bar")
            .header(header::HOST, "example.com")
            .header(header::ORIGIN, "https://malicious.example")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            res.extensions()
                .get_ref::<ProtectionError>()
                .map(|e| e.kind()),
            Some(ProtectionErrorKind::CrossOriginRequestFromOldBrowser),
        );
    }

    #[tokio::test]
    async fn uses_custom_rejection_response() {
        let svc = CsrfLayer::new()
            .with_rejection_response(|_err: ProtectionError| {
                let mut res = Response::new(Body::from("denied"));
                *res.status_mut() = StatusCode::IM_A_TEAPOT;
                res
            })
            .into_layer(echo());
        let req = Request::builder()
            .method("POST")
            .uri("/bar")
            .header(header::ORIGIN, "https://malicious.example")
            .header(header::HOST, "example.com")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::IM_A_TEAPOT);
        // The middleware attaches the error even though a custom builder produced the response.
        assert_eq!(
            res.extensions()
                .get_ref::<ProtectionError>()
                .map(|e| e.kind()),
            Some(ProtectionErrorKind::CrossOriginRequestFromOldBrowser),
        );
        assert_eq!(body_string(res).await, "denied");
    }

    #[tokio::test]
    async fn custom_rejection_response_not_invoked_when_allowed() {
        let svc = CsrfLayer::new()
            .add_trusted_origin("https://example.com")
            .unwrap()
            .with_rejection_response(|_err: ProtectionError| {
                let mut res = Response::new(Body::from("denied"));
                *res.status_mut() = StatusCode::IM_A_TEAPOT;
                res
            })
            .into_layer(echo());
        let req = Request::builder()
            .method("POST")
            .uri("/bar")
            .header(header::ORIGIN, "https://example.com")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.extensions().get_ref::<ProtectionError>().is_none());
        assert_eq!(body_string(res).await, "bar");
    }

    #[test]
    fn layer_add_trusted_origin() {
        let _layer = CsrfLayer::new()
            .add_trusted_origin("https://example.com")
            .unwrap();
        assert!(matches!(
            CsrfLayer::new().add_trusted_origin("not a valid url"),
            Err(ConfigError::InvalidOrigin { .. })
        ));
    }

    #[test]
    fn middleware_bypass() {
        let middleware = CsrfLayer::new()
            .with_insecure_bypass(|_method, uri| {
                uri.path().map(|p| p.as_raw_str()).unwrap_or("/") == "/bypass"
            })
            .into_layer(());

        struct Test {
            name: &'static str,
            path: &'static str,
            sec_fetch_site: Option<&'static str>,
            result: Result<(), ProtectionError>,
        }

        let tests = [
            Test {
                name: "bypass path without sec-fetch-site",
                path: "/bypass",
                sec_fetch_site: None,
                result: Ok(()),
            },
            Test {
                name: "bypass path with cross-site",
                path: "/bypass",
                sec_fetch_site: Some("cross-site"),
                result: Ok(()),
            },
            Test {
                name: "non-bypass path without sec-fetch-site",
                path: "/api",
                sec_fetch_site: None,
                result: Err(ProtectionError::new(
                    ProtectionErrorKind::CrossOriginRequestFromOldBrowser,
                )),
            },
            Test {
                name: "non-bypass path with cross-site",
                path: "/api",
                sec_fetch_site: Some("cross-site"),
                result: Err(ProtectionError::new(
                    ProtectionErrorKind::CrossOriginRequest,
                )),
            },
        ];

        for test in tests {
            let mut req = Request::builder()
                .method("POST")
                .header(header::HOST, "example.com")
                .header(header::ORIGIN, "https://attacker.example")
                .uri(format!("https://example.com{}", test.path));
            if let Some(sfs) = test.sec_fetch_site {
                req = req.header("sec-fetch-site", sfs);
            }
            let req = req.body(Body::empty()).unwrap();
            assert_eq!(middleware.verify(&req), test.result, "{}", test.name);
        }
    }

    #[test]
    fn middleware_sec_fetch_site() {
        let middleware: Csrf<()> = Csrf::default();

        struct Test {
            name: &'static str,
            method: &'static str,
            sec_fetch_site: Option<&'static str>,
            origin: Option<&'static str>,
            result: Result<(), ProtectionError>,
        }

        let tests = [
            Test {
                name: "same-origin allowed",
                method: "GET",
                sec_fetch_site: Some("same-origin"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "none allowed",
                method: "POST",
                sec_fetch_site: Some("none"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "cross-site blocked",
                method: "POST",
                sec_fetch_site: Some("cross-site"),
                origin: None,
                result: Err(ProtectionError::new(
                    ProtectionErrorKind::CrossOriginRequest,
                )),
            },
            Test {
                name: "same-site blocked",
                method: "POST",
                sec_fetch_site: Some("same-site"),
                origin: None,
                result: Err(ProtectionError::new(
                    ProtectionErrorKind::CrossOriginRequest,
                )),
            },
            Test {
                name: "no header with no origin",
                method: "POST",
                sec_fetch_site: None,
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "no header with matching origin",
                method: "POST",
                sec_fetch_site: None,
                origin: Some("https://example.com"),
                result: Ok(()),
            },
            Test {
                name: "no header with mismatched origin",
                method: "POST",
                sec_fetch_site: None,
                origin: Some("https://attacker.example"),
                result: Err(ProtectionError::new(
                    ProtectionErrorKind::CrossOriginRequestFromOldBrowser,
                )),
            },
            Test {
                name: "no header with null origin",
                method: "POST",
                sec_fetch_site: None,
                origin: Some("null"),
                result: Err(ProtectionError::new(
                    ProtectionErrorKind::CrossOriginRequestFromOldBrowser,
                )),
            },
            Test {
                name: "GET allowed",
                method: "GET",
                sec_fetch_site: Some("cross-site"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "OPTIONS allowed",
                method: "OPTIONS",
                sec_fetch_site: Some("cross-site"),
                origin: None,
                result: Ok(()),
            },
            Test {
                name: "PUT blocked",
                method: "PUT",
                sec_fetch_site: Some("cross-site"),
                origin: None,
                result: Err(ProtectionError::new(
                    ProtectionErrorKind::CrossOriginRequest,
                )),
            },
            Test {
                name: "empty origin without sec-fetch-site allowed",
                method: "POST",
                sec_fetch_site: None,
                origin: Some(""),
                result: Ok(()),
            },
        ];

        for test in tests {
            let mut req = Request::builder()
                .method(test.method)
                .header(header::HOST, "example.com");
            if let Some(sfs) = test.sec_fetch_site {
                req = req.header("sec-fetch-site", sfs);
            }
            if let Some(origin) = test.origin {
                req = req.header(header::ORIGIN, origin);
            }
            let req = req.body(Body::empty()).unwrap();
            assert_eq!(middleware.verify(&req), test.result, "{}", test.name);
        }
    }

    #[test]
    fn middleware_origin_host_match_is_structural() {
        let middleware: Csrf<()> = Csrf::default();

        struct Test {
            name: &'static str,
            uri: &'static str,
            host: Option<&'static str>,
            origin: &'static str,
            result: Result<(), ProtectionError>,
        }

        let cross_origin = || {
            Err(ProtectionError::new(
                ProtectionErrorKind::CrossOriginRequestFromOldBrowser,
            ))
        };

        let tests = [
            Test {
                name: "default port both sides",
                uri: "/",
                host: Some("example.com"),
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "same non-default port both sides",
                uri: "/",
                host: Some("example.com:8443"),
                origin: "https://example.com:8443",
                result: Ok(()),
            },
            Test {
                // Structural: an explicit default port equals an implicit one.
                name: "origin explicit default, host implicit",
                uri: "/",
                host: Some("example.com"),
                origin: "https://example.com:443",
                result: Ok(()),
            },
            Test {
                name: "host explicit default, origin implicit",
                uri: "/",
                host: Some("example.com:443"),
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "mismatched non-default ports",
                uri: "/",
                host: Some("example.com:8443"),
                origin: "https://example.com:8444",
                result: cross_origin(),
            },
            Test {
                // RFC 7230 §5.3: request-target authority is the effective host; here it matches.
                name: "request-target authority wins over host header (match)",
                uri: "https://example.com/path",
                host: Some("other.example"),
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "origin matches host header but not winning authority is rejected",
                uri: "https://example.com/path",
                host: Some("other.example"),
                origin: "https://other.example",
                result: cross_origin(),
            },
            Test {
                name: "missing host, uri carries authority (match)",
                uri: "https://example.com/path",
                host: None,
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "scheme-less origin does not match host",
                uri: "/",
                host: Some("example.com:8443"),
                origin: "example.com:8443",
                result: cross_origin(),
            },
            Test {
                name: "non-http origin scheme does not enter host fallback",
                uri: "/",
                host: Some("example.com:8443"),
                origin: "ftp://example.com:8443",
                result: cross_origin(),
            },
        ];

        for test in tests {
            let mut req = Request::builder().method("POST").uri(test.uri);
            if let Some(host) = test.host {
                req = req.header(header::HOST, host);
            }
            let req = req
                .header(header::ORIGIN, test.origin)
                .body(Body::empty())
                .unwrap();
            assert_eq!(middleware.verify(&req), test.result, "{}", test.name);
        }
    }

    #[test]
    fn middleware_trusted_origin_match_is_structural() {
        // Trusted origins are compared structurally: host case and default-port form do not matter.
        struct Test {
            name: &'static str,
            trusted: &'static str,
            origin: &'static str,
            result: Result<(), ProtectionError>,
        }

        let tests = [
            Test {
                name: "exact match trusted",
                trusted: "https://example.com",
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "non-default port match",
                trusted: "https://example.com:8443",
                origin: "https://example.com:8443",
                result: Ok(()),
            },
            Test {
                name: "host case is normalized",
                trusted: "https://Example.COM",
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "explicit default port trusted against bare origin",
                trusted: "https://example.com:443",
                origin: "https://example.com",
                result: Ok(()),
            },
            Test {
                name: "bare trusted matched by explicit-default-port origin",
                trusted: "https://example.com",
                origin: "https://example.com:443",
                result: Ok(()),
            },
            Test {
                name: "different host not trusted",
                trusted: "https://example.com",
                origin: "https://attacker.example",
                result: Err(ProtectionError::new(
                    ProtectionErrorKind::CrossOriginRequest,
                )),
            },
        ];

        for test in tests {
            let middleware = CsrfLayer::new()
                .add_trusted_origin(test.trusted)
                .unwrap_or_else(|e| panic!("{}: add_trusted_origin failed: {e}", test.name))
                .into_layer(());
            let req = Request::builder()
                .method("POST")
                .header(header::HOST, "other.example")
                .header(header::ORIGIN, test.origin)
                .header("sec-fetch-site", "cross-site")
                .body(Body::empty())
                .unwrap();
            assert_eq!(middleware.verify(&req), test.result, "{}", test.name);
        }
    }
}
