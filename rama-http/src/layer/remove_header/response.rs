//! Remove headers from a response.
//!
//! # Example
//!
//! ```
//! use rama_http::layer::remove_header::RemoveResponseHeaderLayer;
//! use rama_http::{Body, Request, Response, header::{self, HeaderValue}};
//! use rama_core::service::service_fn;
//! use rama_core::{Service, Layer};
//! use rama_core::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # let http_client = service_fn(async |_: Request| {
//! #     Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
//! # });
//! #
//! let mut svc = (
//!     // Layer that removes all response headers with the prefix `x-foo`.
//!     RemoveResponseHeaderLayer::prefix("x-foo"),
//! ).into_layer(http_client);
//!
//! let request = Request::new(Body::empty());
//!
//! let response = svc.serve(request).await?;
//! #
//! # Ok(())
//! # }
//! ```

use crate::{HeaderName, Request, Response};
use rama_core::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use rama_utils::str::smol_str::SmolStr;

#[derive(Debug, Clone)]
/// Layer that applies [`RemoveResponseHeader`] which removes response headers.
///
/// See [`RemoveResponseHeader`] for more details.
pub struct RemoveResponseHeaderLayer {
    mode: RemoveResponseHeaderMode,
}

#[derive(Debug, Clone)]
enum RemoveResponseHeaderMode {
    Prefix(SmolStr),
    Exact(HeaderName),
    HopContextAware,
    HopStrict,
    ProxyAuth,
    Sensitive,
}

impl RemoveResponseHeaderLayer {
    /// Create a new [`RemoveResponseHeaderLayer`].
    ///
    /// Removes response headers by prefix.
    pub fn prefix(prefix: impl Into<SmolStr>) -> Self {
        Self {
            mode: RemoveResponseHeaderMode::Prefix(prefix.into()),
        }
    }

    /// Create a new [`RemoveResponseHeaderLayer`].
    ///
    /// Removes the response header with the exact name.
    pub fn exact(header: HeaderName) -> Self {
        Self {
            mode: RemoveResponseHeaderMode::Exact(header),
        }
    }

    /// Create a new [`RemoveResponseHeaderLayer`].
    ///
    /// Removes hop-by-hop response headers while preserving a valid upgrade
    /// response corresponding to the request.
    ///
    /// This is the recommended mode for HTTP intermediaries. Use
    /// [`Self::hop_by_hop_strict`] to remove the upgrade envelope as well.
    /// Pair it with [`super::RemoveRequestHeaderLayer::hop_by_hop`]; mixing
    /// strict request removal with a context-aware response can validate an
    /// upgrade that was not forwarded upstream.
    #[must_use]
    pub fn hop_by_hop() -> Self {
        Self {
            mode: RemoveResponseHeaderMode::HopContextAware,
        }
    }

    /// Removes response-side hop-by-hop fields without forwarding upgrade or
    /// trailer capabilities to the next hop.
    #[must_use]
    pub fn hop_by_hop_strict() -> Self {
        Self {
            mode: RemoveResponseHeaderMode::HopStrict,
        }
    }

    /// Remove fields belonging to a proxy authentication exchange.
    #[must_use]
    pub fn proxy_auth() -> Self {
        Self {
            mode: RemoveResponseHeaderMode::ProxyAuth,
        }
    }

    /// Create a new [`RemoveResponseHeaderLayer`].
    ///
    /// Removes all sensitive response headers.
    #[must_use]
    pub fn sensitive() -> Self {
        Self {
            mode: RemoveResponseHeaderMode::Sensitive,
        }
    }
}

impl<S> Layer<S> for RemoveResponseHeaderLayer {
    type Service = RemoveResponseHeader<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RemoveResponseHeader {
            inner,
            mode: self.mode.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        RemoveResponseHeader {
            inner,
            mode: self.mode,
        }
    }
}

/// Middleware that removes response headers from a request.
#[derive(Debug, Clone)]
pub struct RemoveResponseHeader<S> {
    inner: S,
    mode: RemoveResponseHeaderMode,
}

impl<S> RemoveResponseHeader<S> {
    /// Create a new [`RemoveResponseHeader`].
    ///
    /// Removes response headers by prefix.
    pub fn prefix(prefix: impl Into<SmolStr>, inner: S) -> Self {
        RemoveResponseHeaderLayer::prefix(prefix.into()).into_layer(inner)
    }

    /// Create a new [`RemoveResponseHeader`].
    ///
    /// Removes the response header with the exact name.
    pub fn exact(header: HeaderName, inner: S) -> Self {
        RemoveResponseHeaderLayer::exact(header).into_layer(inner)
    }

    /// Create a new [`RemoveResponseHeader`].
    ///
    /// Removes hop-by-hop response headers while preserving a valid upgrade
    /// response corresponding to the request.
    pub fn hop_by_hop(inner: S) -> Self {
        RemoveResponseHeaderLayer::hop_by_hop().into_layer(inner)
    }

    /// Removes response-side hop-by-hop fields without forwarding upgrade or
    /// trailer capabilities to the next hop.
    pub fn hop_by_hop_strict(inner: S) -> Self {
        RemoveResponseHeaderLayer::hop_by_hop_strict().into_layer(inner)
    }

    /// Remove fields belonging to a proxy authentication exchange.
    pub fn proxy_auth(inner: S) -> Self {
        RemoveResponseHeaderLayer::proxy_auth().into_layer(inner)
    }

    /// Create a new [`RemoveResponseHeader`].
    ///
    /// Removes all sensitive response headers.
    pub fn sensitive(inner: S) -> Self {
        RemoveResponseHeaderLayer::sensitive().into_layer(inner)
    }

    define_inner_service_accessors!();
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for RemoveResponseHeader<S>
where
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let request_context = matches!(&self.mode, RemoveResponseHeaderMode::HopContextAware)
            .then(|| super::HopByHopHeaderContext::capture(req.headers(), req.version()));
        let mut resp = self.inner.serve(req).await?;
        match &self.mode {
            RemoveResponseHeaderMode::HopContextAware => {
                if let Some(request_context) = request_context.as_ref() {
                    super::sanitize_hop_by_hop_response(&mut resp, request_context);
                }
            }
            RemoveResponseHeaderMode::HopStrict => {
                super::remove_hop_by_hop_response_headers(resp.headers_mut())
            }
            RemoveResponseHeaderMode::ProxyAuth => {
                super::remove_proxy_auth_response_headers(resp.headers_mut())
            }
            RemoveResponseHeaderMode::Sensitive => {
                super::remove_sensitive_response_headers(resp.headers_mut())
            }
            RemoveResponseHeaderMode::Prefix(prefix) => {
                super::remove_headers_by_prefix(resp.headers_mut(), prefix)
            }
            RemoveResponseHeaderMode::Exact(header) => {
                super::remove_headers_by_exact_name(resp.headers_mut(), header)
            }
        }
        Ok(resp)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        Body, HeaderValue, Response, header,
        layer::set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
    };
    use rama_core::{Layer, Service, service::service_fn};
    use std::convert::Infallible;

    #[tokio::test]
    async fn remove_response_header_prefix() {
        let svc = RemoveResponseHeaderLayer::prefix("x-foo").into_layer(service_fn(
            async |_req: Request| {
                Ok::<_, Infallible>(
                    Response::builder()
                        .header("x-foo-bar", "baz")
                        .header("foo", "bar")
                        .body(Body::empty())
                        .unwrap(),
                )
            },
        ));
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(req).await.unwrap();
        assert!(res.headers().get("x-foo-bar").is_none());
        assert_eq!(
            res.headers().get("foo").map(|v| v.to_str().unwrap()),
            Some("bar")
        );
    }

    #[tokio::test]
    async fn remove_response_header_exact() {
        let svc = RemoveResponseHeaderLayer::exact(HeaderName::from_static("foo")).into_layer(
            service_fn(async |_req: Request| {
                Ok::<_, Infallible>(
                    Response::builder()
                        .header("x-foo", "baz")
                        .header("foo", "bar")
                        .body(Body::empty())
                        .unwrap(),
                )
            }),
        );
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(req).await.unwrap();
        assert!(res.headers().get("foo").is_none());
        assert_eq!(
            res.headers().get("x-foo").map(|v| v.to_str().unwrap()),
            Some("baz")
        );
    }

    #[tokio::test]
    async fn remove_response_header_hop_by_hop() {
        let svc = RemoveResponseHeaderLayer::hop_by_hop().into_layer(service_fn(
            async |_req: Request| {
                Ok::<_, Infallible>(
                    Response::builder()
                        .header("connection", "close")
                        .header("keep-alive", "timeout=5")
                        .header("foo", "bar")
                        .body(Body::empty())
                        .unwrap(),
                )
            },
        ));
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(req).await.unwrap();
        assert!(res.headers().get("connection").is_none());
        assert!(res.headers().get("keep-alive").is_none());
        assert_eq!(
            res.headers().get("foo").map(|v| v.to_str().unwrap()),
            Some("bar")
        );
    }

    #[tokio::test]
    async fn remove_response_header_hop_by_hop_with_headers_in_connect() {
        let svc = RemoveResponseHeaderLayer::hop_by_hop().into_layer(service_fn(
            async |_req: Request| {
                Ok::<_, Infallible>(
                    Response::builder()
                        .header("connection", "x-foo, x-bar")
                        .header("keep-alive", "timeout=5")
                        .header("x-foo", "1")
                        .header("foo", "bar")
                        .body(Body::empty())
                        .unwrap(),
                )
            },
        ));
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(req).await.unwrap();
        assert!(res.headers().get("connection").is_none());
        assert!(res.headers().get("x-foo").is_none());
        assert!(res.headers().get("x-bar").is_none());
        assert!(res.headers().get("keep-alive").is_none());
        assert_eq!(
            res.headers().get("foo").map(|v| v.to_str().unwrap()),
            Some("bar")
        );
    }

    #[tokio::test]
    async fn remove_response_header_hop_by_hop_preserves_matching_upgrade() {
        let svc = (
            super::super::RemoveRequestHeaderLayer::hop_by_hop(),
            RemoveResponseHeaderLayer::hop_by_hop(),
        )
            .into_layer(service_fn(async |req: Request| {
                assert_eq!(req.headers()["connection"], "upgrade");
                assert_eq!(req.headers()["upgrade"], "WebSocket");
                assert!(!req.headers().contains_key("keep-alive"));
                assert!(!req.headers().contains_key("x-hop"));
                Ok::<_, Infallible>(
                    Response::builder()
                        .version(crate::Version::HTTP_11)
                        .status(crate::StatusCode::SWITCHING_PROTOCOLS)
                        .header("connection", "keep-alive, upgrade, x-hop")
                        .header("upgrade", "websocket")
                        .header("keep-alive", "timeout=5")
                        .header("x-hop", "secret")
                        .body(Body::empty())
                        .unwrap(),
                )
            }));
        let req = Request::builder()
            .version(crate::Version::HTTP_11)
            .header("connection", "keep-alive, upgrade, x-hop")
            .header("upgrade", "WebSocket")
            .header("keep-alive", "timeout=5")
            .header("x-hop", "secret")
            .body(Body::empty())
            .unwrap();

        let res = svc.serve(req).await.unwrap();

        assert_eq!(res.headers()["connection"], "upgrade");
        assert_eq!(res.headers()["upgrade"], "websocket");
        assert!(res.headers().get("keep-alive").is_none());
        assert!(res.headers().get("x-hop").is_none());
    }

    #[tokio::test]
    async fn remove_response_header_hop_by_hop_rejects_unsolicited_upgrade() {
        let svc = RemoveResponseHeaderLayer::hop_by_hop().into_layer(service_fn(
            async |_req: Request| {
                Ok::<_, Infallible>(
                    Response::builder()
                        .version(crate::Version::HTTP_11)
                        .status(crate::StatusCode::SWITCHING_PROTOCOLS)
                        .header("connection", "upgrade")
                        .header("upgrade", "websocket")
                        .body(Body::empty())
                        .unwrap(),
                )
            },
        ));

        let res = svc.serve(Request::new(Body::empty())).await.unwrap();

        assert_eq!(res.status(), crate::StatusCode::BAD_GATEWAY);
        assert_eq!(res.headers()["connection"], "close");
        assert!(res.headers().get("upgrade").is_none());
    }

    #[tokio::test]
    async fn remove_response_header_hop_by_hop_rejects_mismatched_upgrade() {
        let svc = RemoveResponseHeaderLayer::hop_by_hop().into_layer(service_fn(
            async |_req: Request| {
                Ok::<_, Infallible>(
                    Response::builder()
                        .version(crate::Version::HTTP_11)
                        .status(crate::StatusCode::SWITCHING_PROTOCOLS)
                        .header("connection", "upgrade")
                        .header("upgrade", "example/2")
                        .body(Body::empty())
                        .unwrap(),
                )
            },
        ));
        let request = Request::builder()
            .version(crate::Version::HTTP_11)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .unwrap();

        let res = svc.serve(request).await.unwrap();

        assert_eq!(res.status(), crate::StatusCode::BAD_GATEWAY);
        assert_eq!(res.headers()["connection"], "close");
        assert!(!res.headers().contains_key("upgrade"));
    }

    #[tokio::test]
    async fn invalid_h2_switching_protocols_has_no_connection_header() {
        let svc = RemoveResponseHeaderLayer::hop_by_hop().into_layer(service_fn(
            async |_req: Request| {
                Ok::<_, Infallible>(
                    Response::builder()
                        .version(crate::Version::HTTP_2)
                        .status(crate::StatusCode::SWITCHING_PROTOCOLS)
                        .body(Body::empty())
                        .unwrap(),
                )
            },
        ));
        let request = Request::builder()
            .version(crate::Version::HTTP_2)
            .body(Body::empty())
            .unwrap();

        let res = svc.serve(request).await.unwrap();

        assert_eq!(res.status(), crate::StatusCode::BAD_GATEWAY);
        assert!(res.headers().is_empty());
    }

    #[tokio::test]
    async fn remove_response_header_hop_by_hop_strict_removes_upgrade() {
        let svc = RemoveResponseHeaderLayer::hop_by_hop_strict().into_layer(service_fn(
            async |_req: Request| {
                Ok::<_, Infallible>(
                    Response::builder()
                        .version(crate::Version::HTTP_11)
                        .status(crate::StatusCode::SWITCHING_PROTOCOLS)
                        .header("connection", "upgrade")
                        .header("upgrade", "websocket")
                        .body(Body::empty())
                        .unwrap(),
                )
            },
        ));
        let req = Request::builder()
            .version(crate::Version::HTTP_11)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .unwrap();

        let res = svc.serve(req).await.unwrap();

        assert!(res.headers().get("connection").is_none());
        assert!(res.headers().get("upgrade").is_none());
    }

    #[tokio::test]
    async fn hop_layers_consume_fields_before_transform_middleware() {
        let svc = (
            super::super::RemoveRequestHeaderLayer::hop_by_hop(),
            SetResponseHeaderLayer::overriding(
                HeaderName::from_static("x-response-hop"),
                HeaderValue::from_static("secret"),
            ),
            SetResponseHeaderLayer::overriding(
                header::CONNECTION,
                HeaderValue::from_static("upgrade, x-response-hop"),
            ),
            SetRequestHeaderLayer::overriding(
                HeaderName::from_static("x-request-hop"),
                HeaderValue::from_static("secret"),
            ),
            SetRequestHeaderLayer::overriding(
                header::UPGRADE,
                HeaderValue::from_static("websocket"),
            ),
            SetRequestHeaderLayer::overriding(
                header::CONNECTION,
                HeaderValue::from_static("upgrade, x-request-hop"),
            ),
            RemoveResponseHeaderLayer::hop_by_hop(),
        )
            .into_layer(service_fn(async |request: Request| {
                assert_eq!(
                    request.headers()[header::CONNECTION],
                    "upgrade, x-request-hop"
                );
                assert_eq!(request.headers()[header::UPGRADE], "websocket");
                assert_eq!(request.headers()["x-request-hop"], "secret");
                assert!(!request.headers().contains_key("x-ingress-hop"));
                Ok::<_, Infallible>(
                    Response::builder()
                        .version(crate::Version::HTTP_11)
                        .status(crate::StatusCode::SWITCHING_PROTOCOLS)
                        .header(header::CONNECTION, "upgrade, x-upstream-hop")
                        .header(header::UPGRADE, "websocket")
                        .header("x-upstream-hop", "secret")
                        .body(Body::empty())
                        .unwrap(),
                )
            }));
        let request = Request::builder()
            .version(crate::Version::HTTP_11)
            .header(header::CONNECTION, "x-ingress-hop")
            .header("x-ingress-hop", "secret")
            .body(Body::empty())
            .unwrap();

        let response = svc.serve(request).await.unwrap();

        assert_eq!(response.status(), crate::StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            response.headers()[header::CONNECTION],
            "upgrade, x-response-hop"
        );
        assert_eq!(response.headers()[header::UPGRADE], "websocket");
        assert_eq!(response.headers()["x-response-hop"], "secret");
        assert!(!response.headers().contains_key("x-upstream-hop"));
    }
}
