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
    Hop,
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
    /// Removes all hop-by-hop response headers as specified in [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1).
    /// This does not support other hop-by-hop headers defined in [section-14.10](https://datatracker.ietf.org/doc/html/rfc2616#section-14.10).
    #[must_use]
    pub fn hop_by_hop() -> Self {
        Self {
            mode: RemoveResponseHeaderMode::Hop,
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
    /// Removes all hop-by-hop response headers as specified in [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1).
    /// This does not support other hop-by-hop headers defined in [section-14.10](https://datatracker.ietf.org/doc/html/rfc2616#section-14.10).
    pub fn hop_by_hop(inner: S) -> Self {
        RemoveResponseHeaderLayer::hop_by_hop().into_layer(inner)
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
        let mut resp = self.inner.serve(req).await?;
        match &self.mode {
            RemoveResponseHeaderMode::Hop => {
                super::remove_hop_by_hop_response_headers(resp.headers_mut())
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
    use crate::{Body, Response};
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
}
