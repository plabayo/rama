//! Remove headers from a response.
//!
//! # Example
//!
//! ```
//! use rama_http::layer::remove_header::RemoveResponseHeaderLayer;
//! use rama_http::{Body, Request, Response, header::{self, HeaderValue}};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # let http_client = service_fn(|_: Request| async move {
//! #     Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
//! # });
//! #
//! let mut svc = (
//!     // Layer that removes all response headers with the prefix `x-foo`.
//!     RemoveResponseHeaderLayer::prefix("x-foo"),
//! ).layer(http_client);
//!
//! let request = Request::new(Body::empty());
//!
//! let response = svc.serve(Context::default(), request).await?;
//! #
//! # Ok(())
//! # }
//! ```

use crate::{HeaderName, Request, Response};
use rama_core::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::{borrow::Cow, fmt};

#[derive(Debug, Clone)]
/// Layer that applies [`RemoveResponseHeader`] which removes response headers.
///
/// See [`RemoveResponseHeader`] for more details.
pub struct RemoveResponseHeaderLayer {
    mode: RemoveResponseHeaderMode,
}

#[derive(Debug, Clone)]
enum RemoveResponseHeaderMode {
    Prefix(Cow<'static, str>),
    Exact(HeaderName),
    Hop,
}

impl RemoveResponseHeaderLayer {
    /// Create a new [`RemoveResponseHeaderLayer`].
    ///
    /// Removes response headers by prefix.
    pub fn prefix(prefix: impl Into<Cow<'static, str>>) -> Self {
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
}

/// Middleware that removes response headers from a request.
pub struct RemoveResponseHeader<S> {
    inner: S,
    mode: RemoveResponseHeaderMode,
}

impl<S> RemoveResponseHeader<S> {
    /// Create a new [`RemoveResponseHeader`].
    ///
    /// Removes response headers by prefix.
    pub fn prefix(prefix: impl Into<Cow<'static, str>>, inner: S) -> Self {
        RemoveResponseHeaderLayer::prefix(prefix.into()).layer(inner)
    }

    /// Create a new [`RemoveResponseHeader`].
    ///
    /// Removes the response header with the exact name.
    pub fn exact(header: HeaderName, inner: S) -> Self {
        RemoveResponseHeaderLayer::exact(header).layer(inner)
    }

    /// Create a new [`RemoveResponseHeader`].
    ///
    /// Removes all hop-by-hop response headers as specified in [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1).
    /// This does not support other hop-by-hop headers defined in [section-14.10](https://datatracker.ietf.org/doc/html/rfc2616#section-14.10).
    pub fn hop_by_hop(inner: S) -> Self {
        RemoveResponseHeaderLayer::hop_by_hop().layer(inner)
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug> fmt::Debug for RemoveResponseHeader<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoveResponseHeader")
            .field("inner", &self.inner)
            .field("mode", &self.mode)
            .finish()
    }
}

impl<S: Clone> Clone for RemoveResponseHeader<S> {
    fn clone(&self) -> Self {
        RemoveResponseHeader {
            inner: self.inner.clone(),
            mode: self.mode.clone(),
        }
    }
}

impl<ReqBody, ResBody, State, S> Service<State, Request<ReqBody>> for RemoveResponseHeader<S>
where
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    State: Clone + Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let mut resp = self.inner.serve(ctx, req).await?;
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
        let svc = RemoveResponseHeaderLayer::prefix("x-foo").layer(service_fn(
            |_ctx: Context<()>, _req: Request| async move {
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
        let res = svc.serve(Context::default(), req).await.unwrap();
        assert!(res.headers().get("x-foo-bar").is_none());
        assert_eq!(
            res.headers().get("foo").map(|v| v.to_str().unwrap()),
            Some("bar")
        );
    }

    #[tokio::test]
    async fn remove_response_header_exact() {
        let svc = RemoveResponseHeaderLayer::exact(HeaderName::from_static("foo")).layer(
            service_fn(|_ctx: Context<()>, _req: Request| async move {
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
        let res = svc.serve(Context::default(), req).await.unwrap();
        assert!(res.headers().get("foo").is_none());
        assert_eq!(
            res.headers().get("x-foo").map(|v| v.to_str().unwrap()),
            Some("baz")
        );
    }

    #[tokio::test]
    async fn remove_response_header_hop_by_hop() {
        let svc = RemoveResponseHeaderLayer::hop_by_hop().layer(service_fn(
            |_ctx: Context<()>, _req: Request| async move {
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
        let res = svc.serve(Context::default(), req).await.unwrap();
        assert!(res.headers().get("connection").is_none());
        assert!(res.headers().get("keep-alive").is_none());
        assert_eq!(
            res.headers().get("foo").map(|v| v.to_str().unwrap()),
            Some("bar")
        );
    }
}
