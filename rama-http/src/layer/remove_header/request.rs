//! Remove headers from a request.
//!
//! # Example
//!
//! ```
//! use rama_http::layer::remove_header::RemoveRequestHeaderLayer;
//! use rama_http::{Body, Request, Response, header::{self, HeaderValue}};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # let http_client = service_fn(async |_: Request| {
//! #     Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
//! # });
//! #
//! let mut svc = (
//!     // Layer that removes all request headers with the prefix `x-foo`.`ac
//!     RemoveRequestHeaderLayer::prefix("x-foo"),
//! ).into_layer(http_client);
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
use smol_str::SmolStr;
use std::fmt;

#[derive(Debug, Clone)]
/// Layer that applies [`RemoveRequestHeader`] which removes request headers.
///
/// See [`RemoveRequestHeader`] for more details.
pub struct RemoveRequestHeaderLayer {
    mode: RemoveRequestHeaderMode,
}

#[derive(Debug, Clone)]
enum RemoveRequestHeaderMode {
    Prefix(SmolStr),
    Exact(HeaderName),
    Hop,
}

impl RemoveRequestHeaderLayer {
    /// Create a new [`RemoveRequestHeaderLayer`].
    ///
    /// Removes request headers by prefix.
    pub fn prefix(prefix: impl Into<SmolStr>) -> Self {
        Self {
            mode: RemoveRequestHeaderMode::Prefix(prefix.into()),
        }
    }

    /// Create a new [`RemoveRequestHeaderLayer`].
    ///
    /// Removes the request header with the exact name.
    pub fn exact(header: HeaderName) -> Self {
        Self {
            mode: RemoveRequestHeaderMode::Exact(header),
        }
    }

    /// Create a new [`RemoveRequestHeaderLayer`].
    ///
    /// Removes all hop-by-hop request headers as specified in [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1).
    /// This does not support other hop-by-hop headers defined in [section-14.10](https://datatracker.ietf.org/doc/html/rfc2616#section-14.10).
    #[must_use]
    pub fn hop_by_hop() -> Self {
        Self {
            mode: RemoveRequestHeaderMode::Hop,
        }
    }
}

impl<S> Layer<S> for RemoveRequestHeaderLayer {
    type Service = RemoveRequestHeader<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RemoveRequestHeader {
            inner,
            mode: self.mode.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        RemoveRequestHeader {
            inner,
            mode: self.mode,
        }
    }
}

/// Middleware that removes headers from a request.
pub struct RemoveRequestHeader<S> {
    inner: S,
    mode: RemoveRequestHeaderMode,
}

impl<S> RemoveRequestHeader<S> {
    /// Create a new [`RemoveRequestHeader`].
    ///
    /// Removes headers by prefix.
    pub fn prefix(prefix: impl Into<SmolStr>, inner: S) -> Self {
        RemoveRequestHeaderLayer::prefix(prefix.into()).into_layer(inner)
    }

    /// Create a new [`RemoveRequestHeader`].
    ///
    /// Removes the header with the exact name.
    pub fn exact(header: HeaderName, inner: S) -> Self {
        RemoveRequestHeaderLayer::exact(header).into_layer(inner)
    }

    /// Create a new [`RemoveRequestHeader`].
    ///
    /// Removes all hop-by-hop headers as specified in [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1).
    /// This does not support other hop-by-hop headers defined in [section-14.10](https://datatracker.ietf.org/doc/html/rfc2616#section-14.10).
    pub fn hop_by_hop(inner: S) -> Self {
        RemoveRequestHeaderLayer::hop_by_hop().into_layer(inner)
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug> fmt::Debug for RemoveRequestHeader<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoveRequestHeader")
            .field("inner", &self.inner)
            .field("mode", &self.mode)
            .finish()
    }
}

impl<S: Clone> Clone for RemoveRequestHeader<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            mode: self.mode.clone(),
        }
    }
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for RemoveRequestHeader<S>
where
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        ctx: Context,
        mut req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        match &self.mode {
            RemoveRequestHeaderMode::Hop => {
                super::remove_hop_by_hop_request_headers(req.headers_mut())
            }
            RemoveRequestHeaderMode::Prefix(prefix) => {
                super::remove_headers_by_prefix(req.headers_mut(), prefix)
            }
            RemoveRequestHeaderMode::Exact(header) => {
                super::remove_headers_by_exact_name(req.headers_mut(), header)
            }
        }
        self.inner.serve(ctx, req)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Body, Response};
    use rama_core::{Layer, Service, service::service_fn};
    use std::convert::Infallible;

    #[tokio::test]
    async fn remove_request_header_prefix() {
        let svc = RemoveRequestHeaderLayer::prefix("x-foo").into_layer(service_fn(
            async |_ctx: Context, req: Request| {
                assert!(req.headers().get("x-foo-bar").is_none());
                assert_eq!(
                    req.headers().get("foo").map(|v| v.to_str().unwrap()),
                    Some("bar")
                );
                Ok::<_, Infallible>(Response::new(Body::empty()))
            },
        ));
        let req = Request::builder()
            .header("x-foo-bar", "baz")
            .header("foo", "bar")
            .body(Body::empty())
            .unwrap();
        let _ = svc.serve(Context::default(), req).await.unwrap();
    }

    #[tokio::test]
    async fn remove_request_header_exact() {
        let svc = RemoveRequestHeaderLayer::exact(HeaderName::from_static("x-foo")).into_layer(
            service_fn(async |_ctx: Context, req: Request| {
                assert!(req.headers().get("x-foo").is_none());
                assert_eq!(
                    req.headers().get("x-foo-bar").map(|v| v.to_str().unwrap()),
                    Some("baz")
                );
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }),
        );
        let req = Request::builder()
            .header("x-foo", "baz")
            .header("x-foo-bar", "baz")
            .body(Body::empty())
            .unwrap();
        let _ = svc.serve(Context::default(), req).await.unwrap();
    }

    #[tokio::test]
    async fn remove_request_header_hop_by_hop() {
        let svc = RemoveRequestHeaderLayer::hop_by_hop().into_layer(service_fn(
            async |_ctx: Context, req: Request| {
                assert!(req.headers().get("connection").is_none());
                assert_eq!(
                    req.headers().get("foo").map(|v| v.to_str().unwrap()),
                    Some("bar")
                );
                Ok::<_, Infallible>(Response::new(Body::empty()))
            },
        ));
        let req = Request::builder()
            .header("connection", "close")
            .header("foo", "bar")
            .body(Body::empty())
            .unwrap();
        let _ = svc.serve(Context::default(), req).await.unwrap();
    }
}
