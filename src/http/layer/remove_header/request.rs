//! Remove headers from a request.
//!
//! # Example
//!
//! ```
//! use rama::http::layer::remove_header::RemoveRequestHeaderLayer;
//! use rama::http::{Body, Request, Response, header::{self, HeaderValue}};
//! use rama::service::{Context, Service, ServiceBuilder, service_fn};
//! use rama::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # let http_client = service_fn(|_: Request| async move {
//! #     Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
//! # });
//! #
//! let mut svc = ServiceBuilder::new()
//!     .layer(
//!         // Layer that removes all request headers with the prefix `x-foo`.
//!         RemoveRequestHeaderLayer::prefix("x-foo")
//!     )
//!     .service(http_client);
//!
//! let request = Request::new(Body::empty());
//!
//! let response = svc.serve(Context::default(), request).await?;
//! #
//! # Ok(())
//! # }
//! ```

use crate::http::{Request, Response};
use crate::service::{Context, Layer, Service};
use std::future::Future;

#[derive(Debug, Clone)]
/// Layer that applies [`RemoveRequestHeader`] which removes request headers.
///
/// See [`RemoveRequestHeader`] for more details.
pub struct RemoveRequestHeaderLayer {
    mode: RemoveRequestHeaderMode,
}

#[derive(Debug, Clone)]
enum RemoveRequestHeaderMode {
    Prefix(String),
    Exact(String),
    Hop,
}

impl RemoveRequestHeaderLayer {
    /// Create a new [`RemoveRequestHeaderLayer`].
    ///
    /// Removes request headers by prefix.
    pub fn prefix(prefix: impl AsRef<str>) -> Self {
        Self {
            mode: RemoveRequestHeaderMode::Prefix(prefix.as_ref().to_lowercase()),
        }
    }

    /// Create a new [`RemoveRequestHeaderLayer`].
    ///
    /// Removes the request header with the exact name.
    pub fn exact(header: impl AsRef<str>) -> Self {
        Self {
            mode: RemoveRequestHeaderMode::Exact(header.as_ref().to_lowercase()),
        }
    }

    /// Create a new [`RemoveRequestHeaderLayer`].
    ///
    /// Removes all hop-by-hop request headers as specified in [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1).
    /// This does not support other hop-by-hop headers defined in [section-14.10](https://datatracker.ietf.org/doc/html/rfc2616#section-14.10).
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
}

/// Middleware that removes headers from a request.
#[derive(Debug, Clone)]
pub struct RemoveRequestHeader<S> {
    inner: S,
    mode: RemoveRequestHeaderMode,
}

impl<S> RemoveRequestHeader<S> {
    /// Create a new [`RemoveRequestHeader`].
    ///
    /// Removes headers by prefix.
    pub fn prefix(prefix: impl AsRef<str>, inner: S) -> Self {
        RemoveRequestHeaderLayer::prefix(prefix).layer(inner)
    }

    /// Create a new [`RemoveRequestHeader`].
    ///
    /// Removes the header with the exact name.
    pub fn exact(header: impl AsRef<str>, inner: S) -> Self {
        RemoveRequestHeaderLayer::exact(header).layer(inner)
    }

    /// Create a new [`RemoveRequestHeader`].
    ///
    /// Removes all hop-by-hop headers as specified in [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1).
    /// This does not support other hop-by-hop headers defined in [section-14.10](https://datatracker.ietf.org/doc/html/rfc2616#section-14.10).
    pub fn hop_by_hop(inner: S) -> Self {
        RemoveRequestHeaderLayer::hop_by_hop().layer(inner)
    }

    define_inner_service_accessors!();
}

impl<ReqBody, ResBody, State, S> Service<State, Request<ReqBody>> for RemoveRequestHeader<S>
where
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    State: Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        ctx: Context<State>,
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
    use http::Response;

    use super::*;
    use crate::{
        http::Body,
        service::{service_fn, Service, ServiceBuilder},
    };
    use std::convert::Infallible;

    #[tokio::test]
    async fn remove_request_header_prefix() {
        let svc = ServiceBuilder::new()
            .layer(RemoveRequestHeaderLayer::prefix("x-foo"))
            .service(service_fn(|_ctx: Context<()>, req: Request| async move {
                assert!(req.headers().get("x-foo-bar").is_none());
                assert_eq!(
                    req.headers().get("foo").map(|v| v.to_str().unwrap()),
                    Some("bar")
                );
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let req = Request::builder()
            .header("x-foo-bar", "baz")
            .header("foo", "bar")
            .body(Body::empty())
            .unwrap();
        let _ = svc.serve(Context::default(), req).await.unwrap();
    }

    #[tokio::test]
    async fn remove_request_header_exact() {
        let svc = ServiceBuilder::new()
            .layer(RemoveRequestHeaderLayer::exact("x-foo"))
            .service(service_fn(|_ctx: Context<()>, req: Request| async move {
                assert!(req.headers().get("x-foo").is_none());
                assert_eq!(
                    req.headers().get("x-foo-bar").map(|v| v.to_str().unwrap()),
                    Some("baz")
                );
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let req = Request::builder()
            .header("x-foo", "baz")
            .header("x-foo-bar", "baz")
            .body(Body::empty())
            .unwrap();
        let _ = svc.serve(Context::default(), req).await.unwrap();
    }

    #[tokio::test]
    async fn remove_request_header_hop_by_hop() {
        let svc = ServiceBuilder::new()
            .layer(RemoveRequestHeaderLayer::hop_by_hop())
            .service(service_fn(|_ctx: Context<()>, req: Request| async move {
                assert!(req.headers().get("connection").is_none());
                assert_eq!(
                    req.headers().get("foo").map(|v| v.to_str().unwrap()),
                    Some("bar")
                );
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let req = Request::builder()
            .header("connection", "close")
            .header("foo", "bar")
            .body(Body::empty())
            .unwrap();
        let _ = svc.serve(Context::default(), req).await.unwrap();
    }
}
