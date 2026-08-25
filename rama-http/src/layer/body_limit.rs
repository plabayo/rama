//! Apply a request-body limit at the HTTP application layer.
//!
//! This is distinct from [`crate::BodyLimitLayer`], which attaches a
//! connection-wide request/response policy to a transport before HTTP is
//! decoded. Rama's H1/H2 adapter enforces that transport policy. This layer is
//! useful for a stricter per-route or per-service request limit.
//!
//! When both layers are present, the smaller request limit wins. This layer
//! detects an equal or stricter inherited transport limit and avoids wrapping
//! the request body a second time.
//!
//! # Example
//!
//! ```
//! use rama_http::{Body, Request, Response};
//! use std::convert::Infallible;
//! use rama_core::service::service_fn;
//! use rama_core::{Layer, Service};
//! use rama_http::layer::body_limit::BodyLimitLayer;
//!
//! async fn handle<B>(_: Request<B>) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::default()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut svc = (
//!      // Limit the request body to 2MB
//!     BodyLimitLayer::new(2*1024*1024),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service
//! let request = Request::new(Body::default());
//!
//! svc.serve(request).await?;
//! # Ok(())
//! # }
//! ```

use crate::{Body, BodyLimit, Request, StreamingBody, body::util::Limited};
use rama_core::{
    Layer, Service,
    bytes::Bytes,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _, Ingress},
};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Apply a limit to the request body's size.
///
/// See the [module docs](crate::layer::body_limit) for an example.
#[derive(Debug, Clone)]
pub struct BodyLimitLayer {
    size: usize,
}

impl BodyLimitLayer {
    /// Create a new [`BodyLimitLayer`].
    #[must_use]
    pub const fn new(size: usize) -> Self {
        Self { size }
    }
}

impl<S> Layer<S> for BodyLimitLayer {
    type Service = BodyLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyLimitService::new(inner, self.size)
    }
}

/// Apply a transformation to the request body.
///
/// See the [module docs](crate::layer::body_limit) for an example.
#[derive(Clone)]
pub struct BodyLimitService<S> {
    inner: S,
    size: usize,
}

impl<S> BodyLimitService<S> {
    /// Create a new [`BodyLimitService`].
    pub const fn new(service: S, size: usize) -> Self {
        Self {
            inner: service,
            size,
        }
    }

    define_inner_service_accessors!();
}

impl<S, ReqBody> Service<Request<ReqBody>> for BodyLimitService<S>
where
    S: Service<Request<Body>>,
    ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let inherited_limit = inherited_request_limit(req.extensions());
        let additional_limit = additional_request_limit(self.size, inherited_limit);
        let req = req.map(|body| match additional_limit {
            Some(limit) => Body::new(Limited::new(body, limit)),
            None => Body::new(body),
        });
        self.inner.serve(req).await
    }
}

fn inherited_request_limit(extensions: &Extensions) -> Option<usize> {
    extensions
        .get_ref::<Ingress<Extensions>>()
        .and_then(|ingress| ingress.get_ref::<BodyLimit>())
        .and_then(BodyLimit::request)
}

fn additional_request_limit(configured: usize, inherited: Option<usize>) -> Option<usize> {
    if configured == 0 || inherited.is_some_and(|inherited| inherited <= configured) {
        None
    } else {
        Some(configured)
    }
}

impl<S> fmt::Debug for BodyLimitService<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyLimitService")
            .field("inner", &self.inner)
            .field("size", &self.size)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{additional_request_limit, inherited_request_limit};
    use crate::BodyLimit;
    use rama_core::extensions::{Extensions, Ingress};

    #[test]
    fn inherited_and_application_limits_compose_to_the_stricter_value() {
        assert_eq!(additional_request_limit(0, None), None);
        assert_eq!(additional_request_limit(8, None), Some(8));
        assert_eq!(additional_request_limit(8, Some(5)), None);
        assert_eq!(additional_request_limit(8, Some(8)), None);
        assert_eq!(additional_request_limit(5, Some(8)), Some(5));
    }

    #[test]
    fn transport_limit_is_found_in_ingress_extensions() {
        let request_extensions = Extensions::new();
        request_extensions.insert(BodyLimit::request_only(1));
        assert_eq!(inherited_request_limit(&request_extensions), None);

        let ingress_extensions = Extensions::new();
        ingress_extensions.insert(BodyLimit::request_only(5));
        request_extensions.insert(Ingress(ingress_extensions));

        assert_eq!(inherited_request_limit(&request_extensions), Some(5));
        assert_eq!(additional_request_limit(8, Some(5)), None);
    }
}
