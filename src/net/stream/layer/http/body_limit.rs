use crate::{
    http::BodyLimit,
    net::stream::Stream,
    service::{Context, Layer, Service},
};
use std::fmt;

/// Limit the size of the request and/or response bodies.
///
/// As this layer operates on the transport layer ([`Stream`]),
/// it only is used to add the [`BodyLimit`] value to the [`Context`],
/// such that the L7 http service can apply the limit when found in that [`Context`].
///
/// [`Stream`]: crate::net::stream::Stream
/// [`Context`]: crate::service::Context`
#[derive(Debug, Clone)]
pub struct BodyLimitLayer {
    limit: BodyLimit,
}

impl BodyLimitLayer {
    /// Create a new [`BodyLimitLayer`], with the given limit to be applied to the request only.
    ///
    /// See [`BodyLimitLayer`] for more information.
    pub fn request_only(limit: usize) -> Self {
        Self {
            limit: BodyLimit::request_only(limit),
        }
    }

    /// Create a new [`BodyLimitLayer`], with the given limit to be applied to the response only.
    ///
    /// See [`BodyLimitLayer`] for more information.
    pub fn response_only(limit: usize) -> Self {
        Self {
            limit: BodyLimit::response_only(limit),
        }
    }

    /// Create a new [`BodyLimitLayer`], with the given limit to be applied to both the request and response bodies.
    ///
    /// See [`BodyLimitLayer`] for more information.
    pub fn symmetric(limit: usize) -> Self {
        Self {
            limit: BodyLimit::symmetric(limit),
        }
    }

    /// Create a new [`BodyLimitLayer`], with the given limits
    /// respectively to be applied to the request and response bodies.
    ///
    /// See [`BodyLimitLayer`] for more information.
    pub fn asymmetric(request: usize, response: usize) -> Self {
        Self {
            limit: BodyLimit::asymmetric(request, response),
        }
    }
}

impl<S> Layer<S> for BodyLimitLayer {
    type Service = BodyLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyLimitService::new(inner, self.limit)
    }
}

/// Communicate to the downstream http service to apply a limit to the body.
///
/// See [`BodyLimitService`] for more information.
#[derive(Clone)]
pub struct BodyLimitService<S> {
    inner: S,
    limit: BodyLimit,
}

impl<S> BodyLimitService<S> {
    /// Create a new [`BodyLimitService`].
    pub fn new(service: S, limit: BodyLimit) -> Self {
        Self {
            inner: service,
            limit,
        }
    }

    define_inner_service_accessors!();

    /// Create a new [`BodyLimitService`], with the given limit to be applied to the request only.
    ///
    /// See [`BodyLimitLayer`] for more information.
    pub fn request_only(service: S, limit: usize) -> Self {
        BodyLimitLayer::request_only(limit).layer(service)
    }

    /// Create a new [`BodyLimitService`], with the given limit to be applied to the response only.
    ///
    /// See [`BodyLimitLayer`] for more information.
    pub fn response_only(service: S, limit: usize) -> Self {
        BodyLimitLayer::response_only(limit).layer(service)
    }

    /// Create a new [`BodyLimitService`], with the given limit to be applied to both the request and response bodies.
    ///
    /// See [`BodyLimitLayer`] for more information.
    pub fn symmetric(service: S, limit: usize) -> Self {
        BodyLimitLayer::symmetric(limit).layer(service)
    }

    /// Create a new [`BodyLimitService`], with the given limits
    /// respectively to be applied to the request and response bodies.
    ///
    /// See [`BodyLimitLayer`] for more information.
    pub fn asymmetric(service: S, request: usize, response: usize) -> Self {
        BodyLimitLayer::asymmetric(request, response).layer(service)
    }
}

impl<S, State, IO> Service<State, IO> for BodyLimitService<S>
where
    S: Service<State, IO>,
    State: Send + Sync + 'static,
    IO: Stream,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        stream: IO,
    ) -> Result<Self::Response, Self::Error> {
        ctx.insert(self.limit);
        self.inner.serve(ctx, stream).await
    }
}

impl<S> fmt::Debug for BodyLimitService<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyLimitService")
            .field("inner", &self.inner)
            .field("limit", &self.limit)
            .finish()
    }
}
