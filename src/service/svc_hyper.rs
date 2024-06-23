use super::{Context, Service};
use crate::http::{BodyLimit, IntoResponse, Request};
use std::{convert::Infallible, future::Future, pin::Pin, sync::Arc};

/// Wrapper service that implements [`hyper::service::Service`].
///
/// ## Performance
///
/// Currently we require a clone of the service for each request.
/// This is because we need to be able to Box the future returned by the service.
/// Once we can specify such associated types using `impl Trait` we can skip this.
#[derive(Debug)]
pub(crate) struct HyperService<S, T> {
    ctx: Context<S>,
    inner: Arc<T>,
}

impl<S, T> HyperService<S, T> {
    /// Create a new [`HyperService`] from a [`Context`] and a [`Service`].
    pub(crate) fn new(ctx: Context<S>, inner: T) -> Self {
        Self {
            ctx,
            inner: Arc::new(inner),
        }
    }
}

impl<S, T, Response> hyper::service::Service<HyperRequest> for HyperService<S, T>
where
    S: Send + Sync + 'static,
    T: Service<S, Request, Response = Response, Error = Infallible>,
    Response: IntoResponse + Send + 'static,
{
    type Response = crate::http::Response;
    type Error = std::convert::Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn call(&self, req: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        let ctx = self.ctx.clone();
        let inner = self.inner.clone();

        let body_limit = ctx.get::<BodyLimit>().cloned();

        let req = match body_limit.and_then(|limit| limit.request()) {
            Some(limit) => req.map(|body| crate::http::Body::with_limit(body, limit)),
            None => req.map(crate::http::Body::new),
        };

        Box::pin(async move {
            let resp = inner.serve(ctx, req).await.into_response();
            Ok(match body_limit.and_then(|limit| limit.response()) {
                Some(limit) => resp.map(|body| crate::http::Body::with_limit(body, limit)),
                // If there is no limit, we can just return the response as is.
                None => resp,
            })
        })
    }
}

impl<S, T> Clone for HyperService<S, T>
where
    S: Clone,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            inner: self.inner.clone(),
        }
    }
}

type HyperRequest = hyper::Request<hyper::body::Incoming>;
