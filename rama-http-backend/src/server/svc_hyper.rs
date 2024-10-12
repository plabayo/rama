use rama_core::{context::StateTransformer, Context, Service};
use rama_http_types::{BodyLimit, IntoResponse, Request};
use std::{convert::Infallible, fmt, future::Future, pin::Pin, sync::Arc};

/// Wrapper service that implements [`hyper::service::Service`].
///
/// ## Performance
///
/// Currently we require a clone of the service for each request.
/// This is because we need to be able to Box the future returned by the service.
/// Once we can specify such associated types using `impl Trait` we can skip this.
pub(crate) struct HyperService<S, T, R> {
    ctx: Context<S>,
    inner: Arc<T>,
    state_transformer: R,
}

impl<S, T, R> HyperService<S, T, R> {
    /// Create a new [`HyperService`] from a [`Context`] and a [`Service`].
    pub(crate) fn new(ctx: Context<S>, inner: T, state_transformer: R) -> Self {
        Self {
            ctx,
            inner: Arc::new(inner),
            state_transformer,
        }
    }
}

impl<S, T, R, Response> hyper::service::Service<HyperRequest> for HyperService<S, T, R>
where
    S: Clone + Send + Sync + 'static,
    T: Service<R::Output, Request, Response = Response, Error = Infallible>,
    R: StateTransformer<S, Error = std::convert::Infallible>,
    Response: IntoResponse + Send + 'static,
{
    type Response = rama_http_types::Response;
    type Error = std::convert::Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn call(&self, req: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        let state = self
            .state_transformer
            .transform_state(&self.ctx)
            .expect("infallible");
        let ctx = self.ctx.clone_with_state(state);

        let inner = self.inner.clone();

        let body_limit = ctx.get::<BodyLimit>().cloned();

        let req = match body_limit.and_then(|limit| limit.request()) {
            Some(limit) => req.map(|body| rama_http_types::Body::with_limit(body, limit)),
            None => req.map(rama_http_types::Body::new),
        };

        Box::pin(async move {
            let resp = inner.serve(ctx, req).await.into_response();
            Ok(match body_limit.and_then(|limit| limit.response()) {
                Some(limit) => resp.map(|body| rama_http_types::Body::with_limit(body, limit)),
                // If there is no limit, we can just return the response as is.
                None => resp,
            })
        })
    }
}

impl<S, T, R> fmt::Debug for HyperService<S, T, R>
where
    S: fmt::Debug,
    T: fmt::Debug,
    R: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HyperService")
            .field("ctx", &self.ctx)
            .field("inner", &self.inner)
            .field("state_transformer", &self.state_transformer)
            .finish()
    }
}

impl<S, T, R> Clone for HyperService<S, T, R>
where
    S: Clone,
    T: Clone,
    R: Clone,
{
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            inner: self.inner.clone(),
            state_transformer: self.state_transformer.clone(),
        }
    }
}

type HyperRequest = hyper::Request<hyper::body::Incoming>;
