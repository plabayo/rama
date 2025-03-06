use rama_utils::macros::define_inner_service_accessors;
use std::{convert::Infallible, fmt};

use crate::{Context, Layer, Service};

/// A special kind of [`Service`] which has access only to the Request,
/// but not to the Response.
///
/// Useful in case you want to explicitly
/// restrict this acccess or because the Response would
/// anyway not yet be produced at the point this inspector would be layered.
pub trait RequestInspector<StateIn, RequestIn>: Send + Sync + 'static {
    /// The type of error returned by the service.
    type Error: Send + Sync + 'static;
    type RequestOut: Send + 'static;
    type StateOut: Clone + Send + Sync + 'static;

    /// Inspect the request, modify it if needed or desired, and return it.
    fn inspect_request(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> impl Future<Output = Result<(Context<Self::StateOut>, Self::RequestOut), Self::Error>> + Send + '_;
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// identity [`RequestInspector`]
pub struct Identity;

impl Identity {
    #[inline]
    pub fn new() -> Self {
        Self
    }
}

impl<State, Request> Service<State, Request> for Identity
where
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Error = Infallible;
    type Response = (Context<State>, Request);

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<(Context<State>, Request), Self::Error> {
        Ok((ctx, req))
    }
}

impl<S, StateIn, StateOut, RequestIn, RequestOut> RequestInspector<StateIn, RequestIn> for S
where
    S: Service<StateIn, RequestIn, Response = (Context<StateOut>, RequestOut)>,
    RequestIn: Send + 'static,
    RequestOut: Send + 'static,
    StateIn: Clone + Send + Sync + 'static,
    StateOut: Clone + Send + Sync + 'static,
{
    type Error = S::Error;
    type RequestOut = RequestOut;
    type StateOut = StateOut;

    fn inspect_request(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> impl Future<Output = Result<(Context<Self::StateOut>, Self::RequestOut), Self::Error>> + Send + '_
    {
        self.serve(ctx, req)
    }
}

pub struct RequestInspectorLayer<I>(I);

impl<I> RequestInspectorLayer<I> {
    pub fn new(inspector: I) -> Self {
        Self(inspector)
    }
}

impl<I> From<I> for RequestInspectorLayer<I> {
    fn from(inspector: I) -> Self {
        Self(inspector)
    }
}

impl<I: fmt::Debug> fmt::Debug for RequestInspectorLayer<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RequestInspectorLayer")
            .field(&self.0)
            .finish()
    }
}

impl<I: Clone> Clone for RequestInspectorLayer<I> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<I: Clone, S> Layer<S> for RequestInspectorLayer<I> {
    type Service = RequestInspectorLayerService<I, S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            request_inspector: self.0.clone(),
            inner,
        }
    }
}

pub struct RequestInspectorLayerService<I, S> {
    request_inspector: I,
    inner: S,
}

impl<I, S> RequestInspectorLayerService<I, S> {
    define_inner_service_accessors!();
}

impl<I: fmt::Debug, S: fmt::Debug> fmt::Debug for RequestInspectorLayerService<I, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestInspectorLayerService")
            .field("request_inspector", &self.request_inspector)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<I: Clone, S: Clone> Clone for RequestInspectorLayerService<I, S> {
    fn clone(&self) -> Self {
        Self {
            request_inspector: self.request_inspector.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<I, S, StateIn, RequestIn> Service<StateIn, RequestIn> for RequestInspectorLayerService<I, S>
where
    I: RequestInspector<StateIn, RequestIn>,
    S: Service<I::StateOut, I::RequestOut, Error: Into<I::Error>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Response = S::Response;
    type Error = I::Error;

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.request_inspector.inspect_request(ctx, req).await?;
        self.inner.serve(ctx, req).await.map_err(Into::into)
    }
}
