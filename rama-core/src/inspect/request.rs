use std::{convert::Infallible, fmt};

use crate::{Context, Layer, Service};

/// A special kind of [`Service`] which has access only to the Request,
/// but not to the Response.
///
/// Useful in case you want to explicitly
/// restrict this acccess or because the Response would
/// anyway not yet be produced at the point this inspector would be layered.
pub trait RequestInspector<State, Request>: Send + Sync + 'static {
    /// The type of error returned by the service.
    type Error: Send + Sync + 'static;

    /// Inspect the request, modify it if needed or desired, and return it.
    fn inspect_request(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<(Context<State>, Request), Self::Error>> + Send + '_;
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

impl<S, State, Request> RequestInspector<State, Request> for S
where
    S: Service<State, Request, Response = (Context<State>, Request)>,
{
    type Error = S::Error;

    fn inspect_request(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<(Context<State>, Request), Self::Error>> + Send + '_ {
        self.serve(ctx, req)
    }
}

pub struct RequestInspectorLayer<I>(I);

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

impl<I, S, State, Request> Service<State, Request> for RequestInspectorLayerService<I, S>
where
    I: RequestInspector<State, Request, Error: Into<S::Error>>,
    S: Service<State, Request>,
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self
            .request_inspector
            .inspect_request(ctx, req)
            .await
            .map_err(Into::into)?;
        self.inner.serve(ctx, req).await
    }
}
