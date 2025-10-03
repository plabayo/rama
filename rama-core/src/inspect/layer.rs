use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

use super::RequestInspector;
use crate::{Layer, Service};

/// wrapper to turn any [`RequestInspector`] into a [`Layer`].
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

    fn into_layer(self, inner: S) -> Self::Service {
        Self::Service {
            request_inspector: self.0,
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

impl<I, S, RequestIn> Service<RequestIn> for RequestInspectorLayerService<I, S>
where
    I: RequestInspector<RequestIn>,
    S: Service<I::RequestOut, Error: Into<I::Error>>,
    RequestIn: Send + 'static,
{
    type Response = S::Response;
    type Error = I::Error;

    async fn serve(&self, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let req = self.request_inspector.inspect_request(req).await?;
        self.inner.serve(req).await.map_err(Into::into)
    }
}
