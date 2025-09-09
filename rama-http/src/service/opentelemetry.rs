use crate::{Body, Request, Response, body::util::BodyExt};
use opentelemetry_http::HttpClient;
use rama_core::{
    Context, Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext},
    rt::Executor,
};
use std::{fmt, pin::Pin};

/// Wrapper type which allows you to use an rama http [`Service`]
/// as an http exporter for your OTLP setup.
pub struct OtelExporter<S = ()> {
    service: S,
    ctx: Context,
    handle: tokio::runtime::Handle,
}

impl<S> Clone for OtelExporter<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            ctx: self.ctx.clone(),
            handle: self.handle.clone(),
        }
    }
}

impl<S> fmt::Debug for OtelExporter<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtelExporter")
            .field("service", &self.service)
            .field("ctx", &self.ctx)
            .field("handle", &self.handle)
            .finish()
    }
}

impl<S> OtelExporter<S> {
    /// Create a new [`OtelExporter`].
    pub fn new(service: S) -> Self {
        Self {
            service,
            ctx: Context::default(),
            handle: tokio::runtime::Handle::current(),
        }
    }

    /// Set a new [`Executor`] to the [`OtelExporter`].
    ///
    /// Useful in acse you want to make it graceful,
    /// most likely it is however not what you really want to do,
    /// given most exporters live on their own island.
    pub fn set_executor(&mut self, exec: Executor) -> &mut Self {
        self.ctx.set_executor(exec);
        self
    }

    /// Set a new [`Executor`] to the [`OtelExporter`].
    ///
    /// Useful in acse you want to make it graceful,
    /// most likely it is however not what you really want to do,
    /// given most exporters live on their own island.
    #[must_use]
    pub fn with_executor(mut self, exec: Executor) -> Self {
        self.ctx.set_executor(exec);
        self
    }
}

impl<S> HttpClient for OtelExporter<S>
where
    S: fmt::Debug
        + Clone
        + Service<Request<Body>, Response = Response<Body>, Error: Into<BoxError>>,
{
    fn send_bytes<'life0, 'async_trait>(
        &'life0 self,
        request: http::Request<Bytes>,
    ) -> Pin<Box<dyn Future<Output = Result<http::Response<Bytes>, BoxError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        let ctx = self.ctx.clone();
        let request = Request::from(request);
        let request = request.map(Body::from);

        let svc = self.service.clone();

        // spawn actual work to ensure we run it within the tokio runtime
        let handle = self.handle.spawn(async move {
            let resp = svc.serve(ctx, request).await.map_err(Into::into)?;
            let (parts, body) = resp.into_parts();
            let body = body.collect().await?.to_bytes();
            Ok(http::Response::from_parts(parts.into(), body))
        });

        Box::pin(async move { handle.await.context("await tokio handle to fut exec")? })
    }
}
