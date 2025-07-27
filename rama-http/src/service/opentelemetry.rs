use crate::{Request, Response};
use opentelemetry_http::HttpClient;
use rama_core::{
    Context, Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext},
    rt::Executor,
};
use rama_http_types::{Body, dep::http_body_util::BodyExt};
use std::{fmt, pin::Pin};

/// Wrapper type which allows you to use an rama http [`Service`]
/// as an http exporter for your OTLP setup.
pub struct OtelExporter<S, State = ()> {
    service: S,
    ctx: Context<State>,
    handle: tokio::runtime::Handle,
}

impl<S, State> Clone for OtelExporter<S, State>
where
    S: Clone,
    State: Clone,
{
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            ctx: self.ctx.clone(),
            handle: self.handle.clone(),
        }
    }
}

impl<S, State> fmt::Debug for OtelExporter<S, State>
where
    S: fmt::Debug,
    State: fmt::Debug,
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

    /// attach `State` to this [`OtelExporter`],
    /// only useful if you use the state somewhere in your inner service.
    pub fn with_state<T>(self, state: T) -> OtelExporter<S, T> {
        let (ctx, _) = self.ctx.swap_state(state);
        OtelExporter {
            service: self.service,
            ctx,
            handle: self.handle,
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

impl<S, State> HttpClient for OtelExporter<S, State>
where
    S: fmt::Debug + Clone + Service<State, Request, Response = Response, Error: Into<BoxError>>,
    State: fmt::Debug + Send + Sync + Clone + 'static,
{
    fn send_bytes<'life0, 'async_trait>(
        &'life0 self,
        request: Request<Bytes>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Bytes>, BoxError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        let ctx = self.ctx.clone();
        let request = request.map(Body::from);

        let svc = self.service.clone();

        // spawn actual work to ensure we run it within the tokio runtime
        let handle = self.handle.spawn(async move {
            let resp = svc.serve(ctx, request).await.map_err(Into::into)?;
            let (parts, body) = resp.into_parts();
            let body = body.collect().await?.to_bytes();
            Ok(Response::from_parts(parts, body))
        });

        Box::pin(async move { handle.await.context("await tokio handle to fut exec")? })
    }
}
