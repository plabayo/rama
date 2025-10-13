use crate::{Body, Request, Response, body::util::BodyExt};
use opentelemetry_http::HttpClient;
use rama_core::{
    Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext},
};
use std::{fmt, pin::Pin};

/// Wrapper type which allows you to use an rama http [`Service`]
/// as an http exporter for your OTLP setup.
pub struct OtelExporter<S = ()> {
    service: S,
    handle: tokio::runtime::Handle,
}

impl<S> Clone for OtelExporter<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
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
            .field("handle", &self.handle)
            .finish()
    }
}

impl<S> OtelExporter<S> {
    /// Create a new [`OtelExporter`].
    pub fn new(service: S) -> Self {
        Self {
            service,
            handle: tokio::runtime::Handle::current(),
        }
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
        let request = Request::from(request);
        let request = request.map(Body::from);

        let svc = self.service.clone();

        // spawn actual work to ensure we run it within the tokio runtime
        let handle = self.handle.spawn(async move {
            let resp = svc.serve(request).await.map_err(Into::into)?;
            let (parts, body) = resp.into_parts();
            let body = body.collect().await?.to_bytes();
            Ok(http::Response::from_parts(parts.into(), body))
        });

        Box::pin(async move { handle.await.context("await tokio handle to fut exec")? })
    }
}
