use rama_core::bytes::Bytes;
use rama_core::extensions::Extensions;
use rama_core::extensions::ExtensionsMut;
use rama_core::telemetry::tracing::{Instrument, trace_root_span};
use rama_core::{Service, error::BoxError};
use rama_http::StreamingBody;
use rama_http::opentelemetry::version_as_protocol_version;
use rama_http::service::web::response::IntoResponse;
use rama_http_types::{Request, Response};
use rama_utils::macros::generate_set_and_with;
use std::sync::Arc;
use std::{convert::Infallible, fmt};

pub trait HttpService<ReqBody>: sealed::Sealed<ReqBody> {
    #[doc(hidden)]
    fn serve_http(
        &self,
        req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Response, Infallible>> + Send + 'static;
}

pub struct RamaHttpService<S> {
    svc: S,
    parent_extensions: Option<Arc<Extensions>>,
}

impl<S> RamaHttpService<S> {
    pub fn new(svc: S) -> Self {
        Self {
            svc,
            parent_extensions: None,
        }
    }

    generate_set_and_with! {
        /// Set the parent Extensions that will be applied by [`RamaHttpService`] on each [`Request`]
        pub fn parent_extensions(mut self, frozen_extensions: Option<Arc<Extensions>>) -> Self {
            self.parent_extensions = frozen_extensions;
            self
        }
    }
}

impl<S> fmt::Debug for RamaHttpService<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RamaHttpService")
            .field("svc", &self.svc)
            .field("parent_extensions", &self.parent_extensions)
            .finish()
    }
}

impl<S> Clone for RamaHttpService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            svc: self.svc.clone(),
            parent_extensions: self.parent_extensions.clone(),
        }
    }
}

impl<S, ReqBody, R> HttpService<ReqBody> for RamaHttpService<S>
where
    S: Service<Request, Response = R, Error = Infallible> + Clone,
    ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    R: IntoResponse + Send + 'static,
{
    fn serve_http(
        &self,
        req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Response, Infallible>> + Send + 'static {
        let Self {
            svc,
            parent_extensions,
        } = self.clone();
        async move {
            let mut req = req.map(rama_http_types::Body::new);
            if let Some(parent_extensions) = parent_extensions {
                req.extensions_mut()
                    .set_parent_extensions(parent_extensions);
            }

            let span = trace_root_span!(
                "http::serve",
                otel.kind = "server",
                http.request.method = %req.method().as_str(),
                url.full = %req.uri(),
                url.path = %req.uri().path(),
                url.query = req.uri().query().unwrap_or_default(),
                url.scheme = %req.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
                network.protocol.name = "http",
                network.protocol.version = version_as_protocol_version(req.version()),
            );

            Ok(svc.serve(req).instrument(span).await?.into_response())
        }
    }
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct VoidHttpService;

impl<ReqBody> HttpService<ReqBody> for VoidHttpService
where
    ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    #[allow(clippy::manual_async_fn)]
    fn serve_http(
        &self,
        _req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Response, Infallible>> + Send + 'static {
        async move { Ok(Response::new(rama_http_types::Body::empty())) }
    }
}

mod sealed {
    use super::*;

    pub trait Sealed<T>: Send + Sync + 'static {}

    impl<S, ReqBody, R> Sealed<ReqBody> for RamaHttpService<S>
    where
        S: Service<Request, Response = R, Error = Infallible> + Clone,
        ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
        R: IntoResponse + Send + 'static,
    {
    }

    impl<ReqBody> Sealed<ReqBody> for VoidHttpService where
        ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static
    {
    }
}
