use rama_core::error::{BoxError, OpaqueError};
use rama_core::{Layer, Service};
use rama_http::HeaderValue;
use rama_http::layer::version_adapter::adapt_request_version;
use rama_http_types::{Request, Response, Version, header::CONTENT_TYPE};

use super::GrpcWebCall;
use super::call::content_types::GRPC_WEB;

/// Layer implementing the grpc-web protocol for clients.
#[derive(Debug, Default, Clone)]
pub struct GrpcWebClientLayer {
    _priv: (),
}

impl GrpcWebClientLayer {
    /// Create a new grpc-web for clients layer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> Layer<S> for GrpcWebClientLayer {
    type Service = GrpcWebClientService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcWebClientService::new(inner)
    }
}

/// A [`Service`] that wraps some inner http service that will
/// coerce requests coming from `rama-grpc` clients into proper
/// `grpc-web` requests.
#[derive(Debug, Clone)]
pub struct GrpcWebClientService<S> {
    inner: S,
}

impl<S> GrpcWebClientService<S> {
    /// Create a new grpc-web for clients service.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, B1, B2> Service<Request<B1>> for GrpcWebClientService<S>
where
    S: Service<Request<GrpcWebCall<B1>>, Output = Response<B2>, Error: Into<BoxError>>,
    B1: Send + 'static,
    B2: Send + 'static,
{
    type Output = Response<GrpcWebCall<B2>>;
    type Error = OpaqueError;

    async fn serve(&self, mut req: Request<B1>) -> Result<Self::Output, Self::Error> {
        adapt_request_version(&mut req, Version::HTTP_11)?;

        req.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(GRPC_WEB));

        let req = req.map(GrpcWebCall::client_request);

        let resp = self
            .inner
            .serve(req)
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))?;
        Ok(resp.map(GrpcWebCall::client_response))
    }
}
