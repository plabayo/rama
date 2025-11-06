use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_error::BoxError;
use rama_error::OpaqueError;
use rama_http_types::Version;
use rama_http_types::{Request, Response};

#[derive(Clone, Debug)]
pub struct ResponseVersionAdapter<S> {
    inner: S,
}

impl<S> ResponseVersionAdapter<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, Body> Service<Request<Body>> for ResponseVersionAdapter<S>
where
    S: Service<Request<Body>, Response = Response, Error: Into<BoxError>>,
    Body: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Response, Self::Error> {
        let original_req_version = req.version();

        let mut resp = self.inner.serve(req).await.map_err(Into::into)?;
        let response_version = resp.version();

        if original_req_version == response_version {
            tracing::trace!(
                "response version {response_version:?} matches original http request version, it will remain unchanged",
            );
        } else {
            tracing::trace!(
                "change the response http version {response_version:?} into the original http request version {original_req_version:?}",
            );
            adapt_response_version(&mut resp, original_req_version)?;
        }

        Ok(resp)
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct ResponseVersionAdapterLayer;

impl<S> Layer<S> for ResponseVersionAdapterLayer {
    type Service = ResponseVersionAdapter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseVersionAdapter { inner }
    }
}

pub fn adapt_response_version<Body>(
    response: &mut Response<Body>,
    target_version: Version,
) -> Result<(), OpaqueError> {
    *response.version_mut() = target_version;
    Ok(())
}
