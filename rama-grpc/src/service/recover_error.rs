//! Middleware which recovers from error and returns a Grpc status.

use rama_core::{Layer, Service, error::BoxError};
use rama_http::body::OptionalBody;
use rama_http_types::Response;

use crate::Status;

/// Layer which applies the [`RecoverError`] middleware.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct RecoverErrorLayer;

impl RecoverErrorLayer {
    /// Create a new `RecoverErrorLayer`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RecoverErrorLayer {
    type Service = RecoverError<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RecoverError::new(inner)
    }
}

/// Middleware that attempts to recover from service errors by turning them into a response built
/// from the [`Status`].
#[derive(Debug, Clone)]
pub struct RecoverError<S> {
    inner: S,
}

impl<S> RecoverError<S> {
    /// Create a new `RecoverError` middleware.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, Req, ResBody> Service<Req> for RecoverError<S>
where
    S: Service<Req, Output = Response<ResBody>, Error: Into<BoxError>>,
    Req: Send + 'static,
    ResBody: Send + Sync + 'static,
{
    type Output = Response<OptionalBody<ResBody>>;
    type Error = BoxError;

    async fn serve(&self, req: Req) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(req).await {
            Ok(response) => {
                let response = response.map(OptionalBody::some);
                Ok(response)
            }
            Err(err) => match Status::try_from_error(err.into()) {
                Ok(status) => Ok(status.try_into_http()?),
                Err(err) => Err(err),
            },
        }
    }
}
