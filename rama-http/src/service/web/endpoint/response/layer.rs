use crate::service::web::response::IntoResponse;
use rama_core::{Layer, Service};
use rama_http_types::{Request, Response};

/// A [`Service`] that maps response for an inner service using [`IntoResponse`].
#[derive(Debug, Clone)]
pub struct IntoResponseService<S>(S);

impl<S, R, E> IntoResponseService<S>
where
    S: Service<Request, Output = R, Error = E>,
    R: IntoResponse + Send + Sync + 'static,
{
    /// Create a new [`IntoResponseService`] with the given service.
    #[inline(always)]
    pub fn new(svc: S) -> Self {
        Self(svc)
    }
}

impl<S, I, O, E> Service<I> for IntoResponseService<S>
where
    S: Service<I, Output = O, Error = E>,
    I: Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    E: Send + 'static,
{
    type Output = Response;
    type Error = E;

    async fn serve(&self, req: I) -> Result<Self::Output, Self::Error> {
        self.0.serve(req).await.map(IntoResponse::into_response)
    }
}

/// A [`Layer`] that maps response for an inner service using [`IntoResponse`].
#[derive(Debug, Clone)]
pub struct IntoResponseLayer;

impl<S> Layer<S> for IntoResponseLayer {
    type Service = IntoResponseService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IntoResponseService(inner)
    }
}
