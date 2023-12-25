use crate::{
    rt::graceful::ShutdownGuard,
    service::{Layer, Service},
    state::Extendable,
    BoxError,
};

pub struct SpawnService<S> {
    inner: S,
}

impl<S> SpawnService<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, Request> Service<Request> for SpawnService<S>
where
    S: Service<Request, call(): Send> + Clone + Send + 'static,
    S::Error: Into<BoxError>,
    Request: Extendable + Send + 'static,
{
    type Response = ();
    type Error = std::convert::Infallible;

    async fn call(&self, request: Request) -> Result<Self::Response, Self::Error> {
        let service = self.inner.clone();
        if let Some(guard) = request.extensions().get::<ShutdownGuard>() {
            guard.clone().spawn_task(async move {
                if let Err(err) = service.call(request).await {
                    let err = err.into();
                    tracing::error!(error = err, "graceful service error");
                }
            });
        } else {
            // TODO: ideally we spawn not using this global spawn handle,
            // and instead get it from the request.
            crate::rt::spawn(async move {
                if let Err(err) = service.call(request).await {
                    let err = err.into();
                    tracing::error!(error = err, "service error");
                }
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SpawnLayer;

impl SpawnLayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SpawnLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for SpawnLayer {
    type Service = SpawnService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SpawnService::new(inner)
    }
}
