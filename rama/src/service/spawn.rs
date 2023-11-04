use crate::{
    graceful::ShutdownGuard,
    service::{Layer, Service},
    state::Extendable,
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
    S::Error: std::error::Error,
    Request: Extendable + Send + 'static,
{
    type Response = ();
    type Error = std::convert::Infallible;

    async fn call(&mut self, request: Request) -> Result<Self::Response, Self::Error> {
        let mut service = self.inner.clone();
        if let Some(guard) = request.extensions().get::<ShutdownGuard>() {
            guard.clone().spawn_task(async move {
                if let Err(err) = service.call(request).await {
                    tracing::error!(
                        error = &err as &dyn std::error::Error,
                        "graceful service error"
                    );
                }
            });
        } else {
            tokio::spawn(async move {
                if let Err(err) = service.call(request).await {
                    tracing::error!(error = &err as &dyn std::error::Error, "service error");
                }
            });
        }
        Ok(())
    }
}

pub struct SpawnLayer(());

impl SpawnLayer {
    pub fn new() -> Self {
        Self(())
    }
}

impl<S> Layer<S> for SpawnLayer {
    type Service = SpawnService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SpawnService::new(inner)
    }
}
