use tower_async_layer::Layer;
use tower_async_service::Service;

pub use tokio_graceful::*;

use crate::state::Extendable;

pub struct ShutdownGuardAdder<S> {
    inner: S,
    guard: ShutdownGuard,
}

impl<S> ShutdownGuardAdder<S> {
    fn new(inner: S, guard: ShutdownGuard) -> Self {
        Self { inner, guard }
    }
}

impl<S, Request> Service<Request> for ShutdownGuardAdder<S>
where
    S: Service<Request>,
    Request: Extendable,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn call(&mut self, mut request: Request) -> Result<Self::Response, Self::Error> {
        let guard = self.guard.clone();
        request.extensions_mut().insert(guard);
        self.inner.call(request).await
    }
}

pub struct ShutdownGuardAdderLayer {
    guard: ShutdownGuard,
}

impl ShutdownGuardAdderLayer {
    pub fn new(guard: ShutdownGuard) -> Self {
        Self { guard }
    }
}

impl<S> Layer<S> for ShutdownGuardAdderLayer {
    type Service = ShutdownGuardAdder<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ShutdownGuardAdder::new(inner, self.guard.clone())
    }
}
