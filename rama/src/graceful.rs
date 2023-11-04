pub use tokio_graceful::{Shutdown, ShutdownGuard, WeakShutdownGuard};

use crate::{
    service::{Layer, Service},
    state::Extendable,
};

pub struct ShutdownGuardAdder<S> {
    inner: S,
    guard: WeakShutdownGuard,
}

impl<S> ShutdownGuardAdder<S> {
    fn new(inner: S, guard: WeakShutdownGuard) -> Self {
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
        let guard = self.guard.clone().upgrade();
        request.extensions_mut().insert(guard);
        self.inner.call(request).await
    }
}

pub struct ShutdownGuardAdderLayer {
    guard: WeakShutdownGuard,
}

impl ShutdownGuardAdderLayer {
    pub fn new(guard: WeakShutdownGuard) -> Self {
        Self { guard }
    }
}

impl<S> Layer<S> for ShutdownGuardAdderLayer {
    type Service = ShutdownGuardAdder<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ShutdownGuardAdder::new(inner, self.guard.clone())
    }
}
