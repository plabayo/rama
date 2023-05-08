use tower::Layer;

use crate::core::transport::tcp::server::{Service, Connection};

pub struct LogService<S> {
    inner: S,
}

impl<S> LogService<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, State, Output> Service<State, Output> for LogService<S>
where
    S: Service<State, Output>,
{
    type Error = S::Error;

    async fn call(self, conn: Connection<State>) -> Result<Output, Self::Error> {
        let maybe_addr = conn.stream().peer_addr().ok();
        tracing::info!("tcp stream accepted: {:?}", maybe_addr);
        let res = self.inner.call(conn).await;
        tracing::info!("tcp stream finished: {:?}", maybe_addr);
        res
    }
}

pub struct LogLayer;

impl<S> Layer<S> for LogLayer {
    type Service = LogService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LogService::new(inner)
    }
}
