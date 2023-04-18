use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
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

impl<S, State> Service<State> for LogService<S>
where
    S: Service<State>,
{
    type Error = S::Error;
    type Future = LogFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, conn: Connection<State>) -> Self::Future {
        let maybe_addr = conn.stream().peer_addr().ok();
        tracing::info!("tcp stream accepted: {:?}", maybe_addr);
        LogFuture {
            maybe_addr,
            inner: self.inner.call(conn),
        }
    }
}

pin_project! {
    pub struct LogFuture<F> {
        maybe_addr: Option<SocketAddr>,

        #[pin]
        inner: F,
    }
}

impl<F: Future> Future for LogFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => {
                tracing::trace!("tcp stream polled: {:?}", this.maybe_addr);
                Poll::Pending
            }
            Poll::Ready(output) => {
                tracing::info!("tcp stream finished: {:?}", this.maybe_addr);
                Poll::Ready(output)
            }
        }
    }
}

pub struct LogLayer;

impl<S> Layer<S> for LogLayer {
    type Service = LogService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LogService::new(inner)
    }
}
