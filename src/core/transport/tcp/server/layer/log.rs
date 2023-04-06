use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use tokio::net::TcpStream;
use tower::Layer;

use crate::core::transport::tcp::server::{Result, Service};

pub struct LogService<S> {
    inner: S,
}

impl<S> LogService<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> Layer<S> for LogService<S> {
    type Service = Self;

    fn layer(&self, inner: S) -> Self::Service {
        Self::new(inner)
    }
}

impl<S, T> Service<T> for LogService<S>
where
    S: Service<T>,
    T: AsRef<TcpStream>,
{
    type Future = LogFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, stream: T) -> Self::Future {
        let maybe_addr = stream.as_ref().peer_addr().ok();
        tracing::info!("tcp stream accepted: {:?}", maybe_addr);
        LogFuture {
            maybe_addr,
            inner: self.inner.call(stream),
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
