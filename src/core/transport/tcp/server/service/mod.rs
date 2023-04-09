use std::{
    future::{self, Future},
    ops::{Deref, DerefMut},
    task::{Context, Poll},
};

use tokio::net::TcpStream;

use super::{Error, Result};
use crate::core::transport::graceful::Token;

pub mod echo;

pub trait ErrorHandler {
    type FutureAcceptErr: Future<Output = Result<()>>;
    type FutureServiceErr: Future<Output = Result<()>>;

    fn handle_accept_error(&self, err: Error) -> Self::FutureAcceptErr;
    fn handle_service_error(&self, err: Error) -> Self::FutureServiceErr;
}

pub struct LogErrorHandler;

impl ErrorHandler for LogErrorHandler {
    type FutureAcceptErr = future::Ready<Result<()>>;
    type FutureServiceErr = future::Ready<Result<()>>;

    fn handle_accept_error(&self, err: Error) -> Self::FutureAcceptErr {
        tracing::error!("tcp accept error: {}", err);
        future::ready(Ok(()))
    }

    fn handle_service_error(&self, err: Error) -> Self::FutureServiceErr {
        tracing::error!("tcp service error: {}", err);
        future::ready(Ok(()))
    }
}

pub trait ServiceFactory<Stream> {
    type Service: Service<Stream>;

    fn new_service(&mut self) -> Result<Self::Service>;
}

/// A tower-like service which is used to serve a TCP stream.
pub trait Service<Stream> {
    type Future: Future<Output = Result<()>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn call(&mut self, stream: Stream) -> Self::Future;
}

impl<I, S> ServiceFactory<S> for I
where
    I: Service<S> + Clone,
{
    type Service = I;

    fn new_service(&mut self) -> Result<Self::Service> {
        Ok(self.clone())
    }
}

pub struct GracefulTcpStream(pub(crate) TcpStream, pub(crate) Token);

impl GracefulTcpStream {
    pub fn token(&self) -> Token {
        self.1.child_token()
    }

    pub async fn shutdown(&self) {
        self.1.shutdown().await;
    }

    pub fn into_inner(self) -> (TcpStream, Token) {
        (self.0, self.1)
    }
}

impl Deref for GracefulTcpStream {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for GracefulTcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<F, Fut, Stream> Service<Stream> for F
where
    F: FnMut(Stream) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    type Future = Fut;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, stream: Stream) -> Self::Future {
        self(stream)
    }
}
