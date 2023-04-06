use std::{
    future::{self, Future},
    ops::{Deref, DerefMut},
    task::{Context, Poll},
};

use tokio::net::TcpStream;
use tower_service::Service as TowerService;

use super::{Error, Result};
use crate::core::transport::graceful::Token;

pub trait ErrorHandler {
    type FutureAcceptErr: Future<Output = Result<()>>;
    type FutureServiceErr: Future<Output = Result<()>>;

    fn handle_accept_error(&self, err: Error) -> Self::FutureAcceptErr;
    fn handle_service_error(&self, err: Error) -> Self::FutureServiceErr;
}

pub(crate) struct LogErrorHandler;

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

    fn new_service(&self) -> Result<Self::Service>;
}

/// A tower-like service which is used to serve a TCP stream.
pub trait Service<Stream> {
    type Future: Future<Output = Result<()>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn call(&mut self, stream: Stream) -> Self::Future;
}

impl<T, S> Service<S> for T
where
    T: TowerService<S, Response = (), Error = Error>,
{
    type Future = T::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.poll_ready(cx)
    }

    fn call(&mut self, stream: S) -> Self::Future {
        self.call(stream)
    }
}

impl<I, S> ServiceFactory<S> for I
where
    I: Service<S> + Clone,
{
    type Service = I;

    fn new_service(&self) -> Result<Self::Service> {
        Ok(self.clone())
    }
}

pub struct GracefulTcpStream(pub(crate) TcpStream, pub(crate) Token);

impl GracefulTcpStream {
    pub fn token(&self) -> Token {
        self.1.child_token()
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
