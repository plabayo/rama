// TODO: get to understand tower's layer concept better...
// and if useful, apply it

use std::{
    future::Future,
    ops::{Deref, DerefMut},
    task::{Context, Poll},
};

use tokio::net::TcpStream;
use tower_service::Service as TowerService;

use super::{Error, Result};
use crate::core::transport::graceful::Token;

pub trait ServiceFactory<Stream> {
    type Service: Service<Stream>;

    fn new_service(&self) -> Result<Self::Service>;
}

pub trait PermissiveServiceFactory<Stream> {
    type Service: Service<Stream>;

    fn handle_error(&self, error: Error) -> Result<()>;
    fn new_service(&self) -> Result<Self::Service>;
}

impl<F, S, Stream> PermissiveServiceFactory<Stream> for F
where
    F: ServiceFactory<Stream, Service = S>,
    S: Service<Stream>,
{
    type Service = S;

    fn handle_error(&self, error: Error) -> Result<()> {
        tracing::error!("tcp accept service error: {}", error);
        Ok(())
    }

    fn new_service(&self) -> Result<Self::Service> {
        self.new_service()
    }
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

pub struct GracefulTcpStream(TcpStream, Token);

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
