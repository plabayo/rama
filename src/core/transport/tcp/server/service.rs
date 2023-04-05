// TODO: get to understand tower's layer concept better...

use std::{
    future::Future,
    ops::{Deref, DerefMut},
    task::{Context, Poll},
};

use tokio::net::TcpStream;
use tower_service::Service as TowerService;

use super::{Error, Result};
use crate::core::transport::graceful::Token;

pub trait ServiceFactory {
    type Service;

    fn new_service(&self) -> Result<Self::Service>;
}

/// A tower-like service which is used to serve a TCP stream.
pub trait Service {
    type Future: Future<Output = Result<()>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn call(&mut self, stream: TcpStream) -> Self::Future;
}

impl<T> Service for T
where
    T: TowerService<TcpStream, Response = (), Error = Error>,
{
    type Future = T::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.poll_ready(cx)
    }

    fn call(&mut self, stream: TcpStream) -> Self::Future {
        self.call(stream)
    }
}

impl<S> ServiceFactory for S
where
    S: Service + Clone,
{
    type Service = S;

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

/// A tower-like service which is used to serve a TCP stream gracefully
pub trait GracefulService {
    type Future: Future<Output = Result<()>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn call(&mut self, stream: GracefulTcpStream) -> Self::Future;
}

impl<S> GracefulService for S
where
    S: Service,
{
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.poll_ready(cx)
    }

    fn call(&mut self, stream: GracefulTcpStream) -> Self::Future {
        self.call(stream.0)
    }
}
