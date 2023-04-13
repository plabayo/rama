use std::{
    future::{self, Future},
    ops::{Deref, DerefMut},
    task::{Context, Poll}, convert::Infallible,
};

use tokio::net::TcpStream;

use crate::core::{
    BoxError,
    transport::graceful::{Graceful, ShutdownFuture, Token},
};

pub trait ErrorHandler {
    type AcceptError;
    type AcceptFuture: Future<Output = Result<(), Self::AcceptError>>;

    type ServiceError;
    type ServiceFuture: Future<Output = Result<(), Self::ServiceError>>;

    fn handle_accept_error(&self, err: BoxError) -> Self::AcceptFuture;
    fn handle_service_error(&self, err: BoxError) -> Self::ServiceFuture;
}

pub struct LogErrorHandler;

impl ErrorHandler for LogErrorHandler {
    type AcceptError = BoxError;
    type AcceptFuture = future::Ready<Result<(), BoxError>>;

    type ServiceError = BoxError;
    type ServiceFuture = future::Ready<Result<(), BoxError>>;

    fn handle_accept_error(&self, err: BoxError) -> Self::AcceptFuture {
        tracing::error!("tcp accept error: {}", err);
        future::ready(Ok(()))
    }

    fn handle_service_error(&self, err: BoxError) -> Self::ServiceFuture {
        tracing::error!("tcp service error: {}", err);
        future::ready(Ok(()))
    }
}

pub trait ServiceFactory<Stream> {
    type Error;
    type Service: Service<Stream>;
    type Future: Future<Output = Result<Self::Service, Self::Error>>;

    fn new_service(&mut self) -> Self::Future;
}

/// A tower-like service which is used to serve a TCP stream.
pub trait Service<Stream> {
    type Error;
    type Future: Future<Output = Result<(), Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    fn call(&mut self, stream: Stream) -> Self::Future;
}

impl<T, Stream> ServiceFactory<Stream> for T
where
    T: Service<Stream> + Clone,
{
    type Error = Infallible;
    type Service = T;
    type Future = future::Ready<Result<Self::Service, Self::Error>>;

    fn new_service(&mut self) -> Self::Future {
        future::ready(Ok(self.clone()))
    }
}

pub struct GracefulTcpStream(pub(crate) TcpStream, pub(crate) Token);

impl<'a> Graceful<'a> for GracefulTcpStream {
    fn token(&self) -> Token {
        self.1.child_token()
    }

    fn shutdown(&self) -> ShutdownFuture<'a> {
        self.1.shutdown()
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

impl<F, Fut, Stream, Error> Service<Stream> for F
where
    F: FnMut(Stream) -> Fut,
    Fut: Future<Output = Result<(), Error>>,
{
    type Error = Error;
    type Future = Fut;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, stream: Stream) -> Self::Future {
        self(stream)
    }
}
