use pin_project_lite::pin_project;
use std::{
    future::Future,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tower_service::Service as TowerService;

use crate::core::transport::{
    listener::{Handler, HandlerStream},
    shutdown::Shutdown,
    tcp::{Error, Result, TcpStream},
};

// TODO: move handler code to handle.rs and clean that shizzle up...

pub trait GracefulService: Send + 'static {
    type Future: Future<Output = Result<()>> + Send;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn call(&mut self, stream: TcpStream) -> Self::Future;
}

impl<S: TowerService<TcpStream, Response = (), Error = Error> + Send + 'static> GracefulService
    for S
where
    S::Future: Send,
{
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.poll_ready(cx)
    }

    fn call(&mut self, stream: TcpStream) -> Self::Future {
        self.call(stream)
    }
}

pub trait Service {
    type Future: Future<Output = Result<()>> + Send;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn call(&mut self, stream: TokioTcpStream) -> Self::Future;
}

pub trait GracefulServiceFactory {
    type Service: GracefulService + Send + 'static;

    fn new_service(&self) -> Self::Service;
}

impl<S: GracefulService + Clone + 'static> GracefulServiceFactory for S {
    type Service = S;

    fn new_service(&self) -> Self::Service {
        self.clone()
    }
}

pub(crate) struct TcpHandler<S: GracefulService> {
    service: S,
    stream: TokioTcpStream,
}

impl<S: GracefulService> TcpHandler<S> {
    pub fn new(service: S, stream: TokioTcpStream) -> Self {
        Self { service, stream }
    }
}

impl<S: GracefulService + 'static> Handler for TcpHandler<S> {
    type Error = Error;
    type Future = TcpHandlerFuture<S>;

    fn handle(self, shutdown: Shutdown) -> Self::Future {
        TcpHandlerFuture {
            service: self.service,
            stream: self.stream,
            shutdown,
        }
    }
}

pin_project! {
    struct TcpHandlerFuture<S: GracefulService> {
        #[pin]
        service: S,
        stream: TokioTcpStream,
        shutdown: Shutdown,
    }
}

impl<S: GracefulService> Future for TcpHandlerFuture<S> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        ready!(this.service.poll_ready(cx))?;
        let mut fut = self
            .service
            .call(TcpStream::new(self.stream, self.shutdown));
        Pin::new(&mut Box::pin(fut)).poll(cx)
    }
}

pub(crate) struct TcpListener<F: GracefulServiceFactory> {
    service_factory: F,
    listener: TokioTcpListener,
}

impl<F: GracefulServiceFactory> TcpListener<F> {
    pub fn new(service_factory: F, listener: TokioTcpListener) -> Self {
        Self {
            service_factory,
            listener,
        }
    }
}

impl<F: GracefulServiceFactory> HandlerStream for TcpListener<F> {
    type Error = Error;
    type Handler = TcpHandler<F::Service>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Handler>>> {
        let (stream, _) = ready!(self.listener.poll_accept(cx))?;
        Poll::Ready(Some(Ok(TcpHandler::new(
            self.service_factory.new_service(),
            stream,
        ))))
    }
}
