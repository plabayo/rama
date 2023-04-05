use pin_project_lite::pin_project;
use std::{
    future::{ready, Future, Ready},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};
use tokio::net::{TcpListener, TcpStream};
use tower_service::Service as TowerService;

use super::future::ListenerFuture as TcpListenerFuture;
use crate::core::transport::{
    listener,
    tcp::server::{Error, Result},
};

pub trait Service {
    type Future: Future<Output = Result<()>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn call(&mut self, stream: TcpStream) -> Self::Future;
}

impl<S> Service for S
where
    S: TowerService<TcpStream, Response = (), Error = Error>,
{
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.poll_ready(cx)
    }

    fn call(&mut self, stream: TcpStream) -> Self::Future {
        self.call(stream)
    }
}

pub trait ServiceFactory {
    type Service: Service;
    type Future: Future<Output = Result<Self::Service>>;

    fn new_service(&self) -> Self::Future;
}

impl<S: Service + Clone> ServiceFactory for S {
    type Service = S;
    type Future = Ready<Result<Self::Service>>;

    fn new_service(&self) -> Self::Future {
        ready(Ok(self.clone()))
    }
}

pub struct Listener<F> {
    listener: Rc<TcpListener>,
    service_factory: F,
}

impl<F: ServiceFactory> listener::Listener for Listener<F>
where
    <F as ServiceFactory>::Service: Send,
    <<F as ServiceFactory>::Service as Service>::Future: Send,
{
    type Error = Error;
    type Handler = Handler<F::Service>;
    type Future = ListenerFuture<TcpListenerFuture, F::Future>;

    fn accept(&self) -> Self::Future {
        let stream = TcpListenerFuture {
            listener: self.listener.clone(),
        };
        let service = self.service_factory.new_service();
        ListenerFuture { stream, service }
    }
}

pin_project! {
    pub struct ListenerFuture<T, U> {
        #[pin]
        stream: T,
        #[pin]
        service: U,
    }
}

impl<T, U, S> Future for ListenerFuture<T, U>
where
    T: Future<Output = Result<TcpStream>>,
    U: Future<Output = Result<S>>,
{
    type Output = Result<Handler<S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match (this.stream.poll(cx), this.service.poll(cx)) {
            (Poll::Ready(Err(e)), _) => Poll::Ready(Err(e)),
            (_, Poll::Ready(Err(e))) => Poll::Ready(Err(e)),
            (Poll::Ready(Ok(stream)), Poll::Ready(Ok(service))) => {
                Poll::Ready(Ok(Handler { stream, service }))
            }
            _ => Poll::Pending,
        }
    }
}

pub struct Handler<S> {
    stream: TcpStream,
    service: S,
}

impl<S> listener::Handler for Handler<S>
where
    S: Service + Send,
    <S as Service>::Future: Send,
{
    type Error = Error;
    type Future = S::Future;

    fn handle(mut self) -> Self::Future {
        self.service.call(self.stream)
    }
}
