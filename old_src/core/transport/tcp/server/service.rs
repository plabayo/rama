use std::{convert::Infallible, future::Future};

use tokio::net::TcpStream;

use crate::core::transport::tcp::server::{Connection, Stateful};

/// Factory to create Services, one service per incoming connection.
pub trait ServiceFactory<State> {
    type Error: std::error::Error + Send;
    type Service: Service<State>;

    async fn new_service(&mut self) -> Result<Self::Service, Self::Error>;

    async fn handle_accept_error(&mut self, err: std::io::Error) -> Result<(), Self::Error> {
        tracing::error!("TCP accept error: {}", err);
        Ok(())
    }

    async fn handle_service_error(
        &mut self,
        _: <Self::Service as Service<State>>::Error,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Serves an accepted TCP Connection until the end.
pub trait Service<State, Output = ()> {
    type Error: Send;

    async fn call(self, conn: Connection<State>) -> Result<Output, Self::Error>;
}

impl<T, State> ServiceFactory<State> for T
where
    T: Service<State> + Clone,
{
    type Error = Infallible;
    type Service = T;

    async fn new_service(&mut self) -> Result<Self::Service, Self::Error> {
        Ok(self.clone())
    }
}

/// A function which serves an accepted TCP Connection until the end.
#[derive(Debug, Clone)]
pub struct ServiceFn<F, T> {
    f: F,
    _t: std::marker::PhantomData<T>,
}

impl<State, Output, F, Error, Fut> ServiceFn<F, Connection<State>>
where
    F: FnOnce(Connection<State>) -> Fut,
    Error: Send,
    Fut: Future<Output=Result<Output, Error>>,
{
    pub fn new(f: F) -> Self {
        ServiceFn { f, _t: std::marker::PhantomData }
    }
}

impl<State, Output, F, Error, Fut> Service<State, Output> for ServiceFn<F, Connection<State>>
where
    F: FnOnce(Connection<State>) -> Fut,
    Error: Send,
    Fut: Future<Output=Result<Output, Error>>,
{
    type Error = Error;

    async fn call(self, conn: Connection<State>) -> Result<Output, Self::Error> {
        (self.f)(conn).await
    }
}

impl<Output, F, Error, Fut> ServiceFn<F, TcpStream>
where
    F: FnOnce(TcpStream) -> Fut,
    Error: Send,
    Fut: Future<Output=Result<Output, Error>>,
{
    pub fn new(f: F) -> Self {
        ServiceFn { f, _t: std::marker::PhantomData }
    }
}

impl<State, Output, F, Error, Fut> Service<State, Output> for ServiceFn<F, TcpStream>
where
    F: FnOnce(TcpStream) -> Fut,
    Error: Send,
    Fut: Future<Output=Result<Output, Error>>,
{
    type Error = Error;

    async fn call(self, conn: Connection<State>) -> Result<Output, Self::Error> {
        (self.f)(conn.into_stream()).await
    }
}

impl<State, Output, F, Error, Fut> ServiceFn<F, (TcpStream, State)>
where
    F: FnOnce(TcpStream, State) -> Fut,
    Error: Send,
    Fut: Future<Output=Result<Output, Error>>,
{
    pub fn new(f: F) -> Self {
        ServiceFn { f, _t: std::marker::PhantomData }
    }
}

impl<State, Output, F, Error, Fut> Service<Stateful<State>, Output> for ServiceFn<F, (TcpStream, State)>
where
    F: FnOnce(TcpStream, State) -> Fut,
    Error: Send,
    Fut: Future<Output=Result<Output, Error>>,
{
    type Error = Error;

    async fn call(self, conn: Connection<Stateful<State>>) -> Result<Output, Self::Error> {
        let (stream, _, state) = conn.into_parts();
        (self.f)(stream, state).await
    }
}
