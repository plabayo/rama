use std::{
    convert::Infallible,
    future::{self, Future},
    task::{Context, Poll}, pin::Pin,
};

use tokio::net::TcpStream;

use crate::core::transport::{
    graceful::Token,
    tcp::server::{Connection, Stateful, Stateless},
};

pub type BoxErrorFuture<Error: std::error::Error + Send> = Pin<Box<dyn Future<Output = Result<(), Error>>>>;

/// Factory to create Services, one service per incoming connection.
pub trait ServiceFactory<State> {
    type Error: std::error::Error + Send;
    type Service: Service<State>;
    type Future: Future<Output = Result<Self::Service, Self::Error>>;

    fn new_service(&mut self) -> Self::Future;

    fn handle_accept_error(&mut self, err: std::io::Error) -> BoxErrorFuture<Self::Error> {
        tracing::error!("TCP accept error: {}", err);
        Box::pin(future::ready(Ok(())))
    }

    fn handle_service_error(
        &mut self,
        _: <Self::Service as Service<State>>::Error,
    ) -> BoxErrorFuture<Self::Error> {
        Box::pin(future::ready(Ok(())))
    }
}

/// A tower-like service which is used to serve a TCP stream.
pub trait Service<State> {
    type Error: std::error::Error + Send;
    type Future: Future<Output = Result<(), Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    fn call(&mut self, conn: Connection<State>) -> Self::Future;
}

impl<T, State> ServiceFactory<State> for T
where
    T: Service<State> + Clone,
{
    type Error = Infallible;
    type Service = T;
    type Future = future::Ready<Result<Self::Service, Self::Error>>;

    fn new_service(&mut self) -> Self::Future {
        future::ready(Ok(self.clone()))
    }
}

impl<F, Fut, State, Error> Service<State> for F
where
    F: FnMut(Connection<State>) -> Fut,
    Fut: Future<Output = Result<(), Error>>,
    Error: std::error::Error + Send
{
    type Error = Error;
    type Future = Fut;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, conn: Connection<State>) -> Self::Future {
        self(conn)
    }
}

// impl<F, Fut, State, Error> Service<State> for F
// where
//     F: FnMut(TcpStream) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<State>) -> Self::Future {
//         self(conn.into_stream())
//     }
// }

// impl<F, Fut, Error> Service<Stateless> for F
// where
//     F: FnMut(Token, TcpStream) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<Stateless>) -> Self::Future {
//         let (state, token) = conn.into_parts();
//         self(token, state)
//     }
// }

// impl<F, Fut, Error> Service<Stateless> for F
// where
//     F: FnMut(TcpStream, Token) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<Stateless>) -> Self::Future {
//         let (state, token) = conn.into_parts();
//         self(state, token)
//     }
// }

// impl<F, Fut, State, Error> Service<Stateful<State>> for F
// where
//     F: FnMut(TcpStream, Token) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<Stateful<State>>) -> Self::Future {
//         let (state, token, _) = conn.into_parts();
//         self(state, token)
//     }
// }

// impl<F, Fut, State, Error> Service<Stateful<State>> for F
// where
//     F: FnMut(Token, TcpStream) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<Stateful<State>>) -> Self::Future {
//         let (state, token, _) = conn.into_parts();
//         self(token, state)
//     }
// }

// impl<F, Fut, State, Error> Service<Stateful<State>> for F
// where
//     F: FnMut(TcpStream, State) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<Stateful<State>>) -> Self::Future {
//         let (stream, _, state) = conn.into_parts();
//         self(stream, state)
//     }
// }

// impl<F, Fut, State, Error> Service<Stateful<State>> for F
// where
//     F: FnMut(TcpStream, State, Token) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<Stateful<State>>) -> Self::Future {
//         let (stream, token, state) = conn.into_parts();
//         self(stream, state, token)
//     }
// }

// impl<F, Fut, State, Error> Service<Stateful<State>> for F
// where
//     F: FnMut(TcpStream, Token, State) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<Stateful<State>>) -> Self::Future {
//         let (stream, token, state) = conn.into_parts();
//         self(stream, token, state)
//     }
// }

// impl<F, Fut, State, Error> Service<Stateful<State>> for F
// where
//     F: FnMut(Token, TcpStream, State) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<Stateful<State>>) -> Self::Future {
//         let (stream, token, state) = conn.into_parts();
//         self(token, stream, state)
//     }
// }

// impl<F, Fut, State, Error> Service<Stateful<State>> for F
// where
//     F: FnMut(Token, State, TcpStream) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<Stateful<State>>) -> Self::Future {
//         let (stream, token, state) = conn.into_parts();
//         self(token, state, stream)
//     }
// }

// impl<F, Fut, State, Error> Service<Stateful<State>> for F
// where
//     F: FnMut(State, Token, TcpStream) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<Stateful<State>>) -> Self::Future {
//         let (stream, token, state) = conn.into_parts();
//         self(state, token, stream)
//     }
// }

// impl<F, Fut, State, Error> Service<Stateful<State>> for F
// where
//     F: FnMut(State, TcpStream, Token) -> Fut,
//     Fut: Future<Output = Result<(), Error>>,
// {
//     type Error = Error;
//     type Future = Fut;

//     fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, conn: Connection<Stateful<State>>) -> Self::Future {
//         let (stream, token, state) = conn.into_parts();
//         self(state, stream, token)
//     }
// }
