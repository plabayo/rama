use tokio::net::TcpStream;

use crate::core::transport::graceful::{ShutdownFuture, Token};

pub struct Stateless(());

pub struct Stateful<T: Sized>(pub(crate) T);

#[derive(Debug)]
pub struct Connection<T> {
    socket: TcpStream,
    shutdown: Token,
    state: T,
}

impl Connection<Stateless> {
    pub(crate) fn stateless(socket: TcpStream, shutdown: Token) -> Self {
        Connection {
            socket,
            shutdown,
            state: Stateless(()),
        }
    }
}

impl<T> Connection<T> {
    pub fn shutdown(&self) -> ShutdownFuture<'_> {
        self.shutdown.shutdown()
    }

    pub fn child_token(&self) -> Token {
        self.shutdown.child_token()
    }

    pub fn stream(&self) -> &TcpStream {
        &self.socket
    }

    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.socket
    }

    pub fn into_stream(self) -> TcpStream {
        self.socket
    }
}

impl Connection<Stateless> {
    pub(crate) fn stateful<T>(socket: TcpStream, shutdown: Token, state: T) -> Connection<Stateful<T>> {
        Connection {
            socket,
            shutdown,
            state: Stateful(state),
        }
    }

    pub fn into_parts(self) -> (TcpStream, Token) {
        (self.socket, self.shutdown)
    }
}

impl<T: Sized> Connection<Stateful<T>> {
    pub fn state(&self) -> &T {
        &self.state.0
    }

    pub fn state_mut(&mut self) -> &mut T {
        &mut self.state.0
    }

    pub fn into_parts(self) -> (TcpStream, Token, T) {
        (self.socket, self.shutdown, self.state.0)
    }
}
