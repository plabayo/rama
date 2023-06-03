use tokio::net::TcpStream;

use crate::core::transport::graceful::{Token, ShutdownFuture};

pub struct Stateless;
pub struct Stateful<T>(T);

#[derive(Debug)]
pub struct Connection<T> {
    socket: TcpStream,
    shutdown: Token,
    state: T,
}

impl Connection<Stateless> {
    pub(crate) fn new(socket: TcpStream, shutdown: Token) -> Self {
        Connection {
            socket,
            shutdown,
            state: Stateless,
        }
    }

    pub fn into_parts(self) -> (TcpStream, Token) {
        (self.socket, self.shutdown)
    }

    pub fn stateful<T>(self, state: T) -> Connection<Stateful<T>> {
        Connection {
            socket: self.socket,
            shutdown: self.shutdown,
            state: Stateful(state),
        }
    }
}

impl<T> Connection<Stateful<T>> {
    pub(crate) fn stateful(socket: TcpStream, shutdown: Token, state: T) -> Self {
        Connection {
            socket,
            shutdown,
            state: Stateful(state),
        }
    }

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
}
