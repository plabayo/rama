use crate::transport::graceful::{ShutdownFuture, Token};

#[derive(Debug)]
pub struct Connection<S, T> {
    socket: S,
    shutdown: Token,
    state: T,
}

impl<S, T> Connection<S, T> {
    pub fn new(socket: S, shutdown: Token, state: T) -> Self {
        Connection {
            socket,
            shutdown,
            state,
        }
    }

    pub fn shutdown(&self) -> ShutdownFuture<'_> {
        self.shutdown.shutdown()
    }

    pub fn child_token(&self) -> Token {
        self.shutdown.child_token()
    }

    pub fn socket(&self) -> &S {
        &self.socket
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.socket
    }

    pub fn into_parts(self) -> (S, Token, T) {
        (self.socket, self.shutdown, self.state)
    }
}
