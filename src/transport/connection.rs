use crate::transport::graceful::{ShutdownFuture, Token};

mod inner {
    pub struct Stateless;
    pub struct Stateful<T>(pub T);
}

#[derive(Debug)]
pub struct Connection<S, T> {
    socket: S,
    shutdown: Token,
    state: T,
}

impl<S, T> Connection<S, T> {
    pub fn shutdown(&self) -> ShutdownFuture<'_> {
        self.shutdown.shutdown()
    }

    pub fn child_token(&self) -> Token {
        self.shutdown.child_token()
    }

    pub fn stream(&self) -> &S {
        &self.socket
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.socket
    }
}

impl<S, T> Connection<S, inner::Stateful<T>> {
    pub fn stateful(socket: S, shutdown: Token, state: T) -> Self {
        Connection {
            socket,
            shutdown,
            state: inner::Stateful(state),
        }
    }

    pub fn state(&self) -> &T {
        &self.state.0
    }

    pub fn state_mut(&mut self) -> &mut T {
        &mut self.state.0
    }

    pub fn into_parts(self) -> (S, Token, T) {
        (self.socket, self.shutdown, self.state.0)
    }
}

impl<S> Connection<S, inner::Stateless> {
    pub fn new<T>(socket: S, shutdown: Token) -> Self {
        Connection {
            socket,
            shutdown,
            state: inner::Stateless,
        }
    }

    pub fn into_parts(self) -> (S, Token) {
        (self.socket, self.shutdown)
    }
}
