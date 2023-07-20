use crate::transport::graceful::{ShutdownFuture, Token};

mod service_fn;
pub use service_fn::{service_fn, Handler, ServiceFn};

#[derive(Debug)]
pub struct Connection<S, T> {
    stream: S,
    shutdown: Token,
    state: T,
}

impl<S, T> Connection<S, T> {
    pub fn new(stream: S, shutdown: Token, state: T) -> Self {
        Connection {
            stream,
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

    pub fn stream(&self) -> &S {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn state(&self) -> &T {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut T {
        &mut self.state
    }

    pub fn into_parts(self) -> (S, Token, T) {
        (self.stream, self.shutdown, self.state)
    }
}
