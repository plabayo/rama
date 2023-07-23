//! A connection is usually a socket (TCP, UDP, Unix, etc.),
//! with the ability to gracefully shutdown. Optionally, it can also
//! contain some state.
//!
//! See [`Connection`] for more details.
//!
//! `service_fn` is a helper for creating a [`tower_async::Service`] from a function or closure,
//! to serve the full [`Connection`] or just parts of it, e.g. the `stream`.

use crate::transport::graceful::{ShutdownFuture, Token};

mod service_fn;
pub use service_fn::{service_fn, Handler, ServiceFn};

/// A connection is usually a socket (TCP, UDP, Unix, etc.),
/// with the ability to gracefully shutdown. Optionally, it can also
/// contain some state.
///
/// This datastructure bundles these all together
/// so that they can be passed around together with ease.
#[derive(Debug)]
pub struct Connection<S, T> {
    stream: S,
    shutdown: Token,
    state: T,
}

impl<S, T> Connection<S, T> {
    /// Create a new [`Connection`] from a stream, a shutdown token, and some state.
    pub fn new(stream: S, shutdown: Token, state: T) -> Self {
        Connection {
            stream,
            shutdown,
            state,
        }
    }

    /// Retruns the future that resolves when the
    /// graceful shutdown has been triggered.
    pub fn shutdown(&self) -> ShutdownFuture<'_> {
        self.shutdown.shutdown()
    }

    /// Creates a child token that
    /// can be passed down to child procedures that
    /// wish to respect the graceful shutdown when possible.
    pub fn child_token(&self) -> Token {
        self.shutdown.child_token()
    }

    /// Returns a reference to the wrapped stream, usually a socket.
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// Returns an exclusive (mutable) reference to the wrapped stream, usually a socket.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Returnsa reference to the wrapped state.
    pub fn state(&self) -> &T {
        &self.state
    }

    /// Returns an exclusive (mutable) reference to the wrapped state.
    pub fn state_mut(&mut self) -> &mut T {
        &mut self.state
    }

    /// Consumes the [`Connection`] and returns the wrapped stream, shutdown token, and state.
    pub fn into_parts(self) -> (S, Token, T) {
        (self.stream, self.shutdown, self.state)
    }
}
