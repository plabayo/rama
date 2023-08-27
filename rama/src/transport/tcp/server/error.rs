//! Defines the [`Error`] type and [`ErrorHandler`] trait
//! to indicate and handle errors that occur during the execution of
//! a [`super::TcpListener`]'s listen event loop.

pub use tower_async::BoxError;
use tracing::{debug, error};

/// The kind of [`Error`] that can occur during the execution of
/// a [`super::TcpListener`]'s listen event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Indicates an error which happened while trying to accept
    /// an incoming connection on the TCP listener's socket.
    ///
    /// This error is not expected to happen, and might mean the
    /// [`super::TcpListener`] is no longer able to accept new connections.
    Accept,
    /// Indicates that an error was returned by the [`tower_async::Service`] that
    /// was used to handle the incoming connection.
    ///
    /// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
    Service,
    /// Indicates that an error was returned by the [`tower_async::Service`] which is used to
    /// create a new [`tower_async::Service`] that is to handle the incoming connection.
    ///
    /// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
    Factory,
    /// Indicates that the [`super::TcpListener`] was closed during graceful shutdown,
    /// while some connections were still active.
    Timeout,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::Accept => write!(f, "Accept"),
            ErrorKind::Service => write!(f, "Service"),
            ErrorKind::Factory => write!(f, "Factory"),
            ErrorKind::Timeout => write!(f, "Timeout"),
        }
    }
}
/// Error type for TCP server errors, as
/// returned by the [`super::TcpListener`].
///
/// Call [`Error::kind`] to determine the kind of error that occurred,
/// and [`std::error::Error::source`] to get the underlying error, which can be
/// typechecked or downcasted as usual for boxed errors.
///
/// See [`ErrorKind`] for more information about
/// the different kinds of errors that can occur.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: BoxError,
}

impl Error {
    /// Create a new [`Error`] with the given kind and source.
    pub fn new(kind: ErrorKind, source: impl Into<BoxError>) -> Self {
        Self {
            kind,
            source: source.into(),
        }
    }

    /// Get the kind of error that occurred.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Get the underlying error, if any.
    pub fn into_source(self) -> Option<BoxError> {
        Some(self.source)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TCP Server Error ({}): {}", self.kind, self.source)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.source)
    }
}

/// Trait for handling errors that occur during the execution of
/// a [`super::TcpListener`]'s listen event loop.
///
/// The default [`ErrorHandler`] either logs the error
/// or simply ignores it, depending on the kind of error.
pub trait ErrorHandler: Clone + Send + Sync + 'static {
    /// The error type that can be returned by the [`ErrorHandler`]
    /// to indicate a fatal error which cannot be handled.
    type Error: Into<BoxError> + Send + 'static;

    /// Handle an error that occurred while trying to accept
    /// an incoming connection on the TCP listener's socket.
    ///
    /// By default this error is logged using [`tracing:error`],
    /// with a return value of `Ok(())`.
    ///
    /// [`tracing:error`]: https://docs.rs/tracing/*/tracing/macro.error.html
    async fn handle_accept_err(&mut self, error: std::io::Error) -> Result<(), Self::Error> {
        error!("TCP server: accept error: {}", error);
        Ok(())
    }

    /// Handle an error that was returned by the [`tower_async::Service`] that
    /// was used to handle the incoming connection.
    ///
    /// By default this error is logged using [`tracing:debug`],
    /// with a return value of `Ok(())`.
    ///
    /// [`tracing:debug`]: https://docs.rs/tracing/*/tracing/macro.debug.html
    /// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
    async fn handle_service_err(&mut self, error: BoxError) -> Result<(), Self::Error> {
        debug!("TCP server: service error: {}", error);
        Ok(())
    }

    /// Handle an error that was returned by the [`tower_async::Service`] which is used to
    /// create a new [`tower_async::Service`] that is to handle the incoming connection.
    ///
    /// By default this error is logged using [`tracing:debug`],
    /// with a return value of `Ok(())`.
    ///
    /// [`tracing:debug`]: https://docs.rs/tracing/*/tracing/macro.debug.html
    /// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
    async fn handle_factory_err(&mut self, error: BoxError) -> Result<(), Self::Error> {
        debug!("TCP server: factory error: {}", error);
        Ok(())
    }
}
