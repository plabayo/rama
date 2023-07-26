//! Defines the [`Error`] type and [`ErrorHandler`] trait
//! to indicate and handle errors that occur during the execution of
//! a [`super::TcpListener`]'s listen event loop.

pub use tower_async::BoxError;

/// Result type for TCP server errors, as
/// returned by the [`super::TcpListener`].
///
/// See [`Error`] for more information about the error type.
pub type Result<T> = std::result::Result<T, Error>;

/// The kind of [`Error`] that can occur during the execution of
/// a [`super::TcpListener`]'s listen event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Indicates an error which happened while trying to accept
    /// an incoming connection on the TCP listener's socket.
    ///
    /// This error is not expected to happen, and might mean the
    /// [`super::TcpListener`] is no longer able to accept new connections.
    ///
    /// The default [`ErrorHandler`] ignores it,
    /// and the listener will continue to try to accept new connections.
    Accept,
    /// Indicates that an error was returned by the [`tower_async::Service`] that
    /// was used to handle the incoming connection.
    ///
    /// The default [`ErrorHandler`] only logs this error and
    /// therefore the [`super::TcpListener`] will close the connection.
    ///
    /// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
    Service,
    /// Indicates that an error was returned by the [`tower_async::Service`] which is used to
    /// create a new [`tower_async::Service`] that is to handle the incoming connection.
    ///
    /// The default [`ErrorHandler`] only logs this error and
    /// therefore the [`super::TcpListener`] will close the connection.
    ///
    /// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
    Factory,
    /// Indicates that the connection was closed because the timeout
    /// for graceful shutdown was reached, and thus the [`super::TcpListener`]
    /// was closed potentially ungracefully.
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

/// Trait for handling errors (of type [`BoxError`]) that occur during the execution of
/// a [`super::TcpListener`]'s listen event loop.
///
/// The default [`ErrorHandler`] either logs the error
/// or simply ignores it, depending on the kind of error.
///
/// See [`ErrorKind`] for more information about
/// the different kinds of errors that can occur.
pub trait ErrorHandler {
    /// In case a `BoxError` is returned by a call to this function,
    /// the [`super::TcpListener`] will attempt to close gracefully
    /// and return this error to the caller of [`super::TcpListener::serve`].
    async fn handle(&mut self, error: Error) -> std::result::Result<(), BoxError>;
}
