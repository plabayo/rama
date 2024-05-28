#![allow(dead_code)]

use crate::error::{BoxError, OpaqueError};
use crate::http::Uri;

// TODO: support perhaps also more context, such as tracing id, ...

#[derive(Debug)]
/// An opaque error type that encapsulates all possible errors that can occur when using the
/// [`HttpClient`] service directly, as part of a stack or as a building block for other services.
///
/// [`HttpClient`]: crate::http::client::HttpClient
pub struct HttpClientError {
    inner: OpaqueError,
    uri: Option<Uri>,
}

impl HttpClientError {
    /// create a [`HttpClientError`] from an std error
    pub fn from_std(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            inner: OpaqueError::from_std(err),
            uri: None,
        }
    }

    /// create a [`HttpClientError`] from a display object
    pub fn from_display(
        err: impl std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: OpaqueError::from_display(err),
            uri: None,
        }
    }

    /// create a [`HttpClientError`] from a boxed error
    pub fn from_boxed(err: BoxError) -> Self {
        Self {
            inner: OpaqueError::from_boxed(err),
            uri: None,
        }
    }

    /// Attach a [`Uri`] to the error.
    pub fn with_uri(mut self, uri: Uri) -> Self {
        self.uri = Some(uri);
        self
    }

    /// Return the [`Uri`] associated with the error, if any.
    pub fn uri(&self) -> Option<&Uri> {
        self.uri.as_ref()
    }
}

impl std::fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.uri {
            Some(uri) => write!(f, "http client error ({:?}) for uri: {}", self.inner, uri),
            None => write!(f, "http client error ({:?})", self.inner),
        }
    }
}

impl std::error::Error for HttpClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

impl From<BoxError> for HttpClientError {
    fn from(err: BoxError) -> Self {
        Self {
            inner: OpaqueError::from_boxed(err),
            uri: None,
        }
    }
}
