#![allow(dead_code)]

use crate::error::{Error, StdError};

#[derive(Debug)]
/// An opaque error type that encapsulates all possible errors that can occur when using the
/// [`HttpClient`] service directly, as part of a stack or as a building block for other services.
///
/// [`HttpClient`]: crate::http::client::HttpClient
pub struct HttpClientError {
    inner: Option<Error>,
    kind: HttpClientErrorKind,
}

#[derive(Debug)]
enum HttpClientErrorKind {
    Request,
    IO,
}

impl HttpClientError {
    pub(crate) fn request() -> Self {
        Self {
            inner: None,
            kind: HttpClientErrorKind::Request,
        }
    }
    pub(crate) fn request_err(err: Error) -> Self {
        Self {
            inner: Some(Error::new(err)),
            kind: HttpClientErrorKind::Request,
        }
    }

    pub(crate) fn io() -> Self {
        Self {
            inner: None,
            kind: HttpClientErrorKind::IO,
        }
    }

    pub(crate) fn io_err(err: Error) -> Self {
        Self {
            inner: Some(Error::new(err)),
            kind: HttpClientErrorKind::IO,
        }
    }
}

impl std::fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            HttpClientErrorKind::Request => {
                write!(
                    f,
                    "HTTP Client Request error: {}",
                    self.inner.as_ref().unwrap()
                )
            }
            HttpClientErrorKind::IO => {
                write!(f, "HTTP Client IO error: {}", self.inner.as_ref().unwrap())
            }
        }
    }
}

impl std::error::Error for HttpClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.as_ref().and_then(|e| e.source())
    }
}
