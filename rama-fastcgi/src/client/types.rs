use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
};

use crate::body::FastCgiBody;

/// A FastCGI client request to send to a backend application server.
///
/// Construct one with the CGI environment variables (params) and optionally a
/// request body (stdin), then serve it via [`FastCgiClient`][super::FastCgiClient].
///
/// `stdin` is a streaming [`FastCgiBody`]; any of `Bytes`, `Vec<u8>`, `String`,
/// `&'static [u8]`, or an [`AsyncRead`][tokio::io::AsyncRead] wrapper can be
/// passed via [`Self::with_stdin`].
#[derive(Debug)]
pub struct FastCgiClientRequest {
    /// CGI environment variables to send as `FCGI_PARAMS`.
    pub params: Vec<(Bytes, Bytes)>,
    /// Request body to send as `FCGI_STDIN` (may be empty for GET requests).
    pub stdin: FastCgiBody,
    /// Extensions for routing and metadata (e.g. connector target address).
    pub extensions: Extensions,
}

impl FastCgiClientRequest {
    /// Create a new [`FastCgiClientRequest`] with the given params and an empty stdin.
    #[must_use]
    pub fn new(params: impl Into<Vec<(Bytes, Bytes)>>) -> Self {
        Self {
            params: params.into(),
            stdin: FastCgiBody::empty(),
            extensions: Extensions::new(),
        }
    }

    /// Attach a request body (stdin).
    ///
    /// Accepts anything convertible into a [`FastCgiBody`]: `Bytes`,
    /// `Vec<u8>`, `String`, `&'static [u8]`, or wrap a streaming reader with
    /// [`FastCgiBody::from_reader`].
    #[must_use]
    pub fn with_stdin(mut self, stdin: impl Into<FastCgiBody>) -> Self {
        self.stdin = stdin.into();
        self
    }

    /// Get a mutable reference to the extensions.
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

impl ExtensionsRef for FastCgiClientRequest {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

/// The raw bytes received from a FastCGI application.
///
/// For a RESPONDER application `stdout` typically contains HTTP response
/// headers followed by a blank line and the response body, as per CGI
/// conventions. `stderr` carries any diagnostic output the application
/// emitted on `FCGI_STDERR`, capped by
/// [`ClientOptions::max_stderr_bytes`][crate::client::ClientOptions::max_stderr_bytes].
#[derive(Debug, Clone)]
pub struct FastCgiClientResponse {
    /// All bytes received via `FCGI_STDOUT` records (capped).
    pub stdout: Bytes,
    /// All bytes received via `FCGI_STDERR` records (capped).
    pub stderr: Bytes,
    /// Application-level exit status from `FCGI_END_REQUEST`.
    pub app_status: u32,
}
