use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
};

/// A FastCGI client request to send to a backend application server.
///
/// Construct one with the CGI environment variables (params) and optionally a
/// request body (stdin), then serve it via [`FastCgiClient`][super::FastCgiClient].
#[derive(Debug, Clone)]
pub struct FastCgiClientRequest {
    /// CGI environment variables to send as `FCGI_PARAMS`.
    pub params: Vec<(Bytes, Bytes)>,
    /// Request body to send as `FCGI_STDIN` (may be empty for GET requests).
    pub stdin: Bytes,
    /// Extensions for routing and metadata (e.g. connector target address).
    pub extensions: Extensions,
}

impl FastCgiClientRequest {
    /// Create a new [`FastCgiClientRequest`] with the given params and an empty stdin.
    #[must_use]
    pub fn new(params: impl Into<Vec<(Bytes, Bytes)>>) -> Self {
        Self {
            params: params.into(),
            stdin: Bytes::new(),
            extensions: Extensions::new(),
        }
    }

    /// Attach a request body (stdin).
    #[must_use]
    pub fn with_stdin(mut self, stdin: impl Into<Bytes>) -> Self {
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

/// The raw stdout bytes received from a FastCGI application.
///
/// For a RESPONDER application this typically contains HTTP response headers
/// followed by a blank line and the response body, as per CGI conventions.
#[derive(Debug, Clone)]
pub struct FastCgiClientResponse {
    /// All bytes received via `FCGI_STDOUT` records.
    pub stdout: Bytes,
    /// Application-level exit status from `FCGI_END_REQUEST`.
    pub app_status: u32,
}
