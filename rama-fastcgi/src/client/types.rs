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

    /// Append a single CGI name-value pair to [`Self::params`].
    ///
    /// Pair the name with the constants in
    /// [`proto::cgi`][crate::proto::cgi] to avoid bare-string literals at
    /// call sites:
    ///
    /// ```
    /// use rama_fastcgi::{FastCgiClientRequest, proto::cgi};
    ///
    /// let mut req = FastCgiClientRequest::new(vec![]);
    /// req.push_param(cgi::SCRIPT_FILENAME, "/var/www/index.php");
    /// req.push_param(cgi::DOCUMENT_ROOT,   "/var/www");
    /// ```
    ///
    /// Both arguments accept anything that converts into [`Bytes`] —
    /// `&'static [u8]`, `&'static str`, `Bytes`, `Vec<u8>`, `String`, etc.
    pub fn push_param(&mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> &mut Self {
        self.params.push((name.into(), value.into()));
        self
    }

    /// Builder-style sibling of [`Self::push_param`]: append a pair and
    /// return `self` for chaining.
    #[must_use]
    pub fn with_param(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.push_param(name, value);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::cgi;

    #[test]
    fn test_push_param_appends_to_params() {
        let mut req = FastCgiClientRequest::new(vec![]);
        req.push_param(cgi::REQUEST_METHOD, "GET");
        req.push_param(cgi::SCRIPT_FILENAME, "/var/www/index.php");

        assert_eq!(req.params.len(), 2);
        assert_eq!(&req.params[0].0[..], b"REQUEST_METHOD");
        assert_eq!(&req.params[0].1[..], b"GET");
        assert_eq!(&req.params[1].0[..], b"SCRIPT_FILENAME");
        assert_eq!(&req.params[1].1[..], b"/var/www/index.php");
    }

    #[test]
    fn test_push_param_is_chainable() {
        let mut req = FastCgiClientRequest::new(vec![]);
        req.push_param(cgi::REQUEST_METHOD, "POST")
            .push_param(cgi::QUERY_STRING, "")
            .push_param(cgi::CONTENT_LENGTH, "0");
        assert_eq!(req.params.len(), 3);
    }

    #[test]
    fn test_with_param_builder_style() {
        let req = FastCgiClientRequest::new(vec![])
            .with_param(cgi::SCRIPT_FILENAME, "/srv/app.php")
            .with_param(cgi::DOCUMENT_ROOT, "/srv");
        assert_eq!(req.params.len(), 2);
        assert_eq!(&req.params[0].0[..], b"SCRIPT_FILENAME");
        assert_eq!(&req.params[1].0[..], b"DOCUMENT_ROOT");
    }

    #[test]
    fn test_push_param_zero_copy_for_static_name() {
        // The CGI constants are backed by &'static [u8]; pushing them must
        // not re-allocate the name buffer.
        let mut req = FastCgiClientRequest::new(vec![]);
        req.push_param(cgi::REQUEST_METHOD, "GET");
        assert_eq!(req.params[0].0.as_ptr(), cgi::REQUEST_METHOD.as_ptr());
    }
}
