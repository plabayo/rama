use rama_core::bytes::Bytes;

use crate::body::FastCgiBody;
use crate::proto::Role;

/// A complete FastCGI request received from a web server.
///
/// The [`FastCgiServer`][super::FastCgiServer] assembles this from the
/// `FCGI_BEGIN_REQUEST`, `FCGI_PARAMS`, `FCGI_STDIN`, and (for
/// [`Role::Filter`]) `FCGI_DATA` records before passing it to the inner
/// service.
///
/// # Roles
///
/// - [`Role::Responder`]: `params` contains the CGI environment, `stdin`
///   contains the request body. `data` is empty.
/// - [`Role::Authorizer`]: `params` contains the CGI environment. `stdin`
///   and `data` are empty. The inner service decides allow/deny via the HTTP
///   status code in its `FastCgiResponse` stdout — 200 means allowed; any
///   other status is returned to the client as the denial response.
/// - [`Role::Filter`]: `params` contains the CGI environment (including
///   `FCGI_DATA_LAST_MOD` and `FCGI_DATA_LENGTH`), `stdin` contains the
///   request body, and `data` contains the raw file data to be filtered.
#[derive(Debug)]
pub struct FastCgiRequest {
    /// Request ID assigned by the web server (1–65535).
    pub request_id: u16,
    /// Role the web server expects the application to fulfil.
    pub role: Role,
    /// If true, the web server wants to reuse the connection for further requests.
    pub keep_conn: bool,
    /// CGI environment variables received via `FCGI_PARAMS` records.
    ///
    /// Each entry is a `(name, value)` pair decoded from the FastCGI
    /// name-value encoding.
    pub params: Vec<(Bytes, Bytes)>,
    /// Streaming body data from `FCGI_STDIN` records.
    ///
    /// Read via [`AsyncRead`][tokio::io::AsyncRead]. For the Authorizer role
    /// this stream is empty.
    pub stdin: FastCgiBody,
    /// Streaming file data from `FCGI_DATA` records (Filter role only).
    ///
    /// Empty for Responder and Authorizer roles.
    pub data: FastCgiBody,
}

impl FastCgiRequest {
    /// Return the value of the CGI parameter named `name`, if present.
    pub fn param(&self, name: &[u8]) -> Option<&[u8]> {
        self.params
            .iter()
            .find(|(n, _)| n.as_ref() == name)
            .map(|(_, v)| v.as_ref())
    }
}

/// A FastCGI response to be sent back to the web server.
///
/// The [`FastCgiServer`][super::FastCgiServer] writes this as `FCGI_STDOUT`
/// record(s) followed by `FCGI_END_REQUEST`.
///
/// The `stdout` body should contain the full CGI response output, which for
/// an HTTP-backed application typically starts with:
///
/// ```text
/// Content-Type: text/html\r\n
/// \r\n
/// <body>
/// ```
///
/// For the **Authorizer** role, a `Status: 200 OK` response means the
/// request is permitted; any other status code is returned directly to the
/// end user as the denial response. Headers prefixed with `Variable-` are
/// forwarded to the downstream application by the web server.
#[derive(Debug)]
pub struct FastCgiResponse {
    /// Data to be sent as `FCGI_STDOUT`.
    pub stdout: FastCgiBody,
    /// Application exit status (0 for success).
    pub app_status: u32,
}

impl FastCgiResponse {
    /// Create a successful response with the given stdout.
    ///
    /// Accepts anything that converts into a [`FastCgiBody`]: [`Bytes`],
    /// `Vec<u8>`, `String`, or an [`AsyncRead`][tokio::io::AsyncRead] wrapped
    /// via [`FastCgiBody::from_reader`].
    #[must_use]
    pub fn new(stdout: impl Into<FastCgiBody>) -> Self {
        Self {
            stdout: stdout.into(),
            app_status: 0,
        }
    }

    /// Create an error response with empty stdout and a non-zero exit code.
    #[must_use]
    pub fn error(app_status: u32) -> Self {
        Self {
            stdout: FastCgiBody::empty(),
            app_status,
        }
    }
}
