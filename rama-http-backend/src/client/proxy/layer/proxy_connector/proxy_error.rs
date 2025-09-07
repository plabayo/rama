use std::fmt;

use rama_core::error::BoxError;

#[derive(Debug)]
/// error that can be returned in case a http proxy
/// did not manage to establish a connection
pub enum HttpProxyError {
    /// Proxy Authentication Required
    ///
    /// (Proxy returned HTTP 407)
    AuthRequired,
    /// Proxy is Unavailable
    ///
    /// (Proxy returned HTTP 503)
    Unavailable,
    /// I/O error happened as part of HTTP Proxy Connection Establishment
    ///
    /// (e.g. some kind of TCP error)
    Transport(BoxError),
    /// Something went wrong, but classification did not happen.
    ///
    /// (First header line of http response is included in error)
    Other(String),
}

impl fmt::Display for HttpProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthRequired => {
                write!(f, "http proxy error: proxy auth required (http 407)")
            }
            Self::Unavailable => {
                write!(f, "http proxy error: proxy unavailable (http 503)")
            }
            Self::Transport(error) => {
                write!(f, "http proxy error: transport error: I/O [{error}]")
            }
            Self::Other(header) => {
                write!(f, "http proxy error: first line of header = [{header}]")
            }
        }
    }
}

impl From<std::io::Error> for HttpProxyError {
    fn from(value: std::io::Error) -> Self {
        Self::Transport(value.into())
    }
}

impl std::error::Error for HttpProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self::Transport(err) = self else {
            return None;
        };

        // filter out generic io errors,
        // but do allow custom errors (e.g. because IP is blocked)
        let err_ref = err.source().unwrap_or_else(|| err.as_ref());
        if err_ref.is::<std::io::Error>() {
            Some(self)
        } else {
            Some(err_ref)
        }
    }
}
