use super::core::HandshakeError;
use rama_core::error::BoxError;
use std::fmt;

#[derive(Debug)]
/// error that can be returned in case a socks5 proxy
/// did not manage to establish a connection
pub enum Socks5ProxyError {
    /// Socks5 handshake error
    Handshake(HandshakeError),
    /// I/O error happened as part of Socks5 Proxy Connection Establishment
    ///
    /// (e.g. some kind of TCP error)
    Transport(BoxError),
}

impl fmt::Display for Socks5ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake(error) => {
                write!(f, "socks5 proxy error: handshake error [{error}]")
            }
            Self::Transport(error) => {
                write!(f, "socks5 proxy error: transport error: I/O [{error}]")
            }
        }
    }
}

impl From<std::io::Error> for Socks5ProxyError {
    fn from(value: std::io::Error) -> Self {
        Self::Transport(value.into())
    }
}

impl std::error::Error for Socks5ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Handshake(err) => match err.source() {
                Some(err_src) if !err_src.is::<std::io::Error>() => Some(err_src),
                _ => Some(err as &dyn std::error::Error),
            },
            Self::Transport(err) => {
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
    }
}
