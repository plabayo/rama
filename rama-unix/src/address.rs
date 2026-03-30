use crate::TokioSocketAddress;
use std::path::Path;

#[derive(Clone)]
/// An address associated with a Unix socket.
///
/// This type is a thin wrapper around [`std::os::unix::net::SocketAddr`]. You
/// can convert to and from the standard library `SocketAddr` type using the
/// [`From`] trait. It is also just as easily convertabible to and from a tokio unix SocketAddr.
pub struct UnixSocketAddress(pub(crate) std::os::unix::net::SocketAddr);

impl UnixSocketAddress {
    /// Returns `true` if the address is unnamed.
    ///
    /// Documentation reflected in [`SocketAddr`]
    ///
    /// [`SocketAddr`]: std::os::unix::net::SocketAddr
    #[must_use]
    pub fn is_unnamed(&self) -> bool {
        self.0.is_unnamed()
    }

    /// Returns the contents of this address if it is a `pathname` address.
    ///
    /// Documentation reflected in [`SocketAddr`]
    ///
    /// [`SocketAddr`]: std::os::unix::net::SocketAddr
    #[must_use]
    pub fn as_pathname(&self) -> Option<&Path> {
        self.0.as_pathname()
    }
}

impl std::fmt::Debug for UnixSocketAddress {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(fmt)
    }
}

impl From<std::os::unix::net::SocketAddr> for UnixSocketAddress {
    fn from(value: std::os::unix::net::SocketAddr) -> Self {
        Self(value)
    }
}

impl From<UnixSocketAddress> for std::os::unix::net::SocketAddr {
    fn from(value: UnixSocketAddress) -> Self {
        value.0
    }
}

impl From<TokioSocketAddress> for UnixSocketAddress {
    fn from(value: TokioSocketAddress) -> Self {
        Self(value.into())
    }
}

impl From<UnixSocketAddress> for TokioSocketAddress {
    fn from(value: UnixSocketAddress) -> Self {
        value.0.into()
    }
}
