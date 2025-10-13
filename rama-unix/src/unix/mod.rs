mod address;
use std::ops::{Deref, DerefMut};

pub use address::UnixSocketAddress;

pub mod client;
pub mod server;

mod stream;
#[doc(inline)]
pub use stream::{TokioUnixStream, UnixStream};

mod frame;
#[doc(inline)]
pub use frame::UnixDatagramFramed;

pub use tokio::net::unix::SocketAddr as TokioSocketAddress;
pub use tokio::net::{UnixDatagram, UnixSocket};

#[derive(Debug, Clone)]
/// Information about the socket on the egress end.
pub struct ClientUnixSocketInfo(pub UnixSocketInfo);

impl AsRef<UnixSocketInfo> for ClientUnixSocketInfo {
    fn as_ref(&self) -> &UnixSocketInfo {
        &self.0
    }
}

impl AsMut<UnixSocketInfo> for ClientUnixSocketInfo {
    fn as_mut(&mut self) -> &mut UnixSocketInfo {
        &mut self.0
    }
}

impl Deref for ClientUnixSocketInfo {
    type Target = UnixSocketInfo;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for ClientUnixSocketInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug, Clone)]
/// Connected unix socket information.
pub struct UnixSocketInfo {
    local_addr: Option<UnixSocketAddress>,
    peer_addr: UnixSocketAddress,
}

impl UnixSocketInfo {
    /// Create a new [`UnixSocketInfo`].
    pub fn new(
        local_addr: Option<impl Into<UnixSocketAddress>>,
        peer_addr: impl Into<UnixSocketAddress>,
    ) -> Self {
        Self {
            local_addr: local_addr.map(Into::into),
            peer_addr: peer_addr.into(),
        }
    }

    /// Try to get the address of the local unix (domain) socket.
    #[must_use]
    pub fn local_addr(&self) -> Option<&UnixSocketAddress> {
        self.local_addr.as_ref()
    }

    /// Get the address of the peer unix (domain) socket.
    #[must_use]
    pub fn peer_addr(&self) -> &UnixSocketAddress {
        &self.peer_addr
    }
}
