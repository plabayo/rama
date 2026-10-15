//! UDP sockets bound at addresses that need not be the host's own.

use rama_core::Service;
use rama_net::address::SocketAddress;

use crate::{DatagramError, UdpPacketSocket, UdpSocketConfig, UdpSocketFactory};

/// Binds UDP sockets at any address, the host's or not, so that a transparent proxy's replies
/// leave from the destination its client sent to; see
/// [`DatagramDemux::with_reply_sockets`](crate::DatagramDemux::with_reply_sockets).
///
/// Sets `IP_TRANSPARENT` (or `IPV6_TRANSPARENT`) and address reuse on top of its
/// [`UdpSocketConfig`], which needs `CAP_NET_ADMIN`. Sockets stay unconnected: a connected one
/// would draw its client's next datagrams away from the redirecting listener.
#[derive(Debug, Clone, Default)]
pub struct TransparentUdpSocketFactory {
    config: UdpSocketConfig,
}

impl TransparentUdpSocketFactory {
    /// Construct a factory binding with `config` plus the transparent options.
    #[must_use]
    pub const fn new(config: UdpSocketConfig) -> Self {
        Self { config }
    }
}

impl Service<SocketAddress> for TransparentUdpSocketFactory {
    type Output = UdpPacketSocket;
    type Error = DatagramError;

    async fn serve(&self, address: SocketAddress) -> Result<Self::Output, Self::Error> {
        let mut options = self.config.socket_options().clone();
        // Each family's option fails on the other's socket.
        let v4 = address.ip_addr.is_ipv4();
        options.ip_transparent = v4.then_some(true);
        options.ip_transparent_v6 = (!v4).then_some(true);
        options.reuse_address = Some(true);
        UdpSocketFactory::new(self.config.clone().with_socket_options(options))
            .serve(address)
            .await
    }
}
