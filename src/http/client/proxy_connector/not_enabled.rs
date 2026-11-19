use crate::{
    Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
    http::{Request, Response, io::upgrade::Upgraded},
    net::client::{ConnectionError, ConnectionErrorKind, EstablishedClientConnection},
};
use std::{fmt, marker::PhantomData};

#[cfg(doc)]
use super::ProxyConnector;

/// A proxy method a [`ProxyConnector`] was not given, which refuses the routes asking for
/// it: a client serves a proxied route the way it was asked to, or not at all.
///
/// `Over` is the connector towards proxies the method would have been built on, so a slot
/// has the same shape whether or not its method is enabled.
pub struct ProxyMethodNotEnabled<Over = ()> {
    reason: &'static str,
    _phantom: PhantomData<fn() -> Over>,
}

impl<Over> ProxyMethodNotEnabled<Over> {
    pub(in crate::http::client) const SOCKS5: Self = Self::new("socks5 proxying is not enabled");
    pub(in crate::http::client) const HTTP_CONNECT: Self =
        Self::new("http connect proxying is not enabled");
    pub(in crate::http::client) const HTTP_CONNECT_UDP: Self =
        Self::new("http connect-udp proxying is not enabled");
    pub(in crate::http::client) const HTTP_FORWARD: Self =
        Self::new("http forward proxying is not enabled");

    const fn new(reason: &'static str) -> Self {
        Self {
            reason,
            _phantom: PhantomData,
        }
    }
}

impl<Over> fmt::Debug for ProxyMethodNotEnabled<Over> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyMethodNotEnabled")
            .field("reason", &self.reason)
            .finish()
    }
}

impl<Over> Clone for ProxyMethodNotEnabled<Over> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Over> Copy for ProxyMethodNotEnabled<Over> {}

impl<Over: 'static, Input: Send + 'static> Service<Input> for ProxyMethodNotEnabled<Over> {
    type Output = EstablishedClientConnection<NoProxyConnection, Input>;
    type Error = ConnectionError;

    async fn serve(&self, _: Input) -> Result<Self::Output, Self::Error> {
        Err(ConnectionError::local(
            BoxError::from_static_str(self.reason),
            ConnectionErrorKind::Unavailable,
        ))
    }
}

/// The connection of a proxy method which is not enabled: it is never established.
#[derive(Debug, Clone)]
pub enum NoProxyConnection {}

impl From<NoProxyConnection> for Upgraded {
    fn from(conn: NoProxyConnection) -> Self {
        match conn {}
    }
}

impl ExtensionsRef for NoProxyConnection {
    fn extensions(&self) -> &Extensions {
        match *self {}
    }
}

impl<Body: Send + 'static> Service<Request<Body>> for NoProxyConnection {
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, _: Request<Body>) -> Result<Self::Output, Self::Error> {
        match *self {}
    }
}

#[cfg(feature = "udp")]
#[warn(clippy::missing_trait_methods)]
impl crate::net::stream::Socket for NoProxyConnection {
    fn local_addr(&self) -> std::io::Result<crate::net::address::SocketAddress> {
        match *self {}
    }

    fn peer_addr(&self) -> std::io::Result<crate::net::address::SocketAddress> {
        match *self {}
    }
}

#[cfg(feature = "udp")]
#[warn(clippy::missing_trait_methods)]
impl crate::udp::DatagramSocket for NoProxyConnection {
    type Sender = Self;

    fn create_sender(&self) -> Self::Sender {
        match *self {}
    }

    fn poll_recv(
        &mut self,
        _: &mut std::task::Context<'_>,
        _: &mut [std::io::IoSliceMut<'_>],
        _: &mut [crate::udp::DatagramMetadata],
    ) -> std::task::Poll<Result<usize, crate::udp::DatagramError>> {
        match *self {}
    }

    fn capabilities(&self) -> crate::udp::DatagramCapabilities {
        match *self {}
    }
}

#[cfg(feature = "udp")]
#[warn(clippy::missing_trait_methods)]
impl crate::udp::DatagramSender for NoProxyConnection {
    fn poll_send(
        &mut self,
        _: &mut std::task::Context<'_>,
        _: &crate::udp::SendDatagram<'_>,
    ) -> std::task::Poll<Result<(), crate::udp::DatagramError>> {
        match *self {}
    }

    fn poll_send_batch(
        &mut self,
        _: &mut std::task::Context<'_>,
        _: &[crate::udp::SendDatagram<'_>],
    ) -> std::task::Poll<Result<usize, crate::udp::DatagramError>> {
        match *self {}
    }

    fn capabilities(&self) -> crate::udp::DatagramCapabilities {
        match *self {}
    }
}

#[warn(clippy::missing_trait_methods)]
impl tokio::io::AsyncRead for NoProxyConnection {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match *self {}
    }
}

#[warn(clippy::missing_trait_methods)]
impl tokio::io::AsyncWrite for NoProxyConnection {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match *self {}
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match *self {}
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match *self {}
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match *self {}
    }

    fn is_write_vectored(&self) -> bool {
        match *self {}
    }
}
