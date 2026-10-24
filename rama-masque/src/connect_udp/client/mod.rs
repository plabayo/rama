use std::{
    fmt, io,
    io::IoSliceMut,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU16,
    task::{Context, Poll},
};

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
    rt::Executor,
};
use rama_http::{
    Request, Response, Version, conn::TargetHttpVersion, datagram::HttpDatagramSession,
    io::upgrade::handle_upgrade, proto::ext::HttpDatagrams,
};
use rama_net::{
    Protocol,
    address::{Host, ProxyAddress, SocketAddress},
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService,
        EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute,
    },
    stream::Socket,
};
use rama_udp::{
    DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSender, DatagramSocket,
    SendDatagram,
};
use rama_utils::macros::generate_set_and_with;

use super::{
    ConnectUdpSender, ConnectUdpSocket, ConnectUdpSocketConfig, ConnectUdpTarget,
    connect_udp_request, session_config, validate_connect_udp_response,
};

/// The peer a client tunnel to a DNS name reports: the IPv4 dummy address ([RFC 7600]),
/// meant for an interface with no address of its own.
///
/// [RFC 7600]: https://datatracker.ietf.org/doc/html/rfc7600
pub const NAME_TARGET_PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 8);

/// Initial MTU for a QUIC connection to a MASQUE proxy that carries tunnels as HTTP/3
/// datagrams: an inner QUIC packet needs 1200 bytes plus the outer packet's overhead, which
/// QUIC's default of 1200 leaves no room for. Configure it on both sides of that connection.
pub const OUTER_INITIAL_MTU: u16 = 1350;

/// A datagram proxy connector for MASQUE ([RFC 9298]): a request on a [`ProxyRoute`] to a
/// MASQUE proxy gets a CONNECT-UDP tunnel to its target, opened with the HTTP client `S`;
/// every other request goes to the inner datagram connector `C`.
///
/// The tunnel's target keeps its name: the proxy resolves it. A request addressed to its own
/// MASQUE proxy ([`ProxyRoute::addresses_proxy`]) goes to `C`, as does a request without a
/// proxy route. A proxy route to any other kind of proxy is refused, so it is never bypassed.
/// A tunnel publishes [`EstablishedProxyRoute::Tunnel`] on its socket.
///
/// `S` sends the CONNECT-UDP request to the proxy: it needs proxy support, so the proxy's
/// credentials go with it, and, for HTTP/3 datagrams, an outer initial MTU of
/// [`OUTER_INITIAL_MTU`].
///
/// [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
pub struct ConnectUdpConnector<S, C> {
    client: S,
    inner: C,
    exec: Executor,
    socket: ConnectUdpSocketConfig,
    version: Version,
}

impl<S: fmt::Debug, C: fmt::Debug> fmt::Debug for ConnectUdpConnector<S, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectUdpConnector")
            .field("client", &self.client)
            .field("inner", &self.inner)
            .field("socket", &self.socket)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl<S: Clone, C: Clone> Clone for ConnectUdpConnector<S, C> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            inner: self.inner.clone(),
            exec: self.exec.clone(),
            socket: self.socket,
            version: self.version,
        }
    }
}

impl<S, C> ConnectUdpConnector<S, C> {
    /// Tunnel MASQUE routes with `client` and serve the rest with `inner`; `exec` runs each
    /// tunnel's send task.
    pub fn new(inner: C, client: S, exec: Executor) -> Self {
        Self {
            client,
            inner,
            exec,
            socket: ConnectUdpSocketConfig::default(),
            version: Version::HTTP_3,
        }
    }

    generate_set_and_with! {
        /// The HTTP version of the CONNECT-UDP request to the proxy; HTTP/3 by default.
        pub fn version(mut self, version: Version) -> Self {
            self.version = version;
            self
        }
    }

    generate_set_and_with! {
        /// Limits of each tunnel, including its idle timeout.
        pub fn socket_config(mut self, config: ConnectUdpSocketConfig) -> Self {
            self.socket = config;
            self
        }
    }
}

impl<S, C> ConnectUdpConnector<S, C>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    /// Open a tunnel to `target` through `proxy`.
    ///
    /// The socket's peer is the target when it is an IP literal, otherwise
    /// [`NAME_TARGET_PEER`] with the target port: the proxy resolves names, so the client
    /// never learns the address.
    async fn open(
        &self,
        proxy: &ProxyAddress,
        target: ConnectUdpTarget,
    ) -> Result<ConnectUdpSocket, BoxError> {
        let request = connect_udp_request(proxy, &target, self.version)?;
        // The token defines datagram semantics (RFC 9297 §2): declare them for this request.
        request.extensions().insert(HttpDatagrams);
        request.extensions().insert(TargetHttpVersion(self.version));
        // Addressed to the proxy itself: rama's connectors send it straight there, as to a
        // forward proxy, with the proxy's credentials.
        request
            .extensions()
            .insert(ProxyRoute::Proxy(proxy.clone()));
        let response = self
            .client
            .serve(request)
            .await
            .map_err(Into::into)
            .context("connect-udp request")?;
        if let Err(error) = validate_connect_udp_response(self.version, &response) {
            return Err(error
                .context_field("status", response.status())
                .context("connect-udp tunnel refused"));
        }
        let upgraded = handle_upgrade(&response)
            .await
            .context("connect-udp upgrade")?;
        let ip = match target.host {
            Host::Address(ip) => ip,
            _ => IpAddr::V4(NAME_TARGET_PEER),
        };
        let peer = SocketAddress::new(ip, target.port.get());
        // The socket reports a local address of the peer's family: a QUIC endpoint takes its
        // family from it and only reaches remotes of that family.
        let local = if ip.is_ipv6() {
            SocketAddress::default_ipv6(0)
        } else {
            SocketAddress::default_ipv4(0)
        };
        let socket = ConnectUdpSocket::new(
            &self.exec,
            HttpDatagramSession::with_config(upgraded, session_config()),
            local,
            peer,
            self.socket,
        );
        socket
            .extensions()
            .insert(EstablishedProxyRoute::Tunnel(proxy.clone()));
        Ok(socket)
    }
}

impl<S, C> Service<ConnectRequest> for ConnectUdpConnector<S, C>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
    C: ConnectorService<ConnectRequest, Connection: DatagramSocket>,
{
    type Output = EstablishedClientConnection<MaybeTunneledSocket<C::Connection>, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let route = input.extensions.get_ref::<ProxyRoute>();
        let proxy = route
            .filter(|route| !route.addresses_proxy(&input.authority))
            .and_then(ProxyRoute::proxy_address)
            .cloned();
        let Some(proxy) = proxy else {
            let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;
            return Ok(EstablishedClientConnection {
                input,
                conn: MaybeTunneledSocket::Direct(conn),
            });
        };
        if !proxy.protocol.as_ref().is_some_and(Protocol::is_masque) {
            return Err(ConnectionError::local(
                BoxError::from_static_str("connect-udp connector serves masque proxies only"),
                ConnectionErrorKind::Unavailable,
            )
            .context_debug_field("protocol", proxy.protocol.clone()));
        }
        let port = NonZeroU16::new(input.authority.port).ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("connect-udp target port is zero"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        let target = ConnectUdpTarget::new(input.authority.host.clone(), port);
        let conn = self
            .open(&proxy, target)
            .await
            .map_err(|error| ConnectionError::transport(error, ConnectionErrorKind::Unavailable))?;
        Ok(EstablishedClientConnection {
            input,
            conn: MaybeTunneledSocket::Tunneled(conn),
        })
    }
}

/// A [`Layer`] producing [`ConnectUdpConnector`]s over its inner datagram connector.
pub struct ConnectUdpConnectorLayer<S> {
    client: S,
    exec: Executor,
    socket: ConnectUdpSocketConfig,
    version: Version,
}

impl<S: fmt::Debug> fmt::Debug for ConnectUdpConnectorLayer<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectUdpConnectorLayer")
            .field("client", &self.client)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl<S: Clone> Clone for ConnectUdpConnectorLayer<S> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            exec: self.exec.clone(),
            socket: self.socket,
            version: self.version,
        }
    }
}

impl<S> ConnectUdpConnectorLayer<S> {
    /// Tunnel MASQUE routes with `client`; `exec` runs each tunnel's send task.
    pub fn new(client: S, exec: Executor) -> Self {
        Self {
            client,
            exec,
            socket: ConnectUdpSocketConfig::default(),
            version: Version::HTTP_3,
        }
    }

    generate_set_and_with! {
        /// The HTTP version of the CONNECT-UDP request to the proxy; HTTP/3 by default.
        pub fn version(mut self, version: Version) -> Self {
            self.version = version;
            self
        }
    }

    generate_set_and_with! {
        /// Limits of each tunnel, including its idle timeout.
        pub fn socket_config(mut self, config: ConnectUdpSocketConfig) -> Self {
            self.socket = config;
            self
        }
    }
}

impl<S: Clone, C> Layer<C> for ConnectUdpConnectorLayer<S> {
    type Service = ConnectUdpConnector<S, C>;

    fn layer(&self, inner: C) -> Self::Service {
        ConnectUdpConnector {
            client: self.client.clone(),
            inner,
            exec: self.exec.clone(),
            socket: self.socket,
            version: self.version,
        }
    }

    fn into_layer(self, inner: C) -> Self::Service {
        ConnectUdpConnector {
            client: self.client,
            inner,
            exec: self.exec,
            socket: self.socket,
            version: self.version,
        }
    }
}

/// The socket a [`ConnectUdpConnector`] establishes: the inner connector's socket, or a
/// CONNECT-UDP tunnel through a MASQUE proxy.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "one socket per endpoint, owned in place: boxing the tunnel buys nothing"
)]
pub enum MaybeTunneledSocket<S> {
    /// The inner connector's socket.
    Direct(S),
    /// A tunnel through a MASQUE proxy.
    Tunneled(ConnectUdpSocket),
}

impl<S: ExtensionsRef> ExtensionsRef for MaybeTunneledSocket<S> {
    fn extensions(&self) -> &Extensions {
        match self {
            Self::Direct(socket) => socket.extensions(),
            Self::Tunneled(socket) => socket.extensions(),
        }
    }
}

impl<S: Socket> Socket for MaybeTunneledSocket<S> {
    fn local_addr(&self) -> io::Result<SocketAddress> {
        match self {
            Self::Direct(socket) => socket.local_addr(),
            Self::Tunneled(socket) => socket.local_addr(),
        }
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        match self {
            Self::Direct(socket) => socket.peer_addr(),
            Self::Tunneled(socket) => socket.peer_addr(),
        }
    }
}

impl<S: DatagramSocket> DatagramSocket for MaybeTunneledSocket<S> {
    type Sender = MaybeTunneledSender<S::Sender>;

    fn create_sender(&self) -> Self::Sender {
        match self {
            Self::Direct(socket) => MaybeTunneledSender::Direct(socket.create_sender()),
            Self::Tunneled(socket) => MaybeTunneledSender::Tunneled(socket.create_sender()),
        }
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>> {
        match self {
            Self::Direct(socket) => socket.poll_recv(cx, buffers, metadata),
            Self::Tunneled(socket) => socket.poll_recv(cx, buffers, metadata),
        }
    }

    fn capabilities(&self) -> DatagramCapabilities {
        match self {
            Self::Direct(socket) => socket.capabilities(),
            Self::Tunneled(socket) => socket.capabilities(),
        }
    }
}

/// The send handle of a [`MaybeTunneledSocket`].
#[derive(Debug)]
pub enum MaybeTunneledSender<S> {
    /// The inner socket's sender.
    Direct(S),
    /// The tunnel's sender.
    Tunneled(ConnectUdpSender),
}

impl<S: DatagramSender> DatagramSender for MaybeTunneledSender<S> {
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        match self {
            Self::Direct(sender) => sender.poll_send(cx, datagram),
            Self::Tunneled(sender) => sender.poll_send(cx, datagram),
        }
    }

    fn poll_send_batch(
        &mut self,
        cx: &mut Context<'_>,
        datagrams: &[SendDatagram<'_>],
    ) -> Poll<Result<usize, DatagramError>> {
        match self {
            Self::Direct(sender) => sender.poll_send_batch(cx, datagrams),
            Self::Tunneled(sender) => sender.poll_send_batch(cx, datagrams),
        }
    }

    fn capabilities(&self) -> DatagramCapabilities {
        match self {
            Self::Direct(sender) => sender.capabilities(),
            Self::Tunneled(sender) => sender.capabilities(),
        }
    }
}

#[cfg(test)]
mod tests;
