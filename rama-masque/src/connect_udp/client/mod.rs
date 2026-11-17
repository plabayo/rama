use std::{
    fmt,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU16,
    time::Duration,
};

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    extensions::{Extensions, ExtensionsRef, NestedConnectionTransfer},
    graceful::WeakScope,
};
use rama_http::{
    Body, Request, Response, conn::TargetHttpVersion, datagram::HttpDatagramSession,
    io::upgrade::handle_upgrade, proto::ext::HttpDatagrams,
};
use rama_net::{
    address::{Host, ProxyAddress, SocketAddress},
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService,
        EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute, connect_to_proxy,
        proxy_http_version,
    },
};
use rama_tls::client::verify_proxy_tls;
use rama_utils::macros::generate_set_and_with;

use super::{
    ConnectUdpSocket, ConnectUdpSocketConfig, ConnectUdpTarget, connect_udp_request,
    session_config, validate_connect_udp_response,
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

/// Idle timeout for a QUIC connection to a MASQUE proxy that carries tunnels: longer than a
/// tunnel's own idle policy (two minutes, RFC 9298 §3.1), so that policy decides when a quiet
/// tunnel ends. Configure it on both sides of that connection.
pub const OUTER_IDLE_TIMEOUT: Duration = Duration::from_mins(3);

/// A datagram proxy connector for MASQUE ([RFC 9298]): a CONNECT-UDP tunnel to the target of
/// a request on a [`ProxyRoute`], opened over the connector `C` towards that proxy.
///
/// The tunnel's target keeps its name: the proxy resolves it. A route whose proxy offers no
/// CONNECT-UDP is refused, so it is never bypassed. A tunnel publishes
/// [`EstablishedProxyRoute::Tunnel`] on its socket. Compose it with a direct datagram
/// connector in a [`MaybeProxiedConnector`] selecting by [`ProxiedRoute`] to make the proxy
/// optional.
///
/// `C` is the connector towards HTTP proxies, the same one CONNECT tunnels over: it receives
/// its own [`ConnectRequest`] addressed at the proxy and answers with an HTTP connection to
/// it, in the version the [`ProxyAddress`] asks for or negotiates. Tunnels through one proxy share that
/// connection when it can carry them. For HTTP/3 it needs an outer initial MTU of
/// [`OUTER_INITIAL_MTU`].
///
/// `B` is the body type of the connections towards the proxy, in which the CONNECT-UDP
/// request is built: a client reaches its proxies with the body type it serves origins with.
///
/// [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
/// [`MaybeProxiedConnector`]: rama_net::client::MaybeProxiedConnector
/// [`ProxiedRoute`]: rama_net::client::ProxiedRoute
#[derive(ExtensionsRef)]
pub struct HttpConnectUdpProxyConnector<C, B = Body> {
    inner: C,
    scope: WeakScope,
    socket: ConnectUdpSocketConfig,
    _phantom: PhantomData<fn() -> B>,
}

impl<C: fmt::Debug, B> fmt::Debug for HttpConnectUdpProxyConnector<C, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpConnectUdpProxyConnector")
            .field("inner", &self.inner)
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl<C: Clone, B> Clone for HttpConnectUdpProxyConnector<C, B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            scope: self.scope.clone(),
            socket: self.socket.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<C, B> HttpConnectUdpProxyConnector<C, B> {
    /// Tunnel over `proxy`; `scope` runs each tunnel's send task.
    pub fn new(inner: C, scope: impl Into<WeakScope>) -> Self {
        let scope = scope.into();
        Self {
            inner,
            scope,
            socket: ConnectUdpSocketConfig::default(),
            _phantom: PhantomData,
        }
    }
    generate_set_and_with! {
        /// Limits of each tunnel, including its idle timeout.
        pub fn socket_config(mut self, config: ConnectUdpSocketConfig) -> Self {
            self.socket = config;
            self
        }
    }

    generate_set_and_with! {
        /// See [`ConnectUdpSocketConfig::with_nested_connection_transfer`].
        pub fn nested_connection_transfer(mut self, transfer: impl NestedConnectionTransfer) -> Self {
            self.socket.set_nested_connection_transfer(transfer);
            self
        }
    }
}

impl<C, B> HttpConnectUdpProxyConnector<C, B>
where
    C: ConnectorService<
            ConnectRequest,
            Connection: Service<Request<B>, Output = Response, Error: Into<BoxError>>
                            + ExtensionsRef
                            + 'static,
        >,
    B: Default,
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
        extensions: &Extensions,
    ) -> Result<ConnectUdpSocket, BoxError> {
        // The tunnel's socket holds the connector's scope: a closed one opens no tunnel.
        let scope = self.scope.try_hold().context("connect-udp tunnel")?;
        let conn = connect_to_proxy(&self.inner, proxy, extensions).await?;
        verify_proxy_tls(proxy, conn.extensions())?;
        let version = proxy_http_version(proxy, &conn);
        let request = connect_udp_request(proxy, &target, version)?;
        // The token defines datagram semantics (RFC 9297 §2): declare them for this request.
        request.extensions().insert(HttpDatagrams);
        request.extensions().insert(TargetHttpVersion(version));
        let response = conn
            .serve(request)
            .await
            .map_err(Into::into)
            .context("connect-udp request")?;
        if let Err(error) = validate_connect_udp_response(version, &response) {
            return Err(error
                .context_field("status", response.status())
                .context("connect-udp tunnel refused"));
        }
        let upgraded = handle_upgrade(&response)
            .await
            .context("connect-udp upgrade")?
            .with_guard(conn);
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
            &scope,
            HttpDatagramSession::with_config(upgraded, session_config()),
            local,
            peer,
            self.socket.clone(),
        );
        socket
            .extensions()
            .insert(EstablishedProxyRoute::Tunnel(proxy.clone()));
        Ok(socket)
    }
}

impl<C, B> Service<ConnectRequest> for HttpConnectUdpProxyConnector<C, B>
where
    C: ConnectorService<
            ConnectRequest,
            Connection: Service<Request<B>, Output = Response, Error: Into<BoxError>> + 'static,
        >,
    B: Default + Send + 'static,
{
    type Output = EstablishedClientConnection<ConnectUdpSocket, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let Some(proxy) = input
            .extensions
            .get_ref::<ProxyRoute>()
            .and_then(ProxyRoute::proxy_address)
            .cloned()
        else {
            return Err(ConnectionError::local(
                BoxError::from_static_str("connect-udp connector: no proxied route is requested"),
                ConnectionErrorKind::InvalidInput,
            ));
        };
        if proxy.protocol.connect_udp_template().is_none() {
            return Err(ConnectionError::local(
                BoxError::from_static_str("connect-udp connector serves connect-udp proxies only"),
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
            .open(&proxy, target, &input.extensions)
            .await
            .map_err(|error| ConnectionError::transport(error, ConnectionErrorKind::Unavailable))?;
        Ok(EstablishedClientConnection { input, conn })
    }
}

/// A [`Layer`] producing [`HttpConnectUdpProxyConnector`]s over the connector towards proxies.
pub struct HttpConnectUdpProxyConnectorLayer {
    scope: WeakScope,
    socket: ConnectUdpSocketConfig,
}

impl fmt::Debug for HttpConnectUdpProxyConnectorLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpConnectUdpProxyConnectorLayer")
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl Clone for HttpConnectUdpProxyConnectorLayer {
    fn clone(&self) -> Self {
        Self {
            scope: self.scope.clone(),
            socket: self.socket.clone(),
        }
    }
}

impl HttpConnectUdpProxyConnectorLayer {
    /// `scope` runs each tunnel's send task.
    pub fn new(scope: impl Into<WeakScope>) -> Self {
        Self {
            scope: scope.into(),
            socket: ConnectUdpSocketConfig::default(),
        }
    }

    generate_set_and_with! {
        /// Limits of each tunnel, including its idle timeout.
        pub fn socket_config(mut self, config: ConnectUdpSocketConfig) -> Self {
            self.socket = config;
            self
        }
    }

    generate_set_and_with! {
        /// See [`ConnectUdpSocketConfig::with_nested_connection_transfer`].
        pub fn nested_connection_transfer(mut self, transfer: impl NestedConnectionTransfer) -> Self {
            self.socket.set_nested_connection_transfer(transfer);
            self
        }
    }
}

impl<C> Layer<C> for HttpConnectUdpProxyConnectorLayer {
    type Service = HttpConnectUdpProxyConnector<C>;

    fn layer(&self, inner: C) -> Self::Service {
        HttpConnectUdpProxyConnector {
            inner,
            scope: self.scope.clone(),
            socket: self.socket.clone(),
            _phantom: PhantomData,
        }
    }

    fn into_layer(self, inner: C) -> Self::Service {
        HttpConnectUdpProxyConnector {
            inner,
            scope: self.scope,
            socket: self.socket,
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests;
