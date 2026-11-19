use crate::{Socks5Client, client::proxy_error::Socks5ProxyError};
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Layer, Service,
    error::BoxError,
    extensions::{ExtensionsRef, ExtensionsTransfer, SharedExtensionsTransfer},
    io::Io,
    telemetry::tracing,
};
#[cfg(feature = "dns")]
use rama_dns::client::{
    GlobalDnsResolver,
    resolver::{BoxDnsAddressResolver, DnsAddressResolver},
};
use rama_net::{
    ConnectorTargetInputExt, ConnectorTransportProtocolInputExt,
    address::{HostWithPort, ProxyAddress},
    client::{
        ConnectionError, ConnectionErrorKind, ConnectorService, EstablishedClientConnection,
        EstablishedProxyRoute, ProxyDialRequest, ProxyDialer, ProxyRoute,
    },
    stream::{DefaultExtensionsTransfer, NestedConnection},
    transport::TransportProtocol,
    user::ProxyCredential,
};
#[cfg(feature = "dns")]
use rama_net::{
    address::{Host, ProxyProtocol},
    mode::DnsResolveIpMode,
};
use rama_utils::macros::define_inner_service_accessors;
use rama_utils::macros::generate_set_and_with;
#[cfg(feature = "dns")]
use std::net::IpAddr;

#[derive(Debug, Clone)]
/// A [`Layer`] which wraps the given connector towards the proxy, dialed through a
/// [`ProxyDialer`], with a [`Socks5ConnectProxyConnector`].
///
/// See [`Socks5ConnectProxyConnector`] for more information.
///
/// [`ProxyDialer`]: rama_net::client::ProxyDialer
pub struct Socks5ConnectProxyConnectorLayer {
    extensions_transfer: SharedExtensionsTransfer,
    #[cfg(feature = "dns")]
    dns_resolver: Option<BoxDnsAddressResolver>,
}

impl Default for Socks5ConnectProxyConnectorLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl Socks5ConnectProxyConnectorLayer {
    /// Create a new [`Socks5ConnectProxyConnectorLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            extensions_transfer: DefaultExtensionsTransfer.into_shared(),
            #[cfg(feature = "dns")]
            dns_resolver: None,
        }
    }

    generate_set_and_with! {
        /// Set what a SOCKS5 tunnel keeps from the proxy connection it is
        /// nested on.
        ///
        /// Defaults to [`DefaultExtensionsTransfer`]. Chain transfers with
        /// [`ExtensionsTransfer::and`] to also carry your own connection-scoped
        /// extension types across the tunnel.
        pub fn extensions_transfer(mut self, transfer: impl ExtensionsTransfer) -> Self {
            self.extensions_transfer = transfer.into_shared();
            self
        }
    }
}

#[cfg(feature = "dns")]
impl Socks5ConnectProxyConnectorLayer {
    generate_set_and_with! {
        /// Attach the default [`DnsAddressResolver`] to this [`Socks5ConnectProxyConnectorLayer`].
        ///
        /// It will try to be used (best-effort) to resolve domain addresses
        /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
        ///
        /// In case of an error with resolving the domain address the connector
        /// will anyway use the domain instead of the ip.
        pub fn default_dns_resolver(mut self) -> Self {
            self.dns_resolver = Some(GlobalDnsResolver::new().into_box_dns_address_resolver());
            self
        }
    }

    /// Attach a [`DnsAddressResolver`] to this [`Socks5ConnectProxyConnectorLayer`].
    ///
    /// It will try to be used (best-effort) to resolve domain addresses
    /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
    ///
    /// In case of an error with resolving the domain address the connector
    /// will anyway use the domain instead of the ip.
    #[must_use]
    pub fn with_dns_address_resolver(mut self, resolver: impl DnsAddressResolver) -> Self {
        self.dns_resolver = Some(resolver.into_box_dns_address_resolver());
        self
    }

    /// Attach a [`DnsAddressResolver`] to this [`Socks5ConnectProxyConnectorLayer`].
    ///
    /// It will try to be used (best-effort) to resolve domain addresses
    /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
    ///
    /// In case of an error with resolving the domain address the connector
    /// will anyway use the domain instead of the ip.
    pub fn set_dns_address_resolver(&mut self, resolver: impl DnsAddressResolver) -> &mut Self {
        self.dns_resolver = Some(resolver.into_box_dns_address_resolver());
        self
    }
}

impl<S> Layer<S> for Socks5ConnectProxyConnectorLayer {
    type Service = Socks5ConnectProxyConnector<ProxyDialer<S>>;

    fn layer(&self, inner: S) -> Self::Service {
        Socks5ConnectProxyConnector {
            inner: ProxyDialer::new(inner),
            extensions_transfer: self.extensions_transfer.clone(),
            #[cfg(feature = "dns")]
            dns_resolver: self.dns_resolver.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        Socks5ConnectProxyConnector {
            inner: ProxyDialer::new(inner),
            extensions_transfer: self.extensions_transfer,
            #[cfg(feature = "dns")]
            dns_resolver: self.dns_resolver,
        }
    }
}

/// A connector which establishes a tunnel over a SOCKS5 proxy.
///
/// A proxy is required: a request without a proxied [`ProxyRoute`] fails. Pair it with
/// [`MaybeProxiedConnector`] to connect directly instead when no proxy is requested.
///
/// The inner service dials the connection to the proxy, such as a [`ProxyDialer`]
/// over the connector towards proxies. The SOCKS5 handshake for the requested
/// target is spoken over the connection it returns.
///
/// [`MaybeProxiedConnector`]: rama_net::client::MaybeProxiedConnector
/// [`ProxyDialer`]: rama_net::client::ProxyDialer
#[derive(Debug, Clone, ExtensionsRef)]
pub struct Socks5ConnectProxyConnector<S> {
    inner: S,
    extensions_transfer: SharedExtensionsTransfer,
    #[cfg(feature = "dns")]
    dns_resolver: Option<BoxDnsAddressResolver>,
}

impl<S> Socks5ConnectProxyConnector<ProxyDialer<S>> {
    /// Creates a new [`Socks5ConnectProxyConnector`] over the given connector towards the proxy.
    pub fn new(inner: S) -> Self {
        Self::from_dialer(ProxyDialer::new(inner))
    }
}

impl<S> Socks5ConnectProxyConnector<S> {
    /// Creates a new [`Socks5ConnectProxyConnector`] over the connections to the proxy that
    /// `dialer` dials, see [`ProxyDialer`].
    pub fn from_dialer(dialer: S) -> Self {
        Self {
            inner: dialer,
            extensions_transfer: DefaultExtensionsTransfer.into_shared(),
            #[cfg(feature = "dns")]
            dns_resolver: None,
        }
    }

    generate_set_and_with! {
        /// Set what a SOCKS5 tunnel keeps from the proxy connection it is
        /// nested on.
        ///
        /// Defaults to [`DefaultExtensionsTransfer`]. Chain transfers with
        /// [`ExtensionsTransfer::and`] to also carry your own connection-scoped
        /// extension types across the tunnel.
        pub fn extensions_transfer(mut self, transfer: impl ExtensionsTransfer) -> Self {
            self.extensions_transfer = transfer.into_shared();
            self
        }
    }

    define_inner_service_accessors!();
}

#[cfg(feature = "dns")]
impl<S> Socks5ConnectProxyConnector<S> {
    generate_set_and_with! {
        /// Attach the default [`DnsAddressResolver`] to this [`Socks5ConnectProxyConnector`].
        ///
        /// It will try to be used (best-effort) to resolve domain addresses
        /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
        ///
        /// In case of an error with resolving the domain address the connector
        /// will anyway use the domain instead of the ip.
        pub fn default_dns_resolver(mut self) -> Self {
            self.dns_resolver = Some(GlobalDnsResolver::default().into_box_dns_address_resolver());
            self
        }
    }

    generate_set_and_with! {
        /// Attach a [`DnsAddressResolver`] to this [`Socks5ConnectProxyConnector`].
        ///
        /// It will try to be used (best-effort) to resolve domain addresses
        /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
        ///
        /// In case of an error with resolving the domain address the connector
        /// will anyway use the domain instead of the ip.
        pub fn dns_resolver(mut self, resolver: Option<BoxDnsAddressResolver>) -> Self {
            self.dns_resolver = resolver;
            self
        }
    }

    /// Attach a [`DnsAddressResolver`] to this [`Socks5ConnectProxyConnector`].
    ///
    /// It will try to be used (best-effort) to resolve domain addresses
    /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
    ///
    /// In case of an error with resolving the domain address the connector
    /// will anyway use the domain instead of the ip.
    #[must_use]
    pub fn with_dns_address_resolver(mut self, resolver: impl DnsAddressResolver) -> Self {
        self.dns_resolver = Some(resolver.into_box_dns_address_resolver());
        self
    }

    /// Attach a [`DnsAddressResolver`] to this [`Socks5ConnectProxyConnector`].
    ///
    /// It will try to be used (best-effort) to resolve domain addresses
    /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
    ///
    /// In case of an error with resolving the domain address the connector
    /// will anyway use the domain instead of the ip.
    pub fn set_dns_address_resolver(&mut self, resolver: impl DnsAddressResolver) -> &mut Self {
        self.dns_resolver = Some(resolver.into_box_dns_address_resolver());
        self
    }
}

impl<S> Socks5ConnectProxyConnector<S> {
    #[cfg(feature = "dns")]
    async fn resolve_handshake_target(
        &self,
        proxy: &ProxyAddress,
        dns_mode: DnsResolveIpMode,
        target: HostWithPort,
    ) -> HostWithPort {
        let Some(dns_resolver) = self.dns_resolver.as_ref() else {
            return target;
        };
        if !matches!(
            proxy.protocol,
            ProxyProtocol::Socks5 {
                remote_dns: false,
                ..
            }
        ) {
            return target;
        }
        let HostWithPort { host, port } = target;
        let Host::Name(domain) = host else {
            return HostWithPort::new(host, port);
        };

        let host = match dns_mode {
            DnsResolveIpMode::SingleIpV4 => {
                match dns_resolver.lookup_ipv4_rand(domain.clone()).await {
                    Some(Ok(addr)) => Host::Address(IpAddr::V4(addr)),
                    Some(Err(err)) => {
                        tracing::debug!(?err, "failed to lookup ipv4 addresses for domain");
                        Host::Name(domain)
                    }
                    None => {
                        tracing::debug!(
                            "failed to lookup ipv4 addresses for domain: no addresses found"
                        );
                        Host::Name(domain)
                    }
                }
            }
            DnsResolveIpMode::SingleIpV6 => {
                match dns_resolver.lookup_ipv6_rand(domain.clone()).await {
                    Some(Ok(addr)) => Host::Address(IpAddr::V6(addr)),
                    Some(Err(err)) => {
                        tracing::debug!(?err, "failed to lookup ipv6 addresses for domain");
                        Host::Name(domain)
                    }
                    None => {
                        tracing::debug!(
                            "failed to lookup ipv6 addresses for domain: no addresses found"
                        );
                        Host::Name(domain)
                    }
                }
            }
            DnsResolveIpMode::Dual | DnsResolveIpMode::DualPreferIpV4 => {
                crate::dns::race_resolve_dual(dns_resolver, domain.clone(), dns_mode)
                    .await
                    .map(Host::Address)
                    .unwrap_or(Host::Name(domain))
            }
        };

        HostWithPort::new(host, port)
    }

    #[cfg(not(feature = "dns"))]
    async fn resolve_handshake_target(
        &self,
        _proxy: &ProxyAddress,
        target: HostWithPort,
    ) -> HostWithPort {
        target
    }
}

impl<S, Input> Service<Input> for Socks5ConnectProxyConnector<S>
where
    S: ConnectorService<ProxyDialRequest, Connection: Io + Unpin>,
    Input: ConnectorTargetInputExt + ConnectorTransportProtocolInputExt + Send + 'static,
{
    type Output = EstablishedClientConnection<NestedConnection<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let proxy = match input.extensions().get_ref::<ProxyRoute>() {
            Some(ProxyRoute::Proxy(proxy)) => proxy.clone(),
            None | Some(ProxyRoute::Direct) => {
                return Err(ConnectionError::local(
                    BoxError::from_static_str(
                        "socks5 proxy connector: no proxied route is requested",
                    ),
                    ConnectionErrorKind::InvalidInput,
                ));
            }
        };

        if !proxy.protocol.is_socks5() || !proxy.protocol.carries(TransportProtocol::Tcp) {
            return Err(ConnectionError::local(
                BoxError::from_static_str("socks5 proxy connector serves socks5 CONNECT only"),
                ConnectionErrorKind::InvalidInput,
            )
            .context_debug_field("protocol", proxy.protocol.clone()));
        }
        if input.connector_transport_protocol() == Some(TransportProtocol::Udp) {
            return Err(ConnectionError::local(
                BoxError::from_static_str("socks5 proxy connector cannot tunnel a udp flow"),
                ConnectionErrorKind::InvalidInput,
            ));
        }
        if let Some(ProxyCredential::Bearer(_)) = proxy.credential {
            return Err(ConnectionError::local(
                BoxError::from_static_str("socks5 proxy does not support bearer credentials"),
                ConnectionErrorKind::InvalidInput,
            ));
        }

        let target = input.connector_target().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("socks5 proxy connector: destination missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;

        // `socks5` resolves the target locally, `socks5h` leaves it to the proxy.
        #[cfg(feature = "dns")]
        let target = self
            .resolve_handshake_target(
                &proxy,
                input.extensions().get_ref().copied().unwrap_or_default(),
                target,
            )
            .await;
        #[cfg(not(feature = "dns"))]
        let target = self.resolve_handshake_target(&proxy, target).await;

        let mut conn = self
            .inner
            .connect(ProxyDialRequest {
                proxy: proxy.clone(),
                origin: input.extensions().clone(),
            })
            .await?
            .conn;

        tracing::trace!(
            network.peer.address = %proxy.address.host,
            network.peer.port = proxy.address.port,
            server.address = %target.host,
            server.port = target.port,
            "socks5 proxy connector: connected to proxy",
        );

        let mut client = Socks5Client::new();

        match &proxy.credential {
            Some(ProxyCredential::Basic(basic)) => {
                tracing::trace!(
                    network.peer.address = %proxy.address.host,
                    network.peer.port = proxy.address.port,
                    server.address = %target.host,
                    server.port = target.port,
                    "socks5 proxy connector: continue handshake with authorisation",
                );
                client.set_auth(basic.clone());
            }
            Some(ProxyCredential::Bearer(_)) | None => {
                tracing::trace!(
                    network.peer.address = %proxy.address.host,
                    network.peer.port = proxy.address.port,
                    server.address = %target.host,
                    server.port = target.port,
                    "socks5 proxy connector: continue handshake without authorisation",
                );
            }
        }

        match client.handshake_connect(&mut conn, &target).await {
            Ok(bind_addr) => {
                tracing::trace!(
                    network.peer.address = %proxy.address.host,
                    network.peer.port = proxy.address.port,
                    server.address = %target.host,
                    server.port = target.port,
                    %bind_addr,
                    "socks5 proxy connector: handshake complete",
                )
            }
            Err(error) => {
                return Err(ConnectionError::from(Socks5ProxyError::Handshake(error)));
            }
        }

        // The established byte stream now addresses the destination rather than
        // the proxy whose transport supplied the inherited policy.
        let conn = NestedConnection::new(conn, &self.extensions_transfer);
        conn.extensions()
            .insert(EstablishedProxyRoute::Tunnel(proxy));
        Ok(EstablishedClientConnection { input, conn })
    }
}

#[cfg(test)]
mod tests {
    use rama_core::{ServiceInput, extensions::Extensions, io::AbortIo, service::service_fn};
    use rama_net::{
        AuthorityInputExt, ConnectorTransportProtocolInputExt, Protocol, ProtocolInputExt,
        TransportProtocolInputExt,
        address::HostWithPort,
        client::{
            ConnectRequest, ConnectionErrorDomain, ConnectorService, ConnectorTarget, ProxyRoute,
            pool::{ConnectionReuse, ConnectionReusePolicy, ReuseKey},
        },
        transport::TransportProtocol,
        user::credentials::bearer,
    };
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[derive(Debug, rama_core::extensions::Extension, PartialEq)]
    struct OriginMarker(u8);

    #[derive(Debug)]
    struct FixedProxyPolicy;

    impl ConnectionReusePolicy for FixedProxyPolicy {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            Some(ReuseKey::of::<Self>())
        }

        fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
            Some(ReuseKey::of::<Self>())
        }
    }

    fn unreachable_proxy_connector()
    -> impl ConnectorService<ConnectRequest, Connection = ServiceInput<tokio::io::DuplexStream>>
    {
        service_fn(|_: ConnectRequest| async move {
            Err::<EstablishedClientConnection<ServiceInput<tokio::io::DuplexStream>, _>, _>(
                ConnectionError::local(
                    BoxError::from_static_str("connector towards the proxy must not be used"),
                    ConnectionErrorKind::Unavailable,
                ),
            )
        })
    }

    #[tokio::test]
    async fn a_route_without_a_proxy_is_not_served() {
        for route in [None, Some(ProxyRoute::Direct)] {
            let input = ConnectRequest::new(HostWithPort::example_domain_http());
            if let Some(route) = route {
                input.extensions.insert(route);
            }

            let error = Socks5ConnectProxyConnector::new(unreachable_proxy_connector())
                .connect(input)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, rama_core::extensions::Extension)]
    #[extension(scope(connection))]
    struct ProxyLegFact(u8);

    #[tokio::test]
    async fn a_custom_transfer_carries_a_connection_scoped_type_across_the_tunnel() {
        let selected: ProxyAddress = "socks5h://user:secret@proxy.example:1080".parse().unwrap();
        let (io, mut peer) = tokio::io::duplex(4096);
        let peer_task = tokio::spawn(async move {
            assert_eq!(peer.read_u8().await.unwrap(), 5);
            let methods_len = peer.read_u8().await.unwrap();
            let mut methods = vec![0; usize::from(methods_len)];
            peer.read_exact(&mut methods).await.unwrap();
            peer.write_all(&[5, 2]).await.unwrap();

            assert_eq!(peer.read_u8().await.unwrap(), 1);
            let user_len = peer.read_u8().await.unwrap();
            let mut user = vec![0; usize::from(user_len)];
            peer.read_exact(&mut user).await.unwrap();
            let pass_len = peer.read_u8().await.unwrap();
            let mut pass = vec![0; usize::from(pass_len)];
            peer.read_exact(&mut pass).await.unwrap();
            peer.write_all(&[1, 0]).await.unwrap();

            let mut head = [0; 4];
            peer.read_exact(&mut head).await.unwrap();
            assert_eq!(head, [5, 1, 0, 3]);
            let host_len = peer.read_u8().await.unwrap();
            let mut host = vec![0; usize::from(host_len)];
            peer.read_exact(&mut host).await.unwrap();
            assert_eq!(peer.read_u16().await.unwrap(), 80);
            peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
        });

        let carry_fact = |outer: &Extensions, nested: &Extensions| {
            if let Some(fact) = outer.get_ref::<ProxyLegFact>() {
                nested.insert(*fact);
            }
        };

        let io = Arc::new(parking_lot::Mutex::new(Some(io)));
        let inner = service_fn(move |input: ConnectRequest| {
            let io = io.lock().take().unwrap();
            async move {
                let conn = ServiceInput::new(io);
                conn.extensions().insert(ProxyLegFact(7));
                conn.extensions()
                    .insert(ConnectionReuse::new(FixedProxyPolicy));
                Ok::<_, Infallible>(EstablishedClientConnection { input, conn })
            }
        });
        let connector = Socks5ConnectProxyConnector::new(inner)
            .with_extensions_transfer(DefaultExtensionsTransfer.and(carry_fact));
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(ProxyRoute::Proxy(selected));

        let established = tokio::time::timeout(Duration::from_secs(2), connector.connect(input))
            .await
            .expect("SOCKS handshake timed out")
            .unwrap();
        peer_task.await.unwrap();

        assert_eq!(
            established.conn.extensions().get_ref::<ProxyLegFact>(),
            Some(&ProxyLegFact(7)),
            "the configured transfer carries it onto the tunnel"
        );
        let reuse = established
            .conn
            .extensions()
            .get_ref::<ConnectionReuse>()
            .expect("the default transfer still runs");
        assert!(!reuse.is_complete());
    }

    #[tokio::test]
    async fn successful_socks_connection_publishes_exact_selected_route() {
        let selected: ProxyAddress = "socks5://user:secret@proxy.example:1080".parse().unwrap();
        let (io, mut peer) = tokio::io::duplex(4096);
        let peer_task = tokio::spawn(async move {
            assert_eq!(peer.read_u8().await.unwrap(), 5);
            let methods_len = peer.read_u8().await.unwrap();
            let mut methods = vec![0; usize::from(methods_len)];
            peer.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0));
            peer.write_all(&[5, 0]).await.unwrap();

            let mut head = [0; 4];
            peer.read_exact(&mut head).await.unwrap();
            #[cfg(feature = "dns")]
            {
                assert_eq!(head, [5, 1, 0, 1], "socks5 resolves the target locally");
                let mut host = [0; 4];
                peer.read_exact(&mut host).await.unwrap();
                assert_eq!(host, [127, 0, 0, 1]);
            }
            #[cfg(not(feature = "dns"))]
            {
                assert_eq!(head, [5, 1, 0, 3]);
                let host_len = peer.read_u8().await.unwrap();
                let mut host = vec![0; usize::from(host_len)];
                peer.read_exact(&mut host).await.unwrap();
                assert_eq!(host, b"example.com");
            }
            assert_eq!(peer.read_u16().await.unwrap(), 80);
            peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
        });
        let io = Arc::new(parking_lot::Mutex::new(Some(io)));
        let inner = service_fn(move |input: ConnectRequest| {
            let io = io.lock().take().unwrap();
            async move {
                assert_eq!(input.authority, "proxy.example:1080".parse().unwrap());
                assert_eq!(input.protocol(), Some(&Protocol::SOCKS5));
                assert_eq!(input.transport_protocol(), Some(TransportProtocol::Tcp));
                let conn = ServiceInput::new(io);
                conn.extensions()
                    .insert(ConnectionReuse::new(FixedProxyPolicy));
                Ok::<_, Infallible>(EstablishedClientConnection { input, conn })
            }
        });
        let connector = Socks5ConnectProxyConnector::new(inner);
        #[cfg(feature = "dns")]
        let connector = connector.with_dns_address_resolver(std::net::Ipv4Addr::LOCALHOST);
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(ProxyRoute::Proxy(selected.clone()));
        #[cfg(feature = "dns")]
        input.extensions.insert(DnsResolveIpMode::SingleIpV4);

        let established = tokio::time::timeout(Duration::from_secs(2), connector.connect(input))
            .await
            .expect("SOCKS handshake timed out")
            .unwrap();
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<EstablishedProxyRoute>(),
            Some(&EstablishedProxyRoute::Tunnel(selected)),
        );
        let reuse = established
            .conn
            .extensions()
            .get_ref::<ConnectionReuse>()
            .unwrap();
        assert!(reuse.is_reusable());
        assert!(
            !reuse.is_complete(),
            "proxy policy cannot classify the origin"
        );
        tokio::time::timeout(Duration::from_secs(2), peer_task)
            .await
            .expect("SOCKS peer timed out")
            .unwrap();
    }

    #[cfg(feature = "dns")]
    #[tokio::test]
    async fn socks5h_leaves_resolving_the_target_to_the_proxy() {
        let (io, mut peer) = tokio::io::duplex(4096);
        let peer_task = tokio::spawn(async move {
            assert_eq!(peer.read_u8().await.unwrap(), 5);
            let methods_len = peer.read_u8().await.unwrap();
            let mut methods = vec![0; usize::from(methods_len)];
            peer.read_exact(&mut methods).await.unwrap();
            peer.write_all(&[5, 0]).await.unwrap();
            let mut head = [0; 4];
            peer.read_exact(&mut head).await.unwrap();
            assert_eq!(head, [5, 1, 0, 3]);
            let host_len = peer.read_u8().await.unwrap();
            let mut host = vec![0; usize::from(host_len)];
            peer.read_exact(&mut host).await.unwrap();
            assert_eq!(host, b"example.com");
            assert_eq!(peer.read_u16().await.unwrap(), 80);
            peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
        });
        let io = Arc::new(parking_lot::Mutex::new(Some(io)));
        let inner = service_fn(move |input: ConnectRequest| {
            let io = io.lock().take().unwrap();
            async move {
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(io),
                })
            }
        });
        let connector = Socks5ConnectProxyConnector::new(inner)
            .with_dns_address_resolver(std::net::Ipv4Addr::LOCALHOST);
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(ProxyRoute::Proxy(
            "socks5h://proxy.example:1080".parse().unwrap(),
        ));
        input.extensions.insert(DnsResolveIpMode::SingleIpV4);

        tokio::time::timeout(Duration::from_secs(2), connector.connect(input))
            .await
            .expect("SOCKS handshake timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), peer_task)
            .await
            .expect("SOCKS peer timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn the_tunnel_aborts_the_proxy_stream() {
        let (io, mut peer) = tokio::io::duplex(4096);
        let peer_task = tokio::spawn(async move {
            assert_eq!(peer.read_u8().await.unwrap(), 5);
            let methods_len = peer.read_u8().await.unwrap();
            let mut methods = vec![0; usize::from(methods_len)];
            peer.read_exact(&mut methods).await.unwrap();
            peer.write_all(&[5, 0]).await.unwrap();

            let mut head = [0; 4];
            peer.read_exact(&mut head).await.unwrap();
            let host_len = peer.read_u8().await.unwrap();
            let mut host = vec![0; usize::from(host_len)];
            peer.read_exact(&mut host).await.unwrap();
            peer.read_u16().await.unwrap();
            peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
        });
        let aborted = Arc::new(AtomicBool::new(false));
        let io = Arc::new(parking_lot::Mutex::new(Some(io)));
        let inner = service_fn({
            let aborted = aborted.clone();
            move |input: ConnectRequest| {
                let io = io.lock().take().unwrap();
                let aborted = aborted.clone();
                async move {
                    let conn = ServiceInput::new(io);
                    conn.extensions().insert(AbortIo::new(move || {
                        aborted.store(true, Ordering::Release);
                    }));
                    Ok::<_, Infallible>(EstablishedClientConnection { input, conn })
                }
            }
        });
        let connector = Socks5ConnectProxyConnector::new(inner);
        #[cfg(feature = "dns")]
        let connector = connector.with_dns_address_resolver(std::net::Ipv4Addr::LOCALHOST);
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(ProxyRoute::Proxy(
            "socks5h://proxy.example:1080".parse().unwrap(),
        ));
        #[cfg(feature = "dns")]
        input.extensions.insert(DnsResolveIpMode::SingleIpV4);

        let established = tokio::time::timeout(Duration::from_secs(2), connector.connect(input))
            .await
            .expect("SOCKS handshake timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), peer_task)
            .await
            .expect("SOCKS peer timed out")
            .unwrap();

        established
            .conn
            .extensions()
            .get_arc::<AbortIo>()
            .expect("the tunnel fronts the proxy stream")
            .abort();
        assert!(aborted.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn selected_service_is_socks_destination_without_changing_origin() {
        let (io, mut peer) = tokio::io::duplex(4096);
        let peer_task = tokio::spawn(async move {
            assert_eq!(peer.read_u8().await.unwrap(), 5);
            let methods_len = peer.read_u8().await.unwrap();
            let mut methods = vec![0; usize::from(methods_len)];
            peer.read_exact(&mut methods).await.unwrap();
            peer.write_all(&[5, 0]).await.unwrap();
            let mut head = [0; 4];
            peer.read_exact(&mut head).await.unwrap();
            assert_eq!(head, [5, 1, 0, 3]);
            let host_len = peer.read_u8().await.unwrap();
            let mut host = vec![0; usize::from(host_len)];
            peer.read_exact(&mut host).await.unwrap();
            assert_eq!(host, b"alternative.example");
            assert_eq!(peer.read_u16().await.unwrap(), 8443);
            peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
        });
        let io = Arc::new(parking_lot::Mutex::new(Some(io)));
        let inner = service_fn(move |input: ConnectRequest| {
            let io = io.lock().take().unwrap();
            async move {
                assert_eq!(
                    input.connector_target().unwrap(),
                    "127.0.0.1:1080".parse().unwrap()
                );
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(io),
                })
            }
        });
        let connector = Socks5ConnectProxyConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_http())
            .with_application_protocol(Protocol::HTTP);
        input.extensions.insert(ProxyRoute::Proxy(
            "socks5://127.0.0.1:1080".parse().unwrap(),
        ));
        input
            .extensions
            .insert(ConnectorTarget("alternative.example:8443".parse().unwrap()));
        let established = tokio::time::timeout(Duration::from_secs(2), connector.connect(input))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(established.input.protocol(), Some(&Protocol::HTTP));
        assert_eq!(
            established.input.authority().unwrap(),
            HostWithPort::example_domain_http().into()
        );
        peer_task.await.unwrap();
    }

    #[tokio::test]
    async fn the_request_to_the_proxy_forks_the_origin_request() {
        let inner = service_fn(|input: ConnectRequest| async move {
            assert_eq!(input.authority, "127.0.0.1:1080".parse().unwrap());
            assert_eq!(input.protocol(), Some(&Protocol::SOCKS5));
            assert_eq!(
                input.connector_transport_protocol(),
                Some(TransportProtocol::Tcp)
            );
            assert_eq!(input.extensions.get_ref(), Some(&OriginMarker(1)));
            input.extensions.insert(OriginMarker(2));
            Err::<EstablishedClientConnection<ServiceInput<tokio::io::DuplexStream>, _>, _>(
                ConnectionError::local(
                    BoxError::from_static_str("stop after observing connector input"),
                    ConnectionErrorKind::Unavailable,
                ),
            )
        });
        let connector = Socks5ConnectProxyConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::HTTPS)
            .with_transport_protocol(TransportProtocol::Tcp);
        input.extensions.insert(ProxyRoute::Proxy(
            "socks5://127.0.0.1:1080".parse().unwrap(),
        ));
        input.extensions.insert(OriginMarker(1));

        let error = connector.connect(input.clone()).await.unwrap_err();
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(input.extensions.get_ref(), Some(&OriginMarker(1)));
    }

    async fn assert_refused_locally(input: ConnectRequest) {
        let error = Socks5ConnectProxyConnector::new(unreachable_proxy_connector())
            .connect(input)
            .await
            .unwrap_err();
        assert_eq!(
            (error.domain(), error.kind()),
            (
                ConnectionErrorDomain::Local,
                ConnectionErrorKind::InvalidInput
            ),
            "{error:?}"
        );
    }

    fn proxied(proxy: ProxyAddress) -> ConnectRequest {
        let input = ConnectRequest::new(HostWithPort::example_domain_http());
        input.extensions.insert(ProxyRoute::Proxy(proxy));
        input
    }

    #[tokio::test]
    async fn a_non_socks_proxy_protocol_is_rejected() {
        assert_refused_locally(proxied("http://proxy.example:8080".parse().unwrap())).await;
    }

    #[tokio::test]
    async fn a_udp_only_socks_proxy_is_rejected() {
        assert_refused_locally(proxied("socks5+udp://proxy.example:1080".parse().unwrap())).await;
    }

    #[tokio::test]
    async fn bearer_credentials_are_rejected() {
        let mut proxy: ProxyAddress = "socks5://proxy.example:1080".parse().unwrap();
        proxy.credential = Some(ProxyCredential::Bearer(bearer!("token")));
        assert_refused_locally(proxied(proxy)).await;
    }

    #[tokio::test]
    async fn a_udp_flow_is_never_turned_into_a_connect() {
        assert_refused_locally(
            proxied("socks5://proxy.example:1080".parse().unwrap())
                .with_transport_protocol(TransportProtocol::Udp),
        )
        .await;
    }
}
