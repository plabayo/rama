use crate::{Socks5Client, client::proxy_error::Socks5ProxyError};
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Layer, Service, error::BoxError, extensions::ExtensionsRef, io::Io, telemetry::tracing,
};
#[cfg(feature = "dns")]
use rama_dns::client::{
    GlobalDnsResolver,
    resolver::{BoxDnsAddressResolver, DnsAddressResolver},
};
use rama_net::{
    ConnectorTargetInputExt,
    address::ProxyAddress,
    client::{
        ConnectionError, ConnectionErrorKind, ConnectorService, ConnectorTarget,
        ConnectorTransportProtocol, EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute,
    },
    transport::TransportProtocol,
    user::ProxyCredential,
};
#[cfg(feature = "dns")]
use rama_net::{Protocol, address::Host, mode::DnsResolveIpMode};
use rama_utils::macros::define_inner_service_accessors;
#[cfg(feature = "dns")]
use rama_utils::macros::generate_set_and_with;
#[cfg(feature = "dns")]
use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
/// A [`Layer`] which wraps the given service with a [`Socks5ProxyConnector`].
///
/// See [`Socks5ProxyConnector`] for more information.
pub struct Socks5ProxyConnectorLayer {
    required: bool,
    #[cfg(feature = "dns")]
    dns_resolver: Option<BoxDnsAddressResolver>,
}

impl Socks5ProxyConnectorLayer {
    /// Create a new [`Socks5ProxyConnectorLayer`] which creates a [`Socks5ProxyConnector`]
    /// which will only connect via a socks5 proxy when a proxied [`ProxyRoute`] is available
    /// in the input [`Extensions`].
    ///
    /// [`Extensions`]: rama_core::extensions::Extensions
    /// [`ProxyRoute`]: rama_net::client::ProxyRoute
    #[must_use]
    pub fn optional() -> Self {
        Self {
            required: false,
            #[cfg(feature = "dns")]
            dns_resolver: None,
        }
    }

    /// Create a new [`Socks5ProxyConnectorLayer`] which creates a [`Socks5ProxyConnector`]
    /// which will always connect via a SOCKS5 proxy, but fail when a proxied [`ProxyRoute`] is
    /// not available in the input [`Extensions`].
    ///
    /// [`Extensions`]: rama_core::extensions::Extensions
    /// [`ProxyRoute`]: rama_net::client::ProxyRoute
    #[must_use]
    pub fn required() -> Self {
        Self {
            required: true,
            #[cfg(feature = "dns")]
            dns_resolver: None,
        }
    }
}

#[cfg(feature = "dns")]
impl Socks5ProxyConnectorLayer {
    generate_set_and_with! {
        /// Attach the default [`DnsAddressResolver`] to this [`Socks5ProxyConnectorLayer`].
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

    /// Attach a [`DnsAddressResolver`] to this [`Socks5ProxyConnectorLayer`].
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

    /// Attach a [`DnsAddressResolver`] to this [`Socks5ProxyConnectorLayer`].
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

impl<S> Layer<S> for Socks5ProxyConnectorLayer {
    type Service = Socks5ProxyConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Socks5ProxyConnector {
            inner,
            required: self.required,
            #[cfg(feature = "dns")]
            dns_resolver: self.dns_resolver.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        Socks5ProxyConnector {
            inner,
            required: self.required,
            #[cfg(feature = "dns")]
            dns_resolver: self.dns_resolver,
        }
    }
}

/// A connector which can be used to establish a connection over a SOCKS5 Proxy.
///
/// This behaviour is optional and only triggered in case there
/// is a proxied [`ProxyRoute`] found in the [`Extensions`].
///
/// [`Extensions`]: rama_core::extensions::Extensions
#[derive(Debug, Clone)]
pub struct Socks5ProxyConnector<S> {
    inner: S,
    required: bool,
    #[cfg(feature = "dns")]
    dns_resolver: Option<BoxDnsAddressResolver>,
}

impl<S> Socks5ProxyConnector<S> {
    /// Creates a new [`Socks5ProxyConnector`].
    fn new(inner: S, required: bool) -> Self {
        Self {
            inner,
            required,
            #[cfg(feature = "dns")]
            dns_resolver: None,
        }
    }

    /// Creates a new optional [`Socks5ProxyConnector`].
    #[inline]
    pub fn optional(inner: S) -> Self {
        Self::new(inner, false)
    }

    /// Creates a new required [`Socks5ProxyConnector`].
    #[inline]
    pub fn required(inner: S) -> Self {
        Self::new(inner, true)
    }

    define_inner_service_accessors!();
}

#[cfg(feature = "dns")]
impl<S> Socks5ProxyConnector<S> {
    generate_set_and_with! {
        /// Attach the default [`DnsAddressResolver`] to this [`Socks5ProxyConnector`].
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
        /// Attach a [`DnsAddressResolver`] to this [`Socks5ProxyConnector`].
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

    /// Attach a [`DnsAddressResolver`] to this [`Socks5ProxyConnector`].
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

    /// Attach a [`DnsAddressResolver`] to this [`Socks5ProxyConnector`].
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

impl<S> Socks5ProxyConnector<S> {
    #[cfg(feature = "dns")]
    async fn normalize_socks5_proxy_addr(
        &self,
        dns_mode: DnsResolveIpMode,
        addr: ProxyAddress,
    ) -> ProxyAddress {
        if let Some(dns_resolver) = self.dns_resolver.as_ref()
            && addr.protocol == Some(Protocol::SOCKS5)
        {
            use rama_net::address::HostWithPort;

            let ProxyAddress {
                protocol,
                address: HostWithPort { host, port },
                credential,
            } = addr;

            let host = match host {
                Host::Name(domain) => match dns_mode {
                    DnsResolveIpMode::SingleIpV4 => {
                        match dns_resolver.lookup_ipv4_rand(domain.clone()).await {
                            Some(Ok(addr)) => Host::Address(IpAddr::V4(addr)),
                            Some(Err(err)) => {
                                tracing::debug!(
                                    "failed to lookup ipv4 addresses for domain: {err:?}"
                                );
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
                                tracing::debug!(
                                    "failed to lookup ipv6 addresses for domain: {err:?}"
                                );
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
                },
                // IPs and any non-Domain shape pass through unchanged —
                // there's nothing to resolve.
                _ => host,
            };

            let address = HostWithPort::new(host, port);
            return ProxyAddress {
                protocol,
                address,
                credential,
            };
        }

        addr
    }

    #[cfg(not(feature = "dns"))]
    async fn normalize_socks5_proxy_addr(&self, addr: ProxyAddress) -> ProxyAddress {
        addr
    }
}

impl<S, Input> Service<Input> for Socks5ProxyConnector<S>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: ConnectorTargetInputExt + Send + 'static,
{
    type Output = EstablishedClientConnection<S::Connection, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let route_requested = input.extensions().contains::<ProxyRoute>();
        let proxy_info = match input.extensions().get_ref::<ProxyRoute>() {
            Some(ProxyRoute::Proxy(proxy_info)) => proxy_info.clone(),
            None | Some(ProxyRoute::Direct) => {
                return if self.required {
                    Err(ConnectionError::local(
                        BoxError::from_static_str("socks5 proxy required but none is defined"),
                        ConnectionErrorKind::InvalidInput,
                    ))
                } else {
                    tracing::trace!(
                        "socks5 proxy connector: no proxy required or set: proceed with direct connection"
                    );
                    let established = self.inner.connect(input).await.map_err(|error| {
                        error.context(
                            "establish connection target (no socks5 proxy defined and neither required)",
                        )
                    })?;
                    if route_requested {
                        established
                            .conn
                            .extensions()
                            .insert(EstablishedProxyRoute::Direct);
                    }
                    Ok(established)
                };
            }
        };

        if !proxy_info
            .protocol
            .as_ref()
            .map(|p| p.is_socks5())
            .unwrap_or(true)
        {
            return Err(ConnectionError::transport(
                BoxError::from_static_str("socks5 proxy connector can only serve socks5 protocol"),
                ConnectionErrorKind::Protocol,
            )
            .context_debug_field("protocol", proxy_info.protocol.clone()));
        }

        // Preserve the selected route before local DNS resolution changes the
        // proxy's dial address. Connection consumers need the route that won
        // selection, including its original address and credentials.
        let selected_route = EstablishedProxyRoute::Tunnel(proxy_info.clone());

        #[cfg(feature = "dns")]
        let normalized_proxy_info = self
            .normalize_socks5_proxy_addr(
                input.extensions().get_ref().copied().unwrap_or_default(),
                proxy_info,
            )
            .await;
        #[cfg(not(feature = "dns"))]
        let normalized_proxy_info = self.normalize_socks5_proxy_addr(proxy_info).await;
        input
            .extensions()
            .insert(ProxyRoute::Proxy(normalized_proxy_info.clone()));

        // insert target so that inner connector can use it instead of input's version
        input
            .extensions()
            .insert(ConnectorTarget(normalized_proxy_info.address.clone()));
        input
            .extensions()
            .insert(ConnectorTransportProtocol(TransportProtocol::Tcp));

        let EstablishedClientConnection { input, mut conn } =
            self.inner.connect(input).await.map_err(|error| {
                error
                    .context("establish connection to proxy")
                    .context_field("address", normalized_proxy_info.address.clone())
                    .context_debug_field("protocol", normalized_proxy_info.protocol.clone())
            })?;

        let authority = input.authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("socks5 proxy connector: authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;

        tracing::trace!(
            network.peer.address = %normalized_proxy_info.address.host,
            network.peer.port = %normalized_proxy_info.address.port,
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "socks5 proxy connector: connected to proxy",
        );

        let mut client = Socks5Client::new();

        match &normalized_proxy_info.credential {
            Some(ProxyCredential::Basic(basic)) => {
                tracing::trace!(
                    network.peer.address = %normalized_proxy_info.address.host,
                    network.peer.port = %normalized_proxy_info.address.port,
                    server.address = %authority.host,
                    server.port = authority.port_u16(),
                    "socks5 proxy connector: continue handshake with authorisation",
                );
                client.set_auth(basic.clone());
            }
            Some(ProxyCredential::Bearer(_)) => {
                return Err(ConnectionError::local(
                    BoxError::from_static_str(
                        "socks5proxy does not support auth with bearer credential",
                    ),
                    ConnectionErrorKind::InvalidInput,
                ));
            }
            None => {
                tracing::trace!(
                    network.peer.address = %normalized_proxy_info.address.host,
                    network.peer.port = %normalized_proxy_info.address.port,
                    server.address = %authority.host,
                    server.port = authority.port_u16(),
                    "socks5 proxy connector: continue handshake without authorisation",
                );
            }
        }

        let Some(connect_authority) = authority
            .clone()
            .into_host_with_port(input.protocol_default_port())
        else {
            return Err(ConnectionError::local(
                BoxError::from_static_str("failed to get port from transport context"),
                ConnectionErrorKind::InvalidInput,
            ));
        };

        match client
            .handshake_connect(&mut conn, &connect_authority)
            .await
        {
            Ok(bind_addr) => {
                tracing::trace!(
                    network.peer.address = %normalized_proxy_info.address.host,
                    network.peer.port = %normalized_proxy_info.address.port,
                    server.address = %authority.host,
                    server.port = authority.port_u16(),
                    %bind_addr,
                    "socks5 proxy connector: handshake complete",
                )
            }
            Err(error) => {
                return Err(ConnectionError::from(Socks5ProxyError::Handshake(error)));
            }
        }

        conn.extensions().insert(selected_route);
        Ok(EstablishedClientConnection { input, conn })
    }
}

#[cfg(test)]
mod tests {
    use rama_core::{ServiceInput, service::service_fn};
    use rama_net::{
        ConnectorTransportProtocolInputExt, Protocol,
        address::HostWithPort,
        client::{ConnectRequest, ProxyRoute},
    };
    use std::{convert::Infallible, sync::Arc, time::Duration};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[tokio::test]
    async fn optional_direct_connection_preserves_absent_or_explicit_route() {
        for route in [None, Some(ProxyRoute::Direct)] {
            let route_requested = route.is_some();
            let inner = service_fn(move |input: ConnectRequest| async move {
                let (io, _peer) = tokio::io::duplex(64);
                let conn = ServiceInput::new(io);
                if route_requested {
                    conn.extensions().insert(EstablishedProxyRoute::Tunnel(
                        "socks5://stale.example:1080".parse().unwrap(),
                    ));
                }
                Ok::<_, Infallible>(EstablishedClientConnection { input, conn })
            });
            let input = ConnectRequest::new(HostWithPort::example_domain_http());
            if let Some(route) = route {
                input.extensions.insert(route);
            }

            let established = Socks5ProxyConnector::optional(inner)
                .connect(input)
                .await
                .unwrap();
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<EstablishedProxyRoute>(),
                route_requested.then_some(&EstablishedProxyRoute::Direct),
            );
        }
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
                #[cfg(feature = "dns")]
                assert_eq!(
                    input
                        .extensions
                        .get_ref::<ProxyRoute>()
                        .and_then(ProxyRoute::proxy_address)
                        .unwrap()
                        .address
                        .host,
                    "127.0.0.1".parse::<Host>().unwrap(),
                );
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(io),
                })
            }
        });
        let connector = Socks5ProxyConnector::optional(inner);
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
        tokio::time::timeout(Duration::from_secs(2), peer_task)
            .await
            .expect("SOCKS peer timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn stamps_physical_tcp_before_connecting_to_proxy() {
        let inner = service_fn(|input: ConnectRequest| async move {
            assert_eq!(
                input.connector_transport_protocol(),
                Some(TransportProtocol::Tcp)
            );
            Err::<EstablishedClientConnection<ServiceInput<tokio::io::DuplexStream>, _>, _>(
                ConnectionError::local(
                    BoxError::from_static_str("stop after observing connector input"),
                    ConnectionErrorKind::Unavailable,
                ),
            )
        });
        let connector = Socks5ProxyConnector::optional(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https())
            .with_application_protocol(Protocol::HTTPS)
            .with_transport_protocol(TransportProtocol::Udp);
        input.extensions.insert(ProxyRoute::Proxy(
            "socks5://127.0.0.1:1080".parse().unwrap(),
        ));

        let error = connector.connect(input).await.unwrap_err();
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
    }
}
