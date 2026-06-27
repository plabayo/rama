use crate::{
    Socks5Client,
    client::{core::HandshakeError, proxy_error::Socks5ProxyError},
};
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    io::Io,
    telemetry::tracing,
};
#[cfg(feature = "dns")]
use rama_dns::client::{
    GlobalDnsResolver,
    resolver::{BoxDnsAddressResolver, DnsAddressResolver},
};
use rama_net::{
    ConnectorTargetInputExt,
    address::ProxyAddress,
    client::{ConnectorService, ConnectorTarget, EstablishedClientConnection},
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
    /// which will only connect via a socks5 proxy in case the [`ProxyAddress`] is available
    /// in the input [`Extensions`].
    ///
    /// [`Extensions`]: rama_core::extensions::Extensions
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    #[must_use]
    pub fn optional() -> Self {
        Self {
            required: false,
            #[cfg(feature = "dns")]
            dns_resolver: None,
        }
    }

    /// Create a new [`Socks5ProxyConnectorLayer`] which creates a [`Socks5ProxyConnector`]
    /// which will always connect via an http proxy, but fail in case the [`ProxyAddress`] is
    /// not available in the input [`Extensions`].
    ///
    /// [`Extensions`]: rama_core::extensions::Extensions
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
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
        /// Attach the [`Default`] [`DnsResolver`] to this [`Socks5ProxyConnectorLayer`].
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

    generate_set_and_with! {
        /// Attach a [`DnsResolver`] to this [`Socks5ProxyConnectorLayer`].
        ///
        /// It will try to be used (best-effort) to resolve domain addresses
        /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
        ///
        /// In case of an error with resolving the domain address the connector
        /// will anyway use the domain instead of the ip.
        pub fn dns_resolver(mut self, resolver: impl DnsAddressResolver) -> Self {
            self.dns_resolver = Some(resolver.into_box_dns_address_resolver());
            self
        }
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
/// is a [`ProxyAddress`] found in the [`Extensions`].
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
        /// Attach the [`Default`] [`DnsResolver`] to this [`Socks5ProxyConnector`].
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
        /// Attach a [`DnsResolver`] to this [`Socks5ProxyConnector`].
        ///
        /// It will try to be used (best-effort) to resolve domain addresses
        /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
        ///
        /// In case of an error with resolving the domain address the connector
        /// will anyway use the domain instead of the ip.
        pub fn dns_resolver(mut self, resolver: impl DnsAddressResolver) -> Self {
            self.dns_resolver = Some(resolver.into_box_dns_address_resolver());
            self
        }
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
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let Some(proxy_info) = input.extensions().get_ref::<ProxyAddress>().cloned() else {
            // return early in case we did not use a proxy

            return if self.required {
                Err(BoxError::from_static_str(
                    "socks5 proxy required but none is defined",
                ))
            } else {
                tracing::trace!(
                    "socks5 proxy connector: no proxy required or set: proceed with direct connection"
                );
                self.inner.connect(input).await.context(
                    "establish connection target (no socks5 proxy defined and neither reuired)",
                )
            };
        };

        if !proxy_info
            .protocol
            .as_ref()
            .map(|p| p.is_socks5())
            .unwrap_or(true)
        {
            return Err(BoxError::from_static_str(
                "socks5 proxy connector can only serve socks5 protocol",
            ));
        }

        #[cfg(feature = "dns")]
        let normalized_proxy_info = self
            .normalize_socks5_proxy_addr(
                input.extensions().get_ref().copied().unwrap_or_default(),
                proxy_info,
            )
            .await;
        #[cfg(not(feature = "dns"))]
        let normalized_proxy_info = self.normalize_socks5_proxy_addr(proxy_info).await;
        input.extensions().insert(normalized_proxy_info.clone());

        // insert target so that inner connector can use it instead of input's version
        input
            .extensions()
            .insert(ConnectorTarget(normalized_proxy_info.address.clone()));

        let EstablishedClientConnection { input, mut conn } = self
            .inner
            .connect(input)
            .await
            .context("establish connection to proxy")
            .with_context_field("address", || normalized_proxy_info.address.clone())
            .with_context_debug_field("protocol", || normalized_proxy_info.protocol.clone())?;

        let authority = input
            .authority()
            .context("socks5 proxy connector: resolve authority")?;

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
                return Err(BoxError::from_static_str(
                    "socks5proxy does not support auth with bearer credential",
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
            return Err(Box::new(Socks5ProxyError::Handshake(
                HandshakeError::other(BoxError::from_static_str(
                    "failed to get port from transport context",
                )),
            )));
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
            Err(err) => return Err(Box::new(Socks5ProxyError::Handshake(err))),
        }

        Ok(EstablishedClientConnection { input, conn })
    }
}
