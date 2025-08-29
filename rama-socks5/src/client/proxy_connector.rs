use crate::{Socks5Client, client::proxy_error::Socks5ProxyError};
use rama_core::telemetry::tracing;
use rama_core::{
    Context, Layer, Service,
    error::{BoxError, ErrorExt, OpaqueError},
};
use rama_net::{
    address::ProxyAddress,
    client::{ConnectorService, EstablishedClientConnection},
    stream::Stream,
    transport::TryRefIntoTransportContext,
    user::ProxyCredential,
};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

#[cfg(feature = "dns")]
use ::{
    rama_dns::{BoxDnsResolver, DnsResolver},
    rama_net::{
        Protocol,
        address::{Authority, Host},
        mode::DnsResolveIpMode,
    },
    rama_utils::macros::generate_set_and_with,
    std::net::IpAddr,
    tokio::sync::mpsc,
};

#[derive(Debug, Clone, Default)]
/// A [`Layer`] which wraps the given service with a [`Socks5ProxyConnector`].
///
/// See [`Socks5ProxyConnector`] for more information.
pub struct Socks5ProxyConnectorLayer {
    required: bool,
    #[cfg(feature = "dns")]
    dns_resolver: Option<BoxDnsResolver>,
}

impl Socks5ProxyConnectorLayer {
    /// Create a new [`Socks5ProxyConnectorLayer`] which creates a [`Socks5ProxyConnector`]
    /// which will only connect via a socks5 proxy in case the [`ProxyAddress`] is available
    /// in the [`Context`].
    ///
    /// [`Context`]: rama_core::Context
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
    /// not available in the [`Context`].
    ///
    /// [`Context`]: rama_core::Context
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
            self.dns_resolver = Some(rama_dns::global_dns_resolver());
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
        pub fn dns_resolver(mut self, resolver: impl DnsResolver) -> Self {
            self.dns_resolver = Some(resolver.boxed());
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
/// is a [`ProxyAddress`] found in the [`Context`].
pub struct Socks5ProxyConnector<S> {
    inner: S,
    required: bool,
    #[cfg(feature = "dns")]
    dns_resolver: Option<BoxDnsResolver>,
}

impl<S: fmt::Debug> fmt::Debug for Socks5ProxyConnector<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Socks5ProxyConnector");
        d.field("inner", &self.inner)
            .field("required", &self.required);
        #[cfg(feature = "dns")]
        d.field("dns_resolver", &self.dns_resolver);
        d.finish()
    }
}

impl<S: Clone> Clone for Socks5ProxyConnector<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            required: self.required,
            #[cfg(feature = "dns")]
            dns_resolver: self.dns_resolver.clone(),
        }
    }
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
            self.dns_resolver = Some(rama_dns::global_dns_resolver());
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
        pub fn dns_resolver(mut self, resolver: impl DnsResolver) -> Self {
            self.dns_resolver = Some(resolver.boxed());
            self
        }
    }
}

#[cfg(feature = "dns")]
impl<S> Socks5ProxyConnector<S> {
    async fn normalize_socks5_proxy_addr(
        &self,
        dns_mode: DnsResolveIpMode,
        addr: ProxyAddress,
    ) -> ProxyAddress {
        use rand::prelude::*;

        if let Some(dns_resolver) = self.dns_resolver.as_ref()
            && addr.protocol == Some(Protocol::SOCKS5)
        {
            let ProxyAddress {
                protocol,
                authority,
                credential,
            } = addr;
            let (host, port) = authority.into_parts();
            let host = match host {
                Host::Name(domain) => match dns_mode {
                    DnsResolveIpMode::SingleIpV4 => {
                        match dns_resolver.ipv4_lookup(domain.clone()).await {
                            Ok(ips) => ips
                                .into_iter()
                                .choose(&mut rand::rng())
                                .map(|addr| Host::Address(IpAddr::V4(addr)))
                                .unwrap_or(Host::Name(domain)),
                            Err(err) => {
                                tracing::debug!(
                                    "failed to lookup ipv4 addresses for domain: {err:?}"
                                );
                                Host::Name(domain)
                            }
                        }
                    }
                    DnsResolveIpMode::SingleIpV6 => {
                        match dns_resolver.ipv6_lookup(domain.clone()).await {
                            Ok(ips) => ips
                                .into_iter()
                                .choose(&mut rand::rng())
                                .map(|addr| Host::Address(IpAddr::V6(addr)))
                                .unwrap_or(Host::Name(domain)),
                            Err(err) => {
                                tracing::debug!(
                                    "failed to lookup ipv6 addresses for domain: {err:?}"
                                );
                                Host::Name(domain)
                            }
                        }
                    }
                    DnsResolveIpMode::Dual | DnsResolveIpMode::DualPreferIpV4 => {
                        use tracing::{Instrument, trace_span};

                        let (tx, mut rx) = mpsc::unbounded_channel();

                        tokio::spawn(
                                {
                                    let tx = tx.clone();
                                    let domain = domain.clone();
                                    let dns_resolver = dns_resolver.clone();
                                    async move {
                                        match dns_resolver.ipv4_lookup(domain).await {
                                            Ok(ips) => {
                                                if let Some(ip) =
                                                    ips.into_iter().choose(&mut rand::rng())
                                                    && let Err(err) = tx.send(IpAddr::V4(ip)) {
                                                        tracing::trace!(
                                                            "failed to send ipv4 lookup result for ip: {ip}; err = {err:?}"
                                                        )
                                                    }
                                            }
                                            Err(err) => tracing::debug!(
                                                "failed to lookup ipv4 addresses for domain: {err:?}"
                                            ),
                                        }
                                    }
                                }
                                .instrument(trace_span!("dns::ipv4_lookup")),
                            );

                        tokio::spawn(
                                {
                                    let domain = domain.clone();
                                    let dns_resolver = dns_resolver.clone();
                                    async move {
                                        match dns_resolver.ipv6_lookup(domain).await {
                                            Ok(ips) => {
                                                if let Some(ip) =
                                                    ips.into_iter().choose(&mut rand::rng())
                                                    && let Err(err) = tx.send(IpAddr::V6(ip)) {
                                                        tracing::trace!(
                                                            "failed to send ipv6 lookup result for ip {ip}: {err:?}"
                                                        )
                                                    }
                                            }
                                            Err(err) => tracing::debug!(
                                                "failed to lookup ipv6 addresses for domain: {err:?}"
                                            ),
                                        }
                                    }
                                }
                                .instrument(trace_span!("dns::ipv6_lookup")),
                            );

                        rx.recv()
                            .await
                            .map(Host::Address)
                            .unwrap_or(Host::Name(domain))
                    }
                },
                Host::Address(ip_addr) => Host::Address(ip_addr),
            };

            let authority = Authority::new(host, port);
            return ProxyAddress {
                protocol,
                authority,
                credential,
            };
        }

        addr
    }
}

impl<S, Request> Service<Request> for Socks5ProxyConnector<S>
where
    S: ConnectorService<Request, Connection: Stream + Unpin, Error: Into<BoxError>>,
    Request: TryRefIntoTransportContext<Error: Into<BoxError> + Send + 'static> + Send + 'static,
{
    type Response = EstablishedClientConnection<S::Connection, Request>;
    type Error = BoxError;

    async fn serve(&self, mut ctx: Context, req: Request) -> Result<Self::Response, Self::Error> {
        let address = ctx.remove::<ProxyAddress>();
        if !address
            .as_ref()
            .and_then(|addr| addr.protocol.as_ref())
            .map(|p| p.is_socks5())
            .unwrap_or(true)
        {
            return Err(OpaqueError::from_display(
                "socks5 proxy connector can only serve socks5 protocol",
            )
            .into_boxed());
        }

        #[cfg(feature = "dns")]
        let address = match address {
            Some(addr) => {
                let addr = self
                    .normalize_socks5_proxy_addr(ctx.get().copied().unwrap_or_default(), addr)
                    .await;
                ctx.insert(addr.clone());
                Some(addr)
            }
            None => None,
        };

        let established_conn =
            self.inner
                .connect(ctx, req)
                .await
                .map_err(|err| match address.as_ref() {
                    Some(address) => OpaqueError::from_std(Socks5ProxyError::Transport(
                        OpaqueError::from_boxed(err.into())
                            .context(format!(
                                "establish connection to proxy {} (protocol: {:?})",
                                address.authority, address.protocol,
                            ))
                            .into_boxed(),
                    )),
                    None => {
                        OpaqueError::from_boxed(err.into()).context("establish connection target")
                    }
                })?;

        // return early in case we did not use a proxy
        let Some(proxy_address) = address else {
            return if self.required {
                Err("socks5 proxy required but none is defined".into())
            } else {
                tracing::trace!(
                    "socks5 proxy connector: no proxy required or set: proceed with direct connection"
                );
                return Ok(established_conn);
            };
        };
        // and do the handshake otherwise...

        let EstablishedClientConnection {
            mut ctx,
            req,
            mut conn,
        } = established_conn;

        let transport_ctx = ctx
            .get_or_try_insert_with_ctx(|ctx| req.try_ref_into_transport_ctx(ctx))
            .map_err(|err| {
                OpaqueError::from_boxed(err.into())
                    .context("socks5 proxy connector: get transport context")
            })?
            .clone();

        tracing::trace!(
            network.peer.address = %proxy_address.authority.host(),
            network.peer.port = %proxy_address.authority.port(),
            server.address = %transport_ctx.authority.host(),
            server.port = %transport_ctx.authority.port(),
            "socks5 proxy connector: connected to proxy",
        );

        let mut client = Socks5Client::new();

        match &proxy_address.credential {
            Some(ProxyCredential::Basic(basic)) => {
                tracing::trace!(
                    network.peer.address = %proxy_address.authority.host(),
                    network.peer.port = %proxy_address.authority.port(),
                    server.address = %transport_ctx.authority.host(),
                    server.port = %transport_ctx.authority.port(),
                    "socks5 proxy connector: continue handshake with authorisation",
                );
                client.set_auth(basic.clone());
            }
            Some(ProxyCredential::Bearer(_)) => {
                return Err(OpaqueError::from_display(
                    "socks5proxy does not support auth with bearer credential",
                )
                .into_boxed());
            }
            None => {
                tracing::trace!(
                    network.peer.address = %proxy_address.authority.host(),
                    network.peer.port = %proxy_address.authority.port(),
                    server.address = %transport_ctx.authority.host(),
                    server.port = %transport_ctx.authority.port(),
                    "socks5 proxy connector: continue handshake without authorisation",
                );
            }
        }

        // .maybe_with_auth(self.auth.clone());
        match client
            .handshake_connect(&mut conn, &transport_ctx.authority)
            .await
        {
            Ok(bind_addr) => {
                tracing::trace!(
                    network.peer.address = %proxy_address.authority.host(),
                    network.peer.port = %proxy_address.authority.port(),
                    server.address = %transport_ctx.authority.host(),
                    server.port = %transport_ctx.authority.port(),
                    %bind_addr,
                    "socks5 proxy connector: handshake complete",
                )
            }
            Err(err) => return Err(Box::new(Socks5ProxyError::Handshake(err))),
        }

        Ok(EstablishedClientConnection { ctx, req, conn })
    }
}
