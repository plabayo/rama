use crate::{Socks5Auth, Socks5Client, client::proxy_error::Socks5ProxyError};
use rama_core::{
    Context, Layer, Service,
    error::{BoxError, ErrorExt, OpaqueError},
};
use rama_net::{
    address::ProxyAddress,
    client::{ConnectorService, EstablishedClientConnection},
    stream::Stream,
    transport::TryRefIntoTransportContext,
};
use rama_utils::macros::{define_inner_service_accessors, generate_field_setters};
use std::fmt;

#[cfg(feature = "dns")]
use ::{
    rama_dns::{BoxDnsResolver, DnsResolver},
    rama_net::{
        Protocol,
        address::{Authority, Host},
        mode::DnsResolveIpMode,
    },
    std::net::IpAddr,
    tokio::sync::mpsc,
};

#[derive(Debug, Clone, Default)]
/// A [`Layer`] which wraps the given service with a [`Socks5ProxyConnector`].
///
/// See [`Socks5ProxyConnector`] for more information.
pub struct Socks5ProxyConnectorLayer {
    required: bool,
    auth: Option<Socks5Auth>,
    #[cfg(feature = "dns")]
    dns_resolver: Option<BoxDnsResolver<OpaqueError>>,
}

impl Socks5ProxyConnectorLayer {
    /// Create a new [`Socks5ProxyConnectorLayer`] which creates a [`Socks5ProxyConnector`]
    /// which will only connect via a socks5 proxy in case the [`ProxyAddress`] is available
    /// in the [`Context`].
    ///
    /// [`Context`]: rama_core::Context
    /// [`ProxyAddress`]: rama_net::address::ProxyAddress
    pub fn optional() -> Self {
        Self {
            required: false,
            auth: None,
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
    pub fn required() -> Self {
        Self {
            required: true,
            auth: None,
            #[cfg(feature = "dns")]
            dns_resolver: None,
        }
    }

    generate_field_setters!(auth, Socks5Auth);
}

#[cfg(feature = "dns")]
impl Socks5ProxyConnectorLayer {
    /// Attach a [`DnsResolver`] to this [`Socks5ProxyConnectorLayer`].
    ///
    /// It will tried to be used (best-effort) to resolve domain addresses
    /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
    ///
    /// In case of an error with resolving the domain address the connector
    /// will anyway use the domain instead of the ip.
    pub fn with_dns_resolver(mut self, resolver: impl DnsResolver<Error = OpaqueError>) -> Self {
        self.dns_resolver = Some(resolver.boxed());
        self
    }

    /// Attach a [`DnsResolver`] to this [`Socks5ProxyConnectorLayer`].
    ///
    /// It will tried to be used (best-effort) to resolve domain addresses
    /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
    ///
    /// In case of an error with resolving the domain address the connector
    /// will anyway use the domain instead of the ip.
    pub fn set_dns_resolver(
        &mut self,
        resolver: impl DnsResolver<Error = OpaqueError>,
    ) -> &mut Self {
        self.dns_resolver = Some(resolver.boxed());
        self
    }
}

impl<S> Layer<S> for Socks5ProxyConnectorLayer {
    type Service = Socks5ProxyConnector<S>;

    #[cfg(feature = "dns")]
    fn layer(&self, inner: S) -> Self::Service {
        let mut connector =
            Socks5ProxyConnector::new(inner, self.required).maybe_with_auth(self.auth.clone());
        if let Some(resolver) = self.dns_resolver.clone() {
            connector.set_dns_resolver(resolver);
        }
        connector
    }

    #[cfg(not(feature = "dns"))]
    fn layer(&self, inner: S) -> Self::Service {
        Socks5ProxyConnector::new(inner, self.required).maybe_with_auth(self.auth.clone())
    }
}

/// A connector which can be used to establish a connection over a SOCKS5 Proxy.
///
/// This behaviour is optional and only triggered in case there
/// is a [`ProxyAddress`] found in the [`Context`].
pub struct Socks5ProxyConnector<S> {
    inner: S,
    required: bool,
    auth: Option<Socks5Auth>,
    #[cfg(feature = "dns")]
    dns_resolver: Option<BoxDnsResolver<OpaqueError>>,
}

impl<S: fmt::Debug> fmt::Debug for Socks5ProxyConnector<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Socks5ProxyConnector");
        d.field("inner", &self.inner)
            .field("required", &self.required)
            .field("auth", &self.auth);
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
            auth: self.auth.clone(),
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
            auth: None,
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

    generate_field_setters!(auth, Socks5Auth);

    define_inner_service_accessors!();
}

#[cfg(feature = "dns")]
impl<S> Socks5ProxyConnector<S> {
    /// Attach a [`DnsResolver`] to this [`Socks5ProxyConnector`].
    ///
    /// It will tried to be used (best-effort) to resolve domain addresses
    /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
    ///
    /// In case of an error with resolving the domain address the connector
    /// will anyway use the domain instead of the ip.
    pub fn with_dns_resolver(mut self, resolver: impl DnsResolver<Error = OpaqueError>) -> Self {
        self.dns_resolver = Some(resolver.boxed());
        self
    }

    /// Attach a [`DnsResolver`] to this [`Socks5ProxyConnector`].
    ///
    /// It will tried to be used (best-effort) to resolve domain addresses
    /// as IP addresses if the `socks5` protocol is used, but not for the `socks5h` protocol.
    ///
    /// In case of an error with resolving the domain address the connector
    /// will anyway use the domain instead of the ip.
    pub fn set_dns_resolver(
        &mut self,
        resolver: impl DnsResolver<Error = OpaqueError>,
    ) -> &mut Self {
        self.dns_resolver = Some(resolver.boxed());
        self
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

        if let Some(dns_resolver) = self.dns_resolver.as_ref() {
            if addr.protocol == Some(Protocol::SOCKS5) {
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
                                        ?err,
                                        "failed to lookup ipv4 addresses for domain"
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
                                        ?err,
                                        "failed to lookup ipv6 addresses for domain"
                                    );
                                    Host::Name(domain)
                                }
                            }
                        }
                        DnsResolveIpMode::Dual | DnsResolveIpMode::DualPreferIpV4 => {
                            let (tx, mut rx) = mpsc::unbounded_channel();

                            tokio::spawn({
                                let tx = tx.clone();
                                let domain = domain.clone();
                                let dns_resolver = dns_resolver.clone();
                                async move {
                                    match dns_resolver.ipv4_lookup(domain).await {
                                        Ok(ips) => {
                                            if let Some(ip) =
                                                ips.into_iter().choose(&mut rand::rng())
                                            {
                                                if let Err(err) = tx.send(IpAddr::V4(ip)) {
                                                    tracing::trace!(
                                                        ?err,
                                                        %ip,
                                                        "failed to send ipv4 lookup result"
                                                    )
                                                }
                                            }
                                        }
                                        Err(err) => tracing::debug!(
                                            ?err,
                                            "failed to lookup ipv4 addresses for domain"
                                        ),
                                    }
                                }
                            });

                            tokio::spawn({
                                let domain = domain.clone();
                                let dns_resolver = dns_resolver.clone();
                                async move {
                                    match dns_resolver.ipv6_lookup(domain).await {
                                        Ok(ips) => {
                                            if let Some(ip) =
                                                ips.into_iter().choose(&mut rand::rng())
                                            {
                                                if let Err(err) = tx.send(IpAddr::V6(ip)) {
                                                    tracing::trace!(
                                                        ?err,
                                                        %ip,
                                                        "failed to send ipv6 lookup result"
                                                    )
                                                }
                                            }
                                        }
                                        Err(err) => tracing::debug!(
                                            ?err,
                                            "failed to lookup ipv6 addresses for domain"
                                        ),
                                    }
                                }
                            });

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
        }

        addr
    }
}

impl<S, State, Request> Service<State, Request> for Socks5ProxyConnector<S>
where
    S: ConnectorService<State, Request, Connection: Stream + Unpin, Error: Into<BoxError>>,
    State: Clone + Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State, Error: Into<BoxError> + Send + Sync + 'static>
        + Send
        + 'static,
{
    type Response = EstablishedClientConnection<S::Connection, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
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

        let transport_ctx = ctx
            .get_or_try_insert_with_ctx(|ctx| req.try_ref_into_transport_ctx(ctx))
            .map_err(|err| {
                OpaqueError::from_boxed(err.into())
                    .context("socks5 proxy connector: get transport context")
            })?
            .clone();

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
        let proxy_address = match address {
            Some(address) => address,
            None => {
                return if self.required {
                    Err("socks5 proxy required but none is defined".into())
                } else {
                    tracing::trace!(
                        "socks5 proxy connector: no proxy required or set: proceed with direct connection"
                    );
                    return Ok(established_conn);
                };
            }
        };
        // and do the handshake otherwise...

        let EstablishedClientConnection { ctx, req, mut conn } = established_conn;

        tracing::trace!(
            %proxy_address,
            authority = %transport_ctx.authority,
            "socks5 proxy connector: connected to proxy",
        );

        let client = Socks5Client::new().maybe_with_auth(self.auth.clone());
        match client
            .handshake_connect(&mut conn, &transport_ctx.authority)
            .await
        {
            Ok(bind_addr) => {
                tracing::trace!(
                    %proxy_address,
                    authority = %transport_ctx.authority,
                    %bind_addr,
                    "socks5 proxy connector: handshake complete",
                )
            }
            Err(err) => return Err(Box::new(Socks5ProxyError::Handshake(err))),
        }

        Ok(EstablishedClientConnection { ctx, req, conn })
    }
}
