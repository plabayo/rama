use std::{fmt, time::Duration};

use bytes::BytesMut;
use rama_core::{
    Context, Service, combinators::Either, error::BoxError, inspect::RequestInspector,
    layer::timeout::DefaultTimeout,
};
use rama_net::{
    address::{Authority, Host, SocketAddress},
    socket::Interface,
    stream::Stream,
};
use rama_udp::UdpSocket;
use rama_utils::macros::generate_field_setters;

#[cfg(feature = "dns")]
use ::{
    rama_core::error::{ErrorContext, OpaqueError},
    rama_dns::{BoxDnsResolver, DnsResolver},
    rama_net::mode::DnsResolveIpMode,
    rand::seq::IteratorRandom,
    std::net::IpAddr,
    tokio::sync::mpsc,
};

use crate::proto::{ReplyKind, server::Reply, udp::UdpHeader};

use super::Error;

/// Types which can be used as socks5 [`Command::UdpAssociate`] drivers on the server side.
///
/// Typically used as a component part of a [`Socks5Acceptor`].
///
/// The actual underlying trait is sealed and not exposed for usage.
/// No custom associators can be implemented. You can however customise
/// the individual steps as provided and used by [`UdpRelay`].
///
/// [`Socks5Acceptor`]: crate::server::Socks5Acceptor
/// [`Command::UdpAssociate`]: crate::proto::Command::UdpAssociate
pub trait Socks5UdpAssociator<S, State>: Socks5UdpAssociatorSeal<S, State> {}

impl<S, State, C> Socks5UdpAssociator<S, State> for C where C: Socks5UdpAssociatorSeal<S, State> {}

pub trait Socks5UdpAssociatorSeal<S, State>: Send + Sync + 'static {
    fn accept_udp_associate(
        &self,
        ctx: Context<State>,
        stream: S,
        destination: Authority,
    ) -> impl Future<Output = Result<(), Error>> + Send + '_
    where
        S: Stream + Unpin,
        State: Clone + Send + Sync + 'static;
}

impl<S, State> Socks5UdpAssociatorSeal<S, State> for ()
where
    S: Stream + Unpin,
    State: Clone + Send + Sync + 'static,
{
    async fn accept_udp_associate(
        &self,
        _ctx: Context<State>,
        mut stream: S,
        destination: Authority,
    ) -> Result<(), Error> {
        tracing::debug!(
            %destination,
            "socks5 server: abort: command not supported: UDP Associate",
        );

        Reply::error_reply(ReplyKind::CommandNotSupported)
            .write_to(&mut stream)
            .await
            .map_err(|err| {
                Error::io(err)
                    .with_context("write server reply: command not supported (udp associate)")
            })?;
        Err(Error::aborted("command not supported: UDP Associate"))
    }
}

/// Binder to establish a [`UdpSocket`] for the given [`Interface`].
pub trait UdpBinder<S>: Send + Sync + 'static {
    /// Bind to a [`UdpSocket`] for the given [`Interface`] or return an error.
    fn bind(
        &self,
        ctx: Context<S>,
        interface: Interface,
    ) -> impl Future<Output = Result<(UdpSocket, Context<S>), BoxError>> + Send + '_;
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// [`Default`] [`UdpBinder`] implementation.
pub struct DefaultUdpBinder;

impl<S: Clone + Send + Sync + 'static> Service<S, Interface> for DefaultUdpBinder {
    type Response = (UdpSocket, Context<S>);
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<S>,
        interface: Interface,
    ) -> Result<Self::Response, Self::Error> {
        let socket = UdpSocket::bind(interface).await?;
        Ok((socket, ctx))
    }
}

impl<S, State> UdpBinder<State> for S
where
    S: Service<State, Interface, Response = (UdpSocket, Context<State>), Error: Into<BoxError>>,
    State: Clone + Send + Sync + 'static,
{
    async fn bind(
        &self,
        ctx: Context<State>,
        interface: Interface,
    ) -> Result<(UdpSocket, Context<State>), BoxError> {
        self.serve(ctx, interface).await.map_err(Into::into)
    }
}

#[derive(Debug, Clone)]
/// A request to be relayed between client and server in either direction.
pub struct RelayRequest {
    /// Relay direction
    pub direction: RelayDirection,
    /// Udp association header data
    pub header: UdpHeader,
    /// Udp packet to be relayed
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Direction in which we relay
pub enum RelayDirection {
    /// From client to server
    North,
    /// From server to client
    Sotuh,
}

/// Default [`UdpBinder`] type.
pub type DefaultRelay = UdpRelay<DefaultTimeout<DefaultUdpBinder>, ()>;

/// Only "useful" public [`Socks5UdpAssociator`] implementation,
/// which actually is able to accept udp-relay requests and process them.
///
/// The [`Default`] implementation opens a new (udp) socket for accepting 1
/// incoming connection. Once received it will relay incoming packets
/// to the target udp socket and relay received packets from the altter
/// back to the socks5 server cient. Prefixing these upd packets
/// using [`UdpHeader`].
///
/// You can customise the [`UdpRelay`] fully by creating it using [`UdpRelay::new`]
/// or overwrite any of the default components using either or both of [`UdpRelay::with_binder`]
/// and [`Binder::with_inspector`].
pub struct UdpRelay<B, I> {
    binder: B,
    inspector: I,

    #[cfg(feature = "dns")]
    dns_resolver: Option<BoxDnsResolver<OpaqueError>>,

    bind_north_interface: Interface,
    bind_south_interface: Interface,

    relay_timeout: Option<Duration>,
}

impl<B, I> UdpRelay<B, I> {
    /// Create a new [`UdpRelay`].
    ///
    /// In case you only wish to overwrite one of these components
    /// you can also use a [`Default`] [`UdpRelay`] and overwrite the specific component
    /// using [`UdpRelay::with_binder`] or [`UdpRelay::with_inspector`].
    pub fn new(binder: B, inspector: I) -> Self {
        Self {
            binder,
            inspector,
            #[cfg(feature = "dns")]
            dns_resolver: None,
            bind_north_interface: Interface::default_ipv4(0),
            bind_south_interface: Interface::default_ipv4(0),
            relay_timeout: None,
        }
    }
}

impl<B, I> UdpRelay<B, I> {
    /// Overwrite the [`UdpRelay`]'s [`UdpBinder`],
    /// used to open a socket, return the address and
    /// wait for an incoming connection which it will return.
    pub fn with_binder<T>(self, binder: T) -> UdpRelay<T, I> {
        UdpRelay {
            binder,
            inspector: self.inspector,
            #[cfg(feature = "dns")]
            dns_resolver: self.dns_resolver,
            bind_north_interface: self.bind_north_interface,
            bind_south_interface: self.bind_south_interface,
            relay_timeout: self.relay_timeout,
        }
    }

    /// Overwrite the [`Connector`]'s [`Inspector`]
    /// that can be used to inspect / modify a udp packet to be relayed
    ///
    /// Any [`Inspector`] can be used as long as it has the signature:
    ///
    /// ```plain
    /// (Context<()>, RelayRequest) -> ((Context<()>, RelayRequest), Into<BoxError>)
    /// ```
    pub fn with_inspector<T>(self, inspector: T) -> UdpRelay<B, T> {
        UdpRelay {
            binder: self.binder,
            inspector,
            #[cfg(feature = "dns")]
            dns_resolver: self.dns_resolver,
            bind_north_interface: self.bind_north_interface,
            bind_south_interface: self.bind_south_interface,
            relay_timeout: self.relay_timeout,
        }
    }

    /// Define the (network) [`Interface`] to bind to, for both north and south direction.
    ///
    /// Use:
    /// - [`UdpRelay::set_bind_north_interface`]: to only set [`Interface`] for the north direction;
    /// - [`UdpRelay::set_bind_south_interface`]: to only set [`Interface`] for the south direction.
    ///
    /// By default it binds the udp sockets at `0.0.0.0:0`.
    pub fn set_bind_interface(&mut self, interface: Interface) -> &mut Self {
        self.bind_north_interface = interface.clone();
        self.bind_south_interface = interface;
        self
    }

    /// Define the (network) [`Interface`] to bind to, for both north and south direction.
    ///
    /// Use:
    /// - [`UdpRelay::with_bind_north_interface`]: to only set [`Interface`] for the north direction;
    /// - [`UdpRelay::with_bind_south_interface`]: to only set [`Interface`] for the south direction.
    ///
    /// By default it binds the udp sockets at `0.0.0.0:0`.
    pub fn with_bind_interface(mut self, interface: Interface) -> Self {
        self.bind_north_interface = interface.clone();
        self.bind_south_interface = interface;
        self
    }

    /// Define the (network) [`Interface`] to bind to, for the north direction.
    ///
    /// Use:
    /// - [`UdpRelay::set_bind_interface`]: to only set [`Interface`] for both the north and south direction;
    /// - [`UdpRelay::set_bind_south_interface`]: to only set [`Interface`] for the south direction.
    ///
    /// By default it binds the udp sockets at `0.0.0.0:0`.
    pub fn set_bind_north_interface(&mut self, interface: Interface) -> &mut Self {
        self.bind_north_interface = interface;
        self
    }

    /// Define the (network) [`Interface`] to bind to, for the north direction.
    ///
    /// Use:
    /// - [`UdpRelay::with_bind_interface`]: to only set [`Interface`] for both the north and south direction;
    /// - [`UdpRelay::with_bind_south_interface`]: to only set [`Interface`] for the south direction.
    ///
    /// By default it binds the udp sockets at `0.0.0.0:0`.
    pub fn with_bind_north_interface(mut self, interface: Interface) -> Self {
        self.bind_north_interface = interface;
        self
    }

    /// Define the (network) [`Interface`] to bind to, for the south direction.
    ///
    /// Use:
    /// - [`UdpRelay::set_bind_interface`]: to only set [`Interface`] for both the north and south direction;
    /// - [`UdpRelay::set_bind_north_interface`]: to only set [`Interface`] for the north direction.
    ///
    /// By default it binds the udp sockets at `0.0.0.0:0`.
    pub fn set_bind_south_interface(&mut self, interface: Interface) -> &mut Self {
        self.bind_south_interface = interface;
        self
    }

    /// Define the (network) [`Interface`] to bind to, for the south direction.
    ///
    /// Use:
    /// - [`UdpRelay::with_bind_interface`]: to only set [`Interface`] for both the north and south direction;
    /// - [`UdpRelay::with_bind_north_interface`]: to only set [`Interface`] for the north direction.
    ///
    /// By default it binds the udp sockets at `0.0.0.0:0`.
    pub fn with_bind_south_interface(mut self, interface: Interface) -> Self {
        self.bind_south_interface = interface;
        self
    }

    generate_field_setters!(relay_timeout, Duration);
}

#[cfg(feature = "dns")]
impl<B, I> UdpRelay<B, I> {
    /// Attach a [`DnsResolver`] to this [`UdpRelay`].
    ///
    /// It will be used to best-effort resolve the domain name,
    /// in case a domain name is passed to forward to the target server.
    pub fn with_dns_resolver(mut self, resolver: impl DnsResolver<Error = OpaqueError>) -> Self {
        self.dns_resolver = Some(resolver.boxed());
        self
    }

    /// Attach a [`DnsResolver`] to this [`UdpRelay`].
    ///
    /// It will be used to best-effort resolve the domain name,
    /// in case a domain name is passed to forward to the target server.
    pub fn set_dns_resolver(
        &mut self,
        resolver: impl DnsResolver<Error = OpaqueError>,
    ) -> &mut Self {
        self.dns_resolver = Some(resolver.boxed());
        self
    }

    async fn resolve_authority(
        &self,
        authority: Authority,
        dns_mode: DnsResolveIpMode,
    ) -> Result<SocketAddress, BoxError> {
        let (host, port) = authority.into_parts();
        let ip_addr = match host {
            Host::Name(domain) => match dns_mode {
                DnsResolveIpMode::SingleIpV4 => {
                    let ips = self
                        .dns_resolver
                        .ipv4_lookup(domain.clone())
                        .await
                        .map_err(OpaqueError::from_boxed)
                        .context("failed to lookup ipv4 addresses")?;
                    ips.into_iter()
                        .choose(&mut rand::rng())
                        .map(IpAddr::V4)
                        .context("select ipv4 address for resolved domain")?
                }
                DnsResolveIpMode::SingleIpV6 => {
                    let ips = self
                        .dns_resolver
                        .ipv6_lookup(domain.clone())
                        .await
                        .map_err(OpaqueError::from_boxed)
                        .context("failed to lookup ipv6 addresses")?;
                    ips.into_iter()
                        .choose(&mut rand::rng())
                        .map(IpAddr::V6)
                        .context("select ipv6 address for resolved domain")?
                }
                DnsResolveIpMode::Dual | DnsResolveIpMode::DualPreferIpV4 => {
                    let (tx, mut rx) = mpsc::unbounded_channel();

                    tokio::spawn({
                        let tx = tx.clone();
                        let domain = domain.clone();
                        let dns_resolver = self.dns_resolver.clone();
                        async move {
                            match dns_resolver.ipv4_lookup(domain).await {
                                Ok(ips) => {
                                    if let Some(ip) = ips.into_iter().choose(&mut rand::rng()) {
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
                        let dns_resolver = self.dns_resolver.clone();
                        async move {
                            match dns_resolver.ipv6_lookup(domain).await {
                                Ok(ips) => {
                                    if let Some(ip) = ips.into_iter().choose(&mut rand::rng()) {
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

                    rx.recv().await.context("receive resolved ip address")?
                }
            },
            Host::Address(ip_addr) => ip_addr,
        };
        Ok((ip_addr, port).into())
    }
}

#[cfg(not(feature = "dns"))]
impl<B, I> UdpRelay<B, I> {
    async fn resolve_authority(&self, authority: Authority) -> Result<SocketAddress, BoxError> {
        let (host, port) = authority.into_parts();
        let ip_addr = match host {
            Host::Name(domain) => {
                return Err(OpaqueError::from_display(
                    "dns names as target not supported: no dns server defined",
                )
                .into());
            }
            Host::Address(ip_addr) => ip_addr,
        };
        Ok((ip_addr, port).into())
    }
}

impl<B: fmt::Debug, I: fmt::Debug> fmt::Debug for UdpRelay<B, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Binder");
        d.field("binder", &self.binder)
            .field("inspector", &self.inspector);

        #[cfg(feature = "dns")]
        d.field("dns_resolver", &self.dns_resolver);

        d.field("bind_north_interface", &self.bind_north_interface)
            .field("bind_south_interface", &self.bind_south_interface)
            .field("relay_timeout", &self.relay_timeout)
            .finish()
    }
}

impl<B: Clone, I: Clone> Clone for UdpRelay<B, I> {
    fn clone(&self) -> Self {
        Self {
            binder: self.binder.clone(),
            inspector: self.inspector.clone(),
            #[cfg(feature = "dns")]
            dns_resolver: self.dns_resolver.clone(),
            bind_north_interface: self.bind_north_interface.clone(),
            bind_south_interface: self.bind_south_interface.clone(),
            relay_timeout: self.relay_timeout,
        }
    }
}

impl<B, I, S, State> Socks5UdpAssociatorSeal<S, State> for UdpRelay<B, I>
where
    B: UdpBinder<State>,
    I: RequestInspector<State, RelayRequest, StateOut = State, RequestOut = RelayRequest>,
    S: Stream + Unpin,
    State: Clone + Send + Sync + 'static,
{
    async fn accept_udp_associate(
        &self,
        ctx: Context<State>,
        mut stream: S,
        destination: Authority,
    ) -> Result<(), Error> {
        tracing::trace!(
            %destination,
            "socks5 server: udp associate: try to bind incoming socket",
        );

        let (dest_host, dest_port) = destination.into_parts();
        let dest_addr = match dest_host {
            Host::Name(domain) => {
                tracing::debug!(
                    %domain,
                    "udp associate command does not accept domain as bind address",
                );
                let reply_kind = ReplyKind::AddressTypeNotSupported;
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context("write server reply: udp relay failed")
                    })?;
                return Err(Error::aborted("udp relay failed").with_context(reply_kind));
            }
            Host::Address(ip_addr) => ip_addr,
        };
        let client_address = SocketAddress::new(dest_addr, dest_port);

        let (socket_north, ctx) = match self
            .binder
            .bind(ctx, self.bind_north_interface.clone())
            .await
        {
            Ok(twin) => twin,
            Err(err) => {
                tracing::debug!(
                    error=%err,
                    "udp north socket bind failed",
                );
                let reply_kind = ReplyKind::GeneralServerFailure;
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err)
                            .with_context("write server reply: udp north socket bind failed")
                    })?;
                return Err(Error::aborted("udp north socket bind failed")
                    .with_context(reply_kind)
                    .with_source(err));
            }
        };

        let socket_north_address = match socket_north.local_addr() {
            Ok(addr) => addr,
            Err(err) => {
                tracing::debug!(error = %err, "retrieve local addr of north (udp) socket failed");
                let reply_kind = ReplyKind::GeneralServerFailure;
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err)
                            .with_context("write server reply: prepare udp receive socket failed")
                    })?;
                return Err(
                    Error::aborted("prepare udp receive socket failed").with_context(reply_kind)
                );
            }
        };

        let (socket_south, ctx) = match self
            .binder
            .bind(ctx, self.bind_south_interface.clone())
            .await
        {
            Ok(twin) => twin,
            Err(err) => {
                tracing::debug!(
                    error=%err,
                    "udp south socket bind failed",
                );
                let reply_kind = ReplyKind::GeneralServerFailure;
                Reply::error_reply(reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(|err| {
                        Error::io(err)
                            .with_context("write server reply: udp south socket bind failed")
                    })?;
                return Err(Error::aborted("udp south socket bind failed")
                    .with_context(reply_kind)
                    .with_source(err));
            }
        };

        Reply::new(socket_north_address)
            .write_to(&mut stream)
            .await
            .map_err(|err| {
                Error::io(err)
                    .with_context("write server reply: udp associate: north+south sockets ready")
            })?;

        let mut north_buf = [0u8; 4096];
        let mut south_buf = [0u8; 4096];
        let mut north_w_buf = BytesMut::new();

        let mut empty = tokio::io::empty();
        let mut drop_stream_fut = std::pin::pin!(tokio::io::copy(&mut empty, &mut stream));
        let mut timeout_fut = std::pin::pin!(match self.relay_timeout {
            Some(timeout) => Either::A(tokio::time::sleep(timeout)),
            None => Either::B(std::future::pending::<()>()),
        });

        #[cfg(feature = "dns")]
        let dns_mode = ctx.get::<DnsResolveIpMode>().copied().unwrap_or_default();

        loop {
            tokio::select! {
                _ = &mut drop_stream_fut => {
                    tracing::trace!(
                        %client_address,
                        "socks5 server: udp associate: tcp stream dropped: drop relay",
                    );
                    return Ok(());
                }

                _ = &mut timeout_fut => {
                    tracing::debug!(
                        %client_address,
                        "socks5 server: udp associate: timeout reached: drop relay",
                    );
                    return Err(Error::io(std::io::Error::new(std::io::ErrorKind::TimedOut, "relay timeout reached")));
                }

                Ok((len, src)) = socket_north.recv_from(&mut north_buf) => {
                    if src != client_address {
                        tracing::debug!(
                            %src,
                            %client_address,
                            "socks5 server: udp associate: drop unknown traffic",
                        );
                        continue;
                    }

                    let mut buf = &north_buf[..len];
                    let target_authority = match UdpHeader::read_from(&mut buf).await {
                        Ok(header) => {
                            if header.fragment_number != 0 {
                                tracing::debug!(
                                    %src,
                                    %client_address,
                                    fragment_number = header.fragment_number,
                                    "socks5 server: udp associate: received north packet with non-zero fragment number: drop it",
                                );
                                continue;
                            }
                            header.destination
                        },
                        Err(err) => {
                            tracing::debug!(
                                %err,
                                %src,
                                %client_address,
                                "socks5 server: udp associate: received invalid north packet: drop it",
                            );
                            continue;
                        }
                    };

                    #[cfg(feature = "dns")]
                    let target_result = self.resolve_authority(target_authority, dns_mode).await;
                    #[cfg(not(feature = "dns"))]
                    let target_result = self.resolve_authority(target_authority).await;

                    let server_address = match target_result {
                        Ok(addr) => addr,
                        Err(err) => {
                            tracing::debug!(
                                %err,
                                %src,
                                %client_address,
                                "socks5 server: udp associate: failed to resolve target authority: drop it",
                            );
                            continue;
                        }
                    };

                    tracing::debug!(
                        %client_address,
                        %server_address,
                        "socks5 server: udp associate: forward packet from north to south",
                    );

                    // TODO: support request intercept

                    socket_south
                        .send_to(buf, server_address)
                        .await
                        .map_err(|err| Error::service(err).with_context("I/O: forward packet from north to south"))?;
                }

                // Receive from target (response to be wrapped and relayed to client)
                Ok((resp_len, server_address)) = socket_south.recv_from(&mut south_buf) => {
                    let header = UdpHeader {
                        fragment_number: 0,
                        destination: server_address.into(),
                    };

                    // TODO: support request intercept

                    north_w_buf.clear();
                    north_w_buf.reserve(resp_len + header.serialized_len());
                    header.write_to_buf(&mut north_w_buf);
                    north_w_buf.extend_from_slice(&south_buf[..resp_len]);

                    tracing::debug!(
                        %client_address,
                        %server_address,
                        "socks5 server: udp associate: forward packet from south to north",
                    );
                    socket_north
                        .send_to(&north_w_buf[..], client_address)
                        .await
                        .map_err(|err| Error::service(err).with_context("I/O: forward packet from south to north"))?;
                }
            }
        }
    }
}
