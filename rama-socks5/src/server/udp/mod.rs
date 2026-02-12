use std::time::Duration;

use rama_core::{
    Service, combinators::Either, error::BoxError, extensions::ExtensionsMut,
    layer::timeout::DefaultTimeout, stream::Stream, telemetry::tracing,
};
use rama_net::{
    address::{Host, HostWithPort, SocketAddress},
    socket::{Interface, SocketService},
};
use rama_udp::{UdpSocket, bind_udp};
use rama_utils::macros::generate_set_and_with;

#[cfg(feature = "dns")]
use ::rama_dns::{BoxDnsResolver, DnsResolver};

use super::Error;
use crate::proto::{ReplyKind, server::Reply};

mod inspect;
use inspect::UdpPacketProxy;
pub use inspect::{
    AsyncUdpInspector, DirectUdpRelay, RelayDirection, RelayRequest, RelayResponse,
    SyncUdpInspector, UdpInspectAction, UdpInspector,
};

mod relay;

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
pub trait Socks5UdpAssociator<S>: Socks5UdpAssociatorSeal<S> {}

impl<S, C> Socks5UdpAssociator<S> for C where C: Socks5UdpAssociatorSeal<S> {}

pub trait Socks5UdpAssociatorSeal<S>: Send + Sync + 'static {
    fn accept_udp_associate(
        &self,
        stream: S,
        destination: HostWithPort,
    ) -> impl Future<Output = Result<(), Error>> + Send + '_
    where
        S: Stream + Unpin;
}

impl<S> Socks5UdpAssociatorSeal<S> for ()
where
    S: Stream + Unpin,
{
    async fn accept_udp_associate(
        &self,

        mut stream: S,
        destination: HostWithPort,
    ) -> Result<(), Error> {
        tracing::debug!(
            "socks5 server w/ destination {destination}: abort: command not supported: UDP Associate",
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

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// [`Default`] binder [`Service`] implementation.
pub struct DefaultUdpBinder;

impl Service<Interface> for DefaultUdpBinder {
    type Output = UdpSocket;
    type Error = BoxError;

    async fn serve(&self, interface: Interface) -> Result<Self::Output, Self::Error> {
        let socket = bind_udp(interface).await?;
        Ok(socket)
    }
}

/// Default binder [`Service`] type.
pub type DefaultUdpRelay = UdpRelay<DefaultTimeout<DefaultUdpBinder>, DirectUdpRelay>;

/// Only "useful" public [`Socks5UdpAssociator`] implementation,
/// which actually is able to accept udp-relay requests and process them.
///
/// The [`Default`] implementation opens a new (udp) socket for accepting 1
/// incoming connection. Once received it will relay incoming packets
/// to the target udp socket and relay received packets from the latter
/// back to the socks5 server cient. Prefixing these upd packets
/// using [`UdpHeader`][crate::proto::udp::UdpHeader].
///
/// You can customise the [`UdpRelay`] fully by creating it using [`UdpRelay::new`]
/// or overwrite any of the default components using [`UdpRelay::with_binder`],
/// [`UdpRelay::with_sync_inspector`] and [`UdpRelay::with_async_inspector`].
#[derive(Debug, Clone)]
pub struct UdpRelay<B, I> {
    binder: B,
    inspector: I,

    #[cfg(feature = "dns")]
    dns_resolver: Option<BoxDnsResolver>,

    bind_north_interface: Interface,
    bind_south_interface: Interface,

    north_buffer_size: usize,
    south_buffer_size: usize,

    relay_timeout: Option<Duration>,
}

impl<B> UdpRelay<B, DirectUdpRelay> {
    /// Create a new [`UdpRelay`].
    pub fn new(binder: B) -> Self {
        Self {
            binder,
            inspector: DirectUdpRelay::default(),
            #[cfg(feature = "dns")]
            dns_resolver: None,
            bind_north_interface: Interface::default_ipv4(0),
            bind_south_interface: Interface::default_ipv4(0),
            north_buffer_size: 2048,
            south_buffer_size: 2048,
            relay_timeout: None,
        }
    }

    /// Overwrite the [`UdpRelay`]'s [`SyncUdpInspector`] [`UdpInspector`]
    /// that can be used to inspect / modify a udp packet to be relayed synchronously.
    pub fn with_sync_inspector<T>(self, inspector: T) -> UdpRelay<B, SyncUdpInspector<T>> {
        UdpRelay {
            binder: self.binder,
            inspector: SyncUdpInspector(inspector),
            #[cfg(feature = "dns")]
            dns_resolver: self.dns_resolver,
            bind_north_interface: self.bind_north_interface,
            bind_south_interface: self.bind_south_interface,
            north_buffer_size: self.north_buffer_size,
            south_buffer_size: self.south_buffer_size,
            relay_timeout: self.relay_timeout,
        }
    }

    /// Overwrite the [`UdpRelay`]'s [`AsyncUdpInspector`] [`Service`]
    /// that can be used to inspect / modify a udp packet to be relayed asynchronously.
    pub fn with_async_inspector<T>(self, inspector: T) -> UdpRelay<B, AsyncUdpInspector<T>> {
        UdpRelay {
            binder: self.binder,
            inspector: AsyncUdpInspector(inspector),
            #[cfg(feature = "dns")]
            dns_resolver: self.dns_resolver,
            bind_north_interface: self.bind_north_interface,
            bind_south_interface: self.bind_south_interface,
            north_buffer_size: self.north_buffer_size,
            south_buffer_size: self.south_buffer_size,
            relay_timeout: self.relay_timeout,
        }
    }
}

impl<B, I> UdpRelay<B, I> {
    /// Overwrite the [`UdpRelay`]'s bind [`SocketService],
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
            north_buffer_size: self.north_buffer_size,
            south_buffer_size: self.south_buffer_size,
            relay_timeout: self.relay_timeout,
        }
    }

    generate_set_and_with! {
        /// Define the (network) [`Interface`] to bind to, for both north and south direction.
        ///
        /// By default it binds the udp sockets at `0.0.0.0:0`.
        pub fn bind_interface(mut self, interface: impl Into<Interface>) -> Self {
            let interface = interface.into();
            self.bind_north_interface = interface.clone();
            self.bind_south_interface = interface;
            self
        }
    }

    generate_set_and_with! {
        /// Define the (network) [`Interface`] to bind to, for the north direction.
        ///
        /// By default it binds the udp sockets at `0.0.0.0:0`.
        pub fn bind_north_interface(mut self, interface: impl Into<Interface>) -> Self {
            self.bind_north_interface = interface.into();
            self
        }
    }

    generate_set_and_with! {
        /// Define the (network) [`Interface`] to bind to, for the south direction.
        ///
        /// By default it binds the udp sockets at `0.0.0.0:0`.
        pub fn bind_south_interface(mut self, interface: impl Into<Interface>) -> Self {
            self.bind_south_interface = interface.into();
            self
        }
    }

    generate_set_and_with! {
        /// Set the size of the buffer used to read south traffic.
        pub fn buffer_size_south(mut self, n: usize) -> Self {
            self.south_buffer_size = n;
            self
        }
    }

    generate_set_and_with! {
        /// Set the size of the buffer used to read north traffic.
        pub fn buffer_size_north(mut self, n: usize) -> Self {
            self.north_buffer_size = n;
            self
        }
    }

    generate_set_and_with! {
        /// Set the size of the buffer used to read both north and south traffic.
        pub fn buffer_size(mut self, n: usize) -> Self {
            self.north_buffer_size = n;
            self.south_buffer_size = n;
            self
        }
    }

    generate_set_and_with! {
        /// Define the relay timeout for this socks5 UDP server.
        pub fn relay_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.relay_timeout = timeout;
            self
        }
    }
}

#[cfg(feature = "dns")]
impl<B, I> UdpRelay<B, I> {
    generate_set_and_with! {
        /// Attach a the [`Default`] [`DnsResolver`] to this [`UdpRelay`].
        ///
        /// It will be used to best-effort resolve the domain name,
        /// in case a domain name is passed to forward to the target server.
        #[cfg_attr(docsrs, doc(cfg(feature = "dns")))]
        pub fn default_dns_resolver(mut self) -> Self {
            self.dns_resolver = None;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Attach a [`DnsResolver`] to this [`UdpRelay`].
        ///
        /// It will be used to best-effort resolve the domain name,
        /// in case a domain name is passed to forward to the target server.
        #[cfg_attr(docsrs, doc(cfg(feature = "dns")))]
        pub fn dns_resolver(mut self, resolver: impl DnsResolver<Error = BoxError>) -> Self {
            self.dns_resolver = Some(resolver.boxed());
            self
        }
    }
}

impl Default for DefaultUdpRelay {
    fn default() -> Self {
        let relay = Self::new(DefaultTimeout::new(
            DefaultUdpBinder::default(),
            Duration::from_secs(30),
        ));
        #[cfg(feature = "dns")]
        {
            relay.with_default_dns_resolver()
        }
        #[cfg(not(feature = "dns"))]
        relay
    }
}

impl<B, I, S> Socks5UdpAssociatorSeal<S> for UdpRelay<B, I>
where
    B: SocketService<Socket = UdpSocket>,
    I: UdpPacketProxy,
    S: Stream + Unpin + ExtensionsMut,
{
    async fn accept_udp_associate(
        &self,
        mut stream: S,
        destination: HostWithPort,
    ) -> Result<(), Error> {
        tracing::trace!(
            "socks5 server w/ destination {destination}: udp associate: try to bind incoming socket to destination {destination}",
        );

        let extensions = stream.extensions().clone();

        let HostWithPort {
            host: dest_host,
            port: dest_port,
        } = destination;

        let dest_addr = match dest_host {
            Host::Name(domain) => {
                tracing::debug!(
                    "udp associate command does not accept domain {domain} as bind address",
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

        let socket_north = match self.binder.bind(self.bind_north_interface.clone()).await {
            Ok(twin) => twin,
            Err(err) => {
                let err = err.into();

                tracing::debug!("udp north socket bind failed: {err:?}",);

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
                tracing::debug!("retrieve local addr of north (udp) socket failed: {err:?}");
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

        let socket_south = match self.binder.bind(self.bind_south_interface.clone()).await {
            Ok(twin) => twin,
            Err(err) => {
                let err = err.into();

                tracing::debug!("udp south socket bind failed: {err:?}",);

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

        let mut empty = tokio::io::empty();
        let mut drop_stream_fut = std::pin::pin!(tokio::io::copy(&mut stream, &mut empty));
        let mut timeout_fut = std::pin::pin!(match self.relay_timeout {
            Some(timeout) => Either::A(tokio::time::sleep(timeout)),
            None => Either::B(std::future::pending::<()>()),
        });

        let udp_relay = self.inspector.proxy_udp_packets(
            extensions,
            client_address,
            socket_north,
            self.north_buffer_size,
            socket_south,
            self.south_buffer_size,
            #[cfg(feature = "dns")]
            self.dns_resolver.clone(),
        );

        tokio::select! {
            _ = &mut drop_stream_fut => {
                tracing::trace!(
                    network.peer.address = %client_address.ip_addr,
                    network.peer.port = %client_address.port,
                    "socks5 server: udp associate: tcp stream dropped from client: drop relay",
                );
            }

            _ = &mut timeout_fut => {
                tracing::debug!(
                    network.peer.address = %client_address.ip_addr,
                    network.peer.port = %client_address.port,
                    "socks5 server: udp associate: timeout reached: drop relay",
                );
                return Err(Error::io(std::io::Error::new(std::io::ErrorKind::TimedOut, "relay timeout reached")));
            }

            Err(err) = udp_relay => {
                tracing::debug!(
                    network.peer.address = %client_address.ip_addr,
                    network.peer.port = %client_address.port,
                    "socks5 server: udp associate: udp relay: exit with an error",
                );
                return Err(err);
            }
        }

        tracing::trace!(
            network.peer.address = %client_address.ip_addr,
            network.peer.port = %client_address.port,
            "socks5 server: udp associate: udp relay: done",);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) use test::MockUdpAssociator;

#[cfg(test)]
mod test;
