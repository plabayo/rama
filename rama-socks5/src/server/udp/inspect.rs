use std::fmt;

use super::relay::{UdpRelayState, UdpSocketRelay};
use crate::server::Error;
use rama_core::bytes::Bytes;
use rama_core::telemetry::tracing;
use rama_core::{Context, Service, error::BoxError};
use rama_net::address::SocketAddress;
use rama_udp::UdpSocket;

#[cfg(feature = "dns")]
use ::rama_dns::BoxDnsResolver;

#[allow(clippy::too_many_arguments)]
pub(super) trait UdpPacketProxy<State>: Send + Sync + 'static {
    fn proxy_udp_packets(
        &self,
        ctx: Context<State>,
        client_address: SocketAddress,
        north: UdpSocket,
        north_read_buf_size: usize,
        south: UdpSocket,
        south_read_buf_size: usize,
        #[cfg(feature = "dns")] dns_resolver: Option<BoxDnsResolver>,
    ) -> impl Future<Output = Result<Context<State>, Error>> + Send;
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// An UDP Relay which relays the UDP Packets without any inspection.
pub struct DirectUdpRelay;

impl<State: Clone + Send + Sync + 'static> UdpPacketProxy<State> for DirectUdpRelay {
    async fn proxy_udp_packets(
        &self,
        #[cfg_attr(not(feature = "dns"), expect(unused_variables))] ctx: Context<State>,
        client_address: SocketAddress,
        north: UdpSocket,
        north_read_buf_size: usize,
        south: UdpSocket,
        south_read_buf_size: usize,
        #[cfg(feature = "dns")] dns_resolver: Option<BoxDnsResolver>,
    ) -> Result<Context<State>, Error> {
        let relay = UdpSocketRelay::new(
            client_address,
            north,
            north_read_buf_size,
            south,
            south_read_buf_size,
        );

        #[cfg(feature = "dns")]
        let relay = relay.maybe_with_dns_resolver(&ctx, dns_resolver);

        let mut relay = relay;

        loop {
            match relay.recv().await.map_err(Error::service)? {
                Some(UdpRelayState::ReadNorth(server_address)) => {
                    tracing::trace!("relay: north -> south @ {server_address}");
                    relay
                        .send_to_south(None, server_address)
                        .await
                        .map_err(Error::service)?
                }
                Some(UdpRelayState::ReadSouth(server_address)) => {
                    tracing::trace!("relay: south @ {server_address} -> north");
                    relay
                        .send_to_north(None, server_address)
                        .await
                        .map_err(Error::service)?
                }
                None => {
                    tracing::trace!("ignore dropped packet: nothing to relay");
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Direction in which we relay
pub enum RelayDirection {
    /// From client to server
    North,
    /// From server to client
    South,
}

#[derive(Debug, Clone)]
/// Request to Relay, used by an async UDP inspector [`Service`].
pub struct RelayRequest {
    pub direction: RelayDirection,
    pub server_address: SocketAddress,
    pub payload: Bytes,
}

/// Wrapper used for Async udp inspectors.
///
/// Only exposed so you are able to define the type, it is not
/// intended to be created directly by a rama user.
pub struct AsyncUdpInspector<S>(pub(super) S);

impl<S: fmt::Debug> fmt::Debug for AsyncUdpInspector<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AsyncUdpInspector").field(&self.0).finish()
    }
}

impl<S: Clone> Clone for AsyncUdpInspector<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S, State> UdpPacketProxy<State> for AsyncUdpInspector<S>
where
    S: Service<
            State,
            RelayRequest,
            Response = (Context<State>, Option<Bytes>),
            Error: Into<BoxError>,
        >,
    State: Clone + Send + Sync + 'static,
{
    async fn proxy_udp_packets(
        &self,
        mut ctx: Context<State>,
        client_address: SocketAddress,
        north: UdpSocket,
        north_read_buf_size: usize,
        south: UdpSocket,
        south_read_buf_size: usize,
        #[cfg(feature = "dns")] dns_resolver: Option<BoxDnsResolver>,
    ) -> Result<Context<State>, Error> {
        let relay = UdpSocketRelay::new(
            client_address,
            north,
            north_read_buf_size,
            south,
            south_read_buf_size,
        );

        #[cfg(feature = "dns")]
        let relay = relay.maybe_with_dns_resolver(&ctx, dns_resolver);

        let mut relay = relay;

        loop {
            match relay.recv().await.map_err(Error::service)? {
                Some(UdpRelayState::ReadNorth(server_address)) => {
                    tracing::trace!("relay request: north -> south @ {server_address}");

                    let request = RelayRequest {
                        direction: RelayDirection::South,
                        server_address,
                        payload: Bytes::copy_from_slice(relay.north_read_buf_slice()),
                    };

                    let maybe_payload;
                    (ctx, maybe_payload) = self
                        .0
                        .serve(ctx, request)
                        .await
                        .map_err(Into::into)
                        .inspect_err(|err| {
                            tracing::debug!(
                                "relay request: south @ {server_address} -> north: failed: {err:?}"
                            );
                        })
                        .map_err(Error::service)?;

                    match maybe_payload {
                        Some(payload) => relay
                            .send_to_south(Some(payload), server_address)
                            .await
                            .map_err(Error::service)?,
                        None => {
                            tracing::trace!(
                                "block request: north -> south @ {server_address}: inspecter blocked"
                            );
                        }
                    }
                }
                Some(UdpRelayState::ReadSouth(server_address)) => {
                    tracing::trace!("relay request: south @ {server_address} -> north");

                    let request = RelayRequest {
                        direction: RelayDirection::North,
                        server_address,
                        payload: Bytes::copy_from_slice(relay.south_read_buf_slice()),
                    };

                    let maybe_payload;
                    (ctx, maybe_payload) = self
                        .0
                        .serve(ctx, request)
                        .await
                        .map_err(Into::into)
                        .inspect_err(|err| {
                            tracing::debug!(
                                "relay request: north -> south @ {server_address}: failed: {err:?}"
                            );
                        })
                        .map_err(Error::service)?;

                    match maybe_payload {
                        Some(payload) => relay
                            .send_to_south(Some(payload), server_address)
                            .await
                            .map_err(Error::service)?,
                        None => {
                            tracing::trace!(
                                "block request: north -> south @ {server_address}: inspecter blocked"
                            );
                        }
                    }
                }
                None => {
                    tracing::trace!("ignore dropped packet: nothing to inspect or relay");
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Action defined by [`UdpInspector`] for an inspected udp packet.
pub enum UdpInspectAction {
    /// Forward the read payload as-is.
    Forward,
    /// Drop the udp packet.
    Block,
    /// Forward the attached bytes instead of the original read payload.
    Modify(Bytes),
}

/// Inspector of relayed udp packets,
/// handling both north and south traffic.
pub trait UdpInspector<State>: Send + Sync + 'static {
    type Error: Into<BoxError> + Send + 'static;

    /// Inspect a relayed udp packet respond with a [`UdpInspectAction`].
    fn inspect_packet(
        &self,
        ctx: &Context<State>,
        direction: RelayDirection,
        server_address: SocketAddress,
        payload: &[u8],
    ) -> Result<UdpInspectAction, Self::Error>;
}

impl<F, E, State> UdpInspector<State> for F
where
    F: Fn(&Context<State>, RelayDirection, SocketAddress, &[u8]) -> Result<UdpInspectAction, E>
        + Send
        + Sync
        + 'static,
    E: Into<BoxError> + Send + 'static,
{
    type Error = E;

    fn inspect_packet(
        &self,
        ctx: &Context<State>,
        direction: RelayDirection,
        server_address: SocketAddress,
        payload: &[u8],
    ) -> Result<UdpInspectAction, Self::Error> {
        (self)(ctx, direction, server_address, payload)
    }
}

/// Wrapper used for synchronous udp inspectors.
///
/// Only exposed so you are able to define the type, it is not
/// intended to be created directly by a rama user.
pub struct SyncUdpInspector<S>(pub(super) S);

impl<S: fmt::Debug> fmt::Debug for SyncUdpInspector<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SyncUdpInspector").field(&self.0).finish()
    }
}

impl<S: Clone> Clone for SyncUdpInspector<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S, State> UdpPacketProxy<State> for SyncUdpInspector<S>
where
    S: UdpInspector<State>,
    State: Clone + Send + Sync + 'static,
{
    async fn proxy_udp_packets(
        &self,
        ctx: Context<State>,
        client_address: SocketAddress,
        north: UdpSocket,
        north_read_buf_size: usize,
        south: UdpSocket,
        south_read_buf_size: usize,
        #[cfg(feature = "dns")] dns_resolver: Option<BoxDnsResolver>,
    ) -> Result<Context<State>, Error> {
        let relay = UdpSocketRelay::new(
            client_address,
            north,
            north_read_buf_size,
            south,
            south_read_buf_size,
        );

        #[cfg(feature = "dns")]
        let relay = relay.maybe_with_dns_resolver(&ctx, dns_resolver);

        let mut relay = relay;

        loop {
            match relay.recv().await.map_err(Error::service)? {
                Some(UdpRelayState::ReadNorth(server_address)) => {
                    tracing::trace!("relay request: north -> south @ {server_address}");

                    let action = self
                        .0
                        .inspect_packet(
                            &ctx,
                            RelayDirection::South,
                            server_address,
                            relay.north_read_buf_slice(),
                        )
                        .map_err(Into::into)
                        .inspect_err(|err| {
                            tracing::debug!(
                                "relay request: north -> south @ {server_address}: failed: {err:?}"
                            );
                        })
                        .map_err(Error::service)?;

                    match action {
                        UdpInspectAction::Forward => {
                            tracing::trace!(
                                "relay request: north -> south @ {server_address}: forward"
                            );
                            relay
                                .send_to_south(None, server_address)
                                .await
                                .map_err(Error::service)?;
                        }
                        UdpInspectAction::Block => {
                            tracing::trace!(
                                "block request: north -> south @ {server_address}: inspecter blocked"
                            );
                        }
                        UdpInspectAction::Modify(bytes) => {
                            tracing::trace!(
                                "relay request: north -> south @ {server_address}: forward modified bytes (len = {})",
                                bytes.len()
                            );
                            relay
                                .send_to_south(Some(bytes), server_address)
                                .await
                                .map_err(Error::service)?;
                        }
                    }
                }
                Some(UdpRelayState::ReadSouth(server_address)) => {
                    tracing::trace!("relay request: south @ {server_address} -> north");

                    let action = self
                        .0
                        .inspect_packet(
                            &ctx,
                            RelayDirection::North,
                            server_address,
                            relay.south_read_buf_slice(),
                        )
                        .map_err(Into::into)
                        .inspect_err(|err| {
                            tracing::debug!(
                                "relay request: south @ {server_address} -> north: failed: {err:?}"
                            );
                        })
                        .map_err(Error::service)?;

                    match action {
                        UdpInspectAction::Forward => {
                            tracing::trace!(
                                "relay request: south @ {server_address} -> north: forward"
                            );
                            relay
                                .send_to_north(None, server_address)
                                .await
                                .map_err(Error::service)?;
                        }
                        UdpInspectAction::Block => {
                            tracing::trace!(
                                "block request: south @ {server_address} -> north: inspecter blocked"
                            );
                        }
                        UdpInspectAction::Modify(bytes) => {
                            tracing::trace!(
                                "relay request: south @ {server_address} -> north: forward modified bytes (len = {})",
                                bytes.len()
                            );
                            relay
                                .send_to_north(Some(bytes), server_address)
                                .await
                                .map_err(Error::service)?;
                        }
                    }
                }
                None => {
                    tracing::trace!("ignore dropped packet: nothing to inspect or relay");
                }
            }
        }
    }
}
