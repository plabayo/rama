use std::io::ErrorKind;

use rama_core::bytes::{Bytes, BytesMut};
use rama_core::error::{BoxError, ErrorExt, OpaqueError};
use rama_core::telemetry::tracing;
use rama_net::address::{Authority, Host, SocketAddress};
use rama_udp::UdpSocket;

use crate::proto::udp::UdpHeader;

#[cfg(feature = "dns")]
use ::{
    rama_core::{Context, error::ErrorContext},
    rama_dns::{BoxDnsResolver, DnsResolver},
    rama_net::mode::DnsResolveIpMode,
    rand::seq::IteratorRandom,
    std::net::IpAddr,
    tokio::sync::mpsc,
};

#[derive(Debug)]
pub(super) struct UdpSocketRelay {
    client_address: SocketAddress,

    north: UdpSocket,
    north_max_size: usize,
    south: UdpSocket,
    south_max_size: usize,

    north_read_buf: BytesMut,
    south_read_buf: BytesMut,

    north_write_buf: BytesMut,

    #[cfg(feature = "dns")]
    dns_resolve_mode: DnsResolveIpMode,
    #[cfg(feature = "dns")]
    dns_resolver: Option<BoxDnsResolver>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum UdpRelayState {
    ReadNorth(SocketAddress),
    ReadSouth(SocketAddress),
}

impl UdpSocketRelay {
    pub(super) fn new(
        client_address: SocketAddress,
        north: UdpSocket,
        north_read_buf_size: usize,
        south: UdpSocket,
        south_read_buf_size: usize,
    ) -> Self {
        Self {
            client_address,

            north,
            north_max_size: south_read_buf_size,
            north_read_buf: {
                let mut b = BytesMut::with_capacity(north_read_buf_size);
                b.resize(north_read_buf_size, 0);
                b
            },
            north_write_buf: BytesMut::new(),

            south,
            south_max_size: north_read_buf_size,
            south_read_buf: {
                let mut b = BytesMut::with_capacity(south_read_buf_size);
                b.resize(south_read_buf_size, 0);
                b
            },

            #[cfg(feature = "dns")]
            dns_resolve_mode: DnsResolveIpMode::default(),
            #[cfg(feature = "dns")]
            dns_resolver: None,
        }
    }

    pub(super) fn north_read_buf_slice(&self) -> &[u8] {
        &self.north_read_buf[..]
    }

    pub(super) fn south_read_buf_slice(&self) -> &[u8] {
        &self.south_read_buf[..]
    }

    pub(super) async fn recv(&mut self) -> Result<Option<UdpRelayState>, BoxError> {
        self.north_read_buf.clear();
        self.north_read_buf.resize(self.north_max_size, 0);

        self.south_read_buf.clear();
        self.south_read_buf.resize(self.south_max_size, 0);

        tokio::select! {
            result = self.north.recv_from(&mut self.north_read_buf[..]) => {
                match result {
                    Ok((len, src)) => {
                        tracing::trace!(
                            %len,
                            %src,
                            "north socket: received packet",
                        );

                        if !self.client_address.eq(&src) {
                            tracing::debug!(
                                %len,
                                %src,
                                client = %self.client_address,
                                "north socket: drop packet non-client packet",
                            );
                            return Ok(None);
                        }

                        let mut buf = &self.north_read_buf[..len];
                        let target_authority = match UdpHeader::read_from(&mut buf).await {
                            Ok(header) => {
                                if header.fragment_number != 0 {
                                    tracing::debug!(
                                        client = %self.client_address,
                                        fragment_number = header.fragment_number,
                                        "received north packet with non-zero fragment number: drop it",
                                    );
                                    return Ok(None);
                                }
                                header.destination
                            }
                            Err(err) => {
                                tracing::debug!(
                                    %err,
                                    client = %self.client_address,
                                    "received invalid north packet: drop it",
                                );
                                return Ok(None);
                            }
                        };

                        let server_address = match self.authority_to_socket_address(target_authority).await {
                            Ok(addr) => addr,
                            Err(err) => {
                                tracing::debug!(
                                    %err,
                                    client = %self.client_address,
                                    "north packet's destination authority failed to (dns) resolve",
                                );
                                return Ok(None);
                            },
                        };

                        // remove header from payload
                        let offset = len - buf.len();
                        self.north_read_buf.copy_within(offset.., 0);
                        self.north_read_buf.truncate(len-offset);

                        Ok(Some(UdpRelayState::ReadNorth(server_address)))
                    }

                    Err(err) if is_fatal_io_error(&err) => {
                        tracing::debug!(?err, "north socket: non-fatal error: retry again");
                        Ok(None)
                    }

                    Err(err) => {
                        Err(err.context("north socket: fatal error").into_boxed())
                    }
                }
            }

            result = self.south.recv_from(&mut self.south_read_buf[..]) => {
                match result {
                    Ok((len, src)) => {
                        tracing::trace!(
                            %len,
                            %src,
                            "south socket: received packet",
                        );
                        self.south_read_buf.truncate(len);
                        Ok(Some(UdpRelayState::ReadSouth(src)))
                    }

                    Err(err) if is_fatal_io_error(&err) => {
                        tracing::debug!(?err, "south socket: non-fatal error: retry again");
                        Ok(None)
                    }

                    Err(err) => {
                        Err(err.context("south socket: fatal error").into_boxed())
                    }
                }
            }
        }
    }

    pub(super) async fn send_to_south(
        &mut self,
        data: Option<Bytes>,
        server_address: SocketAddress,
    ) -> Result<(), BoxError> {
        let result = match data {
            Some(data) => {
                tracing::trace!(
                    len = %data.len(),
                    client = %self.client_address,
                    server = %server_address,
                    "send packet south: data from input",
                );
                if data.len() > self.south_max_size {
                    tracing::trace!(
                        len = %data.len(),
                        max_len = self.south_max_size,
                        client = %self.client_address,
                        server = %server_address,
                        "drop packet south: length is too large for defined limit",
                    );
                    return Ok(());
                }
                self.south.send_to(&data, server_address).await
            }
            None => {
                tracing::trace!(
                    len = %self.north_read_buf.len(),
                    client = %self.client_address,
                    server = %server_address,
                    "send packet south: data from north socket",
                );
                self.south
                    .send_to(&self.north_read_buf, server_address)
                    .await
            }
        };

        match result {
            Ok(len) => {
                tracing::trace!(
                    len = %self.north_read_buf.len(),
                    write_len = len,
                    client = %self.client_address,
                    server = %server_address,
                    "send packet south: complete",
                );
                Ok(())
            }

            Err(err) => match err.downcast::<std::io::Error>() {
                Ok(err) if is_fatal_io_error(&err) => {
                    tracing::debug!(?err, "south socket: fatal I/O write error");
                    Err(err
                        .context("south socket fatal I/O write error")
                        .into_boxed())
                }
                Ok(err) => {
                    tracing::debug!(
                        ?err,
                        "south socket: write error: packet lost but relay continues"
                    );
                    Ok(())
                }
                Err(err) => {
                    tracing::debug!(?err, "south socket: fatal unknown write error");
                    Err(OpaqueError::from_boxed(err)
                        .context("south socket fatal unknown write error")
                        .into_boxed())
                }
            },
        }
    }

    pub(super) async fn send_to_north(
        &mut self,
        data: Option<Bytes>,
        server_address: SocketAddress,
    ) -> Result<(), BoxError> {
        let header = UdpHeader {
            fragment_number: 0,
            destination: server_address.into(),
        };

        self.north_write_buf.truncate(0);

        match data {
            Some(data) => {
                tracing::trace!(
                    len = %data.len(),
                    client = %self.client_address,
                    server = %server_address,
                    "send packet north: data from input",
                );

                if data.len() > self.north_max_size {
                    tracing::trace!(
                        len = %data.len(),
                        max_len = self.north_max_size,
                        client = %self.client_address,
                        server = %server_address,
                        "drop packet north: length is too large for defined limit",
                    );
                    return Ok(());
                }

                header.write_to_buf(&mut self.north_write_buf);
                self.north_write_buf.extend_from_slice(&data);
            }
            None => {
                tracing::trace!(
                    len = %self.north_read_buf.len(),
                    client = %self.client_address,
                    server = %server_address,
                    "send packet north: data from south socket",
                );
                self.north_write_buf
                    .resize(self.south_read_buf.len() + header.serialized_len(), 0);
                header.write_to_buf(&mut self.north_write_buf);
                self.north_write_buf.extend_from_slice(&self.south_read_buf);
            }
        };

        match self
            .north
            .send_to(&self.north_write_buf, self.client_address)
            .await
        {
            Ok(len) => {
                tracing::trace!(
                    len = %self.north_write_buf.len(),
                    write_len = len,
                    client = %self.client_address,
                    server = %server_address,
                    "send packet north: complete",
                );
                Ok(())
            }

            Err(err) => match err.downcast::<std::io::Error>() {
                Ok(err) if is_fatal_io_error(&err) => {
                    tracing::debug!(?err, "north socket: fatal I/O write error");
                    Err(err
                        .context("north socket fatal I/O write error")
                        .into_boxed())
                }
                Ok(err) => {
                    tracing::debug!(
                        ?err,
                        "north socket: write error: packet lost but relay continues"
                    );
                    Ok(())
                }
                Err(err) => {
                    tracing::debug!(?err, "north socket: fatal unknown write error");
                    Err(OpaqueError::from_boxed(err)
                        .context("north socket fatal unknown write error")
                        .into_boxed())
                }
            },
        }
    }
}

fn is_fatal_io_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::Interrupted
            | ErrorKind::ConnectionReset
            | ErrorKind::AddrNotAvailable
            | ErrorKind::PermissionDenied
            | ErrorKind::Other
    )
}

#[cfg(not(feature = "dns"))]
impl UdpSocketRelay {
    pub(super) async fn authority_to_socket_address(
        &self,
        authority: Authority,
    ) -> Result<SocketAddress, BoxError> {
        let (host, port) = authority.into_parts();
        let ip_addr = match host {
            Host::Name(_) => {
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

#[cfg(feature = "dns")]
impl UdpSocketRelay {
    pub(super) fn maybe_with_dns_resolver<State>(
        mut self,
        ctx: &Context<State>,
        resolver: Option<BoxDnsResolver>,
    ) -> Self {
        self.dns_resolver = resolver;
        if let Some(mode) = ctx.get().copied() {
            self.dns_resolve_mode = mode;
        }
        self
    }

    pub(super) async fn authority_to_socket_address(
        &self,
        authority: Authority,
    ) -> Result<SocketAddress, BoxError> {
        let (host, port) = authority.into_parts();
        let ip_addr = match host {
            Host::Name(domain) => {
                let dns_resolver = self
                    .dns_resolver
                    .clone()
                    .context("domain cannot be resolved: no dns resolver defined")?;

                match self.dns_resolve_mode {
                    DnsResolveIpMode::SingleIpV4 => {
                        let ips = dns_resolver
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
                        let ips = dns_resolver
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
                            }
                            .instrument(trace_span!("dns::ipv4_lookup")),
                        );

                        tokio::spawn(
                            {
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
                            }
                            .instrument(trace_span!("dns::ipv6_lookup")),
                        );

                        rx.recv().await.context("receive resolved ip address")?
                    }
                }
            }
            Host::Address(ip_addr) => ip_addr,
        };
        Ok((ip_addr, port).into())
    }
}
