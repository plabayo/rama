use std::io::ErrorKind;

use rama_core::bytes::{Bytes, BytesMut};
use rama_core::error::{BoxError, ErrorExt};
use rama_core::telemetry::tracing;
use rama_net::address::{Host, HostWithPort, SocketAddress};
use rama_udp::UdpSocket;

use crate::proto::udp::UdpHeader;

use ::{
    rama_core::{error::ErrorContext, extensions::Extensions},
    rama_dns::client::resolver::{BoxDnsAddressResolver, DnsAddressResolver},
    rama_net::mode::DnsResolveIpMode,
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

    dns_resolve_mode: DnsResolveIpMode,
    dns_resolver: Option<BoxDnsAddressResolver>,
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

            dns_resolve_mode: DnsResolveIpMode::default(),
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
                            "north socket: received packet (len = {len}; src = {src})",
                        );

                        // Per RFC 1928 §7 the client MAY send all-zeros when it does not
                        // know its own address/port yet; in that case we skip source
                        // filtering and accept packets from any sender.
                        if !self.client_address.ip_addr.is_unspecified()
                            && !self.client_address.eq(&src)
                        {
                            tracing::debug!(
                                network.peer.address = %self.client_address.ip_addr,
                                network.peer.port = %self.client_address.port,
                                "north socket: drop packet non-client packet (len = {len}; src = {src})",
                            );
                            return Ok(None);
                        }

                        let mut buf = &self.north_read_buf[..len];
                        let target_authority = match UdpHeader::read_from(&mut buf).await {
                            Ok(header) => {
                                if header.fragment_number != 0 {
                                    tracing::debug!(
                                        network.peer.address = %self.client_address.ip_addr,
                                        network.peer.port = %self.client_address.port,
                                        "received north packet with non-zero fragment number {}: drop it",
                                        header.fragment_number,
                                    );
                                    return Ok(None);
                                }
                                header.destination
                            }
                            Err(err) => {
                                tracing::debug!(
                                    network.peer.address = %self.client_address.ip_addr,
                                    network.peer.port = %self.client_address.port,
                                    "received invalid north packet: drop it: err = {err:?}",
                                );
                                return Ok(None);
                            }
                        };

                        let server_address = match self.authority_to_socket_address(target_authority).await {
                            Ok(addr) => addr,
                            Err(err) => {
                                tracing::debug!(
                                    network.peer.address = %self.client_address.ip_addr,
                                    network.peer.port = %self.client_address.port,
                                    "north packet's destination authority failed to (dns) resolve: {err:?}",
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

                    Err(err) if is_transient_udp_io_error(&err) => {
                        tracing::debug!("north socket: non-fatal error: retry again: {err:?}");
                        Ok(None)
                    }

                    Err(err) => {
                        Err(err.context("north socket: fatal error"))
                    }
                }
            }

            result = self.south.recv_from(&mut self.south_read_buf[..]) => {
                match result {
                    Ok((len, src)) => {
                        tracing::trace!(
                            "south socket: received packet (len = {len}; src = {src})",
                        );
                        self.south_read_buf.truncate(len);
                        Ok(Some(UdpRelayState::ReadSouth(src.into())))
                    }

                    Err(err) if is_transient_udp_io_error(&err) => {
                        tracing::debug!("south socket: non-fatal error: retry again: {err:?}");
                        Ok(None)
                    }

                    Err(err) => {
                        Err(err.context("south socket: fatal error"))
                    }
                }
            }
        }
    }

    #[expect(clippy::needless_pass_by_ref_mut)]
    pub(super) async fn send_to_south(
        &mut self,
        data: Option<Bytes>,
        server_address: SocketAddress,
    ) -> Result<(), BoxError> {
        let result = if let Some(data) = data {
            tracing::trace!(
                network.peer.address = %self.client_address.ip_addr,
                network.peer.port = %self.client_address.port,
                server.address = %server_address.ip_addr,
                server.port = %server_address.port,
                "send packet south: data from input (len = {})",
                data.len()
            );
            if data.len() > self.south_max_size {
                tracing::trace!(
                    network.peer.address = %self.client_address.ip_addr,
                    network.peer.port = %self.client_address.port,
                    server.address = %server_address.ip_addr,
                    server.port = %server_address.port,
                    "drop packet south: length is too large for defined limit (len = {}; max len = {})",
                    data.len(),
                    self.south_max_size,
                );
                return Ok(());
            }
            self.south.send_to(&data, server_address.into_std()).await
        } else {
            tracing::trace!(
                network.peer.address = %self.client_address.ip_addr,
                network.peer.port = %self.client_address.port,
                server.address = %server_address.ip_addr,
                server.port = %server_address.port,
                "send packet south: data from north socket (len = {})",
                self.north_read_buf.len(),
            );
            self.south
                .send_to(&self.north_read_buf, server_address.into_std())
                .await
        };

        match result {
            Ok(len) => {
                tracing::trace!(
                    network.peer.address = %self.client_address.ip_addr,
                    network.peer.port = %self.client_address.port,
                    server.address = %server_address.ip_addr,
                    server.port = %server_address.port,
                    "send packet south: complete (len = {}; write len = {})",
                    self.north_read_buf.len(),
                    len
                );
                Ok(())
            }

            Err(err) => match err.downcast::<std::io::Error>() {
                Ok(err) if is_transient_udp_io_error(&err) => {
                    tracing::debug!(
                        "south socket: write error: packet lost but relay continues: {err:?}"
                    );
                    Ok(())
                }
                Ok(err) => {
                    tracing::debug!(?err, "south socket: fatal I/O write error: {err:?}");
                    Err(err.context("south socket fatal I/O write error"))
                }
                Err(err) => {
                    tracing::debug!("south socket: fatal unknown write error: {err:?}");
                    Err(err.context("south socket fatal unknown write error"))
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

        if let Some(data) = data {
            tracing::trace!(
                network.peer.address = %self.client_address.ip_addr,
                network.peer.port = %self.client_address.port,
                server.address = %server_address.ip_addr,
                server.port = %server_address.port,
                "send packet north: data from input (len = {})",
                data.len(),
            );

            if data.len() > self.north_max_size {
                tracing::trace!(
                    network.peer.address = %self.client_address.ip_addr,
                    network.peer.port = %self.client_address.port,
                    server.address = %server_address.ip_addr,
                    server.port = %server_address.port,
                    "drop packet north: length is too large for defined limit (len = {}; max len = {})",
                    data.len(),
                    self.north_max_size,
                );
                return Ok(());
            }

            header.write_to_buf(&mut self.north_write_buf);
            self.north_write_buf.extend_from_slice(&data);
        } else {
            tracing::trace!(
                network.peer.address = %self.client_address.ip_addr,
                network.peer.port = %self.client_address.port,
                server.address = %server_address.ip_addr,
                server.port = %server_address.port,
                "send packet north: data from south socket (len = {})",
                self.south_read_buf.len(),
            );
            header.write_to_buf(&mut self.north_write_buf);
            self.north_write_buf.extend_from_slice(&self.south_read_buf);
        };

        match self
            .north
            .send_to(&self.north_write_buf, self.client_address.into_std())
            .await
        {
            Ok(len) => {
                tracing::trace!(
                    network.peer.address = %self.client_address.ip_addr,
                    network.peer.port = %self.client_address.port,
                    server.address = %server_address.ip_addr,
                    server.port = %server_address.port,
                    "send packet north: complete (len = {}; write len = {})",
                    self.north_write_buf.len(),
                    len,
                );
                Ok(())
            }

            Err(err) => match err.downcast::<std::io::Error>() {
                Ok(err) if is_transient_udp_io_error(&err) => {
                    tracing::debug!(
                        "north socket: write error: packet lost but relay continues: {err:?}"
                    );
                    Ok(())
                }
                Ok(err) => {
                    tracing::debug!("north socket: fatal I/O write error: {err:?}");
                    Err(err.context("north socket fatal I/O write error"))
                }
                Err(err) => {
                    tracing::debug!("north socket: fatal unknown write error: {err:?}");
                    Err(err.context("north socket fatal unknown write error"))
                }
            },
        }
    }
}

fn is_transient_udp_io_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::Interrupted
            | ErrorKind::ConnectionReset
            | ErrorKind::AddrNotAvailable
            | ErrorKind::PermissionDenied
    )
}

impl UdpSocketRelay {
    pub(super) fn maybe_with_dns_resolver(
        mut self,
        extensions: &Extensions,
        resolver: Option<BoxDnsAddressResolver>,
    ) -> Self {
        self.dns_resolver = resolver;
        if let Some(mode) = extensions.get_ref().copied() {
            self.dns_resolve_mode = mode;
        }
        self
    }

    pub(super) async fn authority_to_socket_address(
        &self,
        authority: HostWithPort,
    ) -> Result<SocketAddress, BoxError> {
        let HostWithPort { host, port } = authority;
        let ip_addr = match host {
            Host::Name(domain) => {
                let dns_resolver = self
                    .dns_resolver
                    .clone()
                    .context("domain cannot be resolved: no dns resolver defined")?;

                match self.dns_resolve_mode {
                    DnsResolveIpMode::SingleIpV4 => IpAddr::V4(
                        dns_resolver
                            .lookup_ipv4_rand(domain.clone())
                            .await
                            .context("no ipv4 addresses found during DNS lookup")?
                            .context("ipv4 dns lookup")?,
                    ),
                    DnsResolveIpMode::SingleIpV6 => IpAddr::V6(
                        dns_resolver
                            .lookup_ipv6_rand(domain.clone())
                            .await
                            .context("no ipv6 addresses found during DNS lookup")?
                            .context("ipv6 dns lookup")?,
                    ),
                    DnsResolveIpMode::Dual | DnsResolveIpMode::DualPreferIpV4 => {
                        use tracing::{Instrument, trace_span};

                        let (tx, mut rx) = mpsc::unbounded_channel();

                        tokio::spawn(
                            {
                                let tx = tx.clone();
                                let domain = domain.clone();
                                let dns_resolver = dns_resolver.clone();
                                async move {
                                    match dns_resolver.lookup_ipv4_rand(domain.clone()).await {
                                        Some(Ok(addr)) => {
                                            if let Err(err) = tx.send(IpAddr::V4(addr)) {
                                                tracing::debug!(
                                                    "failed to send ipv4 lookup result for ip: {addr}; err = {err:?}"
                                                )
                                            }
                                        },
                                        Some(Err(err)) => {
                                            tracing::debug!(
                                                "failed to lookup ipv4 addresses for domain: {err:?}"
                                            );
                                        }
                                        None => {
                                            tracing::debug!(
                                                "failed to lookup ipv4 addresses for domain: no addresses found"
                                            );
                                        }
                                    }
                                }
                            }
                            .instrument(trace_span!("dns::ipv4_lookup")),
                        );

                        tokio::spawn(
                            {
                                async move {
                                    match dns_resolver.lookup_ipv6_rand(domain.clone()).await {
                                        Some(Ok(addr)) => {
                                            if let Err(err) = tx.send(IpAddr::V6(addr)) {
                                                tracing::debug!(
                                                    "failed to send ipv6 lookup result for ip: {addr}; err = {err:?}"
                                                )
                                            }
                                        },
                                        Some(Err(err)) => {
                                            tracing::debug!(
                                                "failed to lookup ipv6 addresses for domain: {err:?}"
                                            );
                                        }
                                        None => {
                                            tracing::debug!(
                                                "failed to lookup ipv6 addresses for domain: no addresses found"
                                            );
                                        }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Regression for Bug 2: send_to_north(None) was calling BytesMut::resize() after
    // truncate(0), which filled the buffer with N zeros before appending header+data,
    // producing [zeros][header][data] instead of the correct [header][data].
    #[tokio::test]
    async fn test_send_to_north_none_produces_header_then_data_no_leading_zeros() {
        // client_socket receives north-bound packets
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr: std::net::SocketAddr = client.local_addr().unwrap();
        let client_socket_addr: SocketAddress = client_addr.into();

        let north = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let south = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let south_addr = south.local_addr().unwrap();

        // server sends raw payload to south socket (simulates south data)
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_socket_addr: SocketAddress = server_addr.into();

        let payload = b"regression bug2 payload";
        server.send_to(payload, south_addr).await.unwrap();

        let mut relay = UdpSocketRelay::new(client_socket_addr, north, 4096, south, 4096);

        // recv() reads south packet and stores raw payload in south_read_buf
        let state = relay.recv().await.unwrap().unwrap();
        assert!(
            matches!(state, UdpRelayState::ReadSouth(addr) if addr == server_socket_addr),
            "expected ReadSouth from server address"
        );

        // send_to_north(None) should relay [socks5_header][payload] to client, no leading zeros
        relay.send_to_north(None, server_socket_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client.recv_from(&mut buf),
        )
        .await
        .expect("timed out waiting for north packet")
        .unwrap();
        let received = &buf[..n];

        let expected_header = UdpHeader {
            fragment_number: 0,
            destination: server_socket_addr.into(),
        };
        let mut expected = BytesMut::new();
        expected_header.write_to_buf(&mut expected);
        expected.extend_from_slice(payload);

        assert_eq!(
            received,
            &expected[..],
            "send_to_north(None) must produce exactly [header][data]; \
             got {} bytes, expected {} bytes",
            received.len(),
            expected.len(),
        );
    }

    // Regression for Bug 3: when the client sends 0.0.0.0:0 in the UDP ASSOCIATE
    // request (RFC 1928 §7 allows this when the client doesn't know its address),
    // the relay was dropping ALL north packets because no source ever matches 0.0.0.0.
    #[tokio::test]
    async fn test_recv_north_unspecified_client_addr_accepts_any_source() {
        // client_address = 0.0.0.0:0 — the RFC 1928 §7 all-zeros sentinel
        let client_addr = SocketAddress::default_ipv4(0);

        let north = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let north_addr = north.local_addr().unwrap();
        let south = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut relay = UdpSocketRelay::new(client_addr, north, 4096, south, 4096);

        // Any sender (127.0.0.1:OS-assigned) sends a valid SOCKS5 UDP packet to north
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target: SocketAddress = SocketAddress::local_ipv4(9999);
        let header = UdpHeader {
            fragment_number: 0,
            destination: target.into(),
        };
        let mut packet = BytesMut::new();
        header.write_to_buf(&mut packet);
        packet.extend_from_slice(b"data");
        sender.send_to(&packet, north_addr).await.unwrap();

        let state = tokio::time::timeout(std::time::Duration::from_millis(500), relay.recv())
            .await
            .expect("timed out")
            .unwrap()
            .expect("packet must not be dropped when client_address is 0.0.0.0:0");

        assert!(
            matches!(state, UdpRelayState::ReadNorth(_)),
            "RFC 1928 §7: packets from any source must be accepted when client_address is 0.0.0.0:0"
        );
    }
}
