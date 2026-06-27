use std::io::ErrorKind;

use rama_core::bytes::{Bytes, BytesMut};
use rama_core::error::{BoxError, ErrorExt};
use rama_core::telemetry::tracing;
use rama_net::address::{HostWithPort, SocketAddress};
#[cfg(feature = "dns")]
use rama_net::mode::DnsResolveIpMode;
use rama_udp::UdpSocket;

use super::MaybeDnsResolver;
use crate::proto::udp::UdpHeader;

#[cfg(feature = "dns")]
use rama_core::error::ErrorContext;
use rama_core::extensions::Extensions;
use std::net::IpAddr;

#[derive(Debug)]
pub(super) struct UdpSocketRelay {
    client_address: SocketAddress,
    pinned_client_address: Option<SocketAddress>,
    unspecified_client_address_policy: UnspecifiedClientUdpAddressPolicy,
    tcp_peer_ip: Option<IpAddr>,

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
    dns_resolver: MaybeDnsResolver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum UnspecifiedClientUdpAddressPolicy {
    #[default]
    /// Accept the first UDP packet only when it matches the TCP peer IP, if known,
    /// then pin to that packet's full UDP source address.
    ///
    /// The IP match is canonicalized, so a v4-mapped IPv6 TCP peer matches the
    /// equivalent plain IPv4 UDP source. When the TCP peer IP is unknown (no
    /// [`SocketInfo`] in the extensions) this degrades to [`Self::PinToFirstPacket`].
    ///
    /// [`SocketInfo`]: rama_net::stream::SocketInfo
    PinToTcpPeerIp,
    /// Accept the first UDP packet from any source, then pin to that packet's full
    /// UDP source address.
    PinToFirstPacket,
    /// Accept UDP packets from any source. Replies are sent to the most recent
    /// accepted source address.
    AnySource,
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
            pinned_client_address: None,
            unspecified_client_address_policy: UnspecifiedClientUdpAddressPolicy::default(),
            tcp_peer_ip: None,

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
            dns_resolver: Default::default(),
        }
    }

    pub(super) fn with_unspecified_client_address_policy(
        mut self,
        policy: UnspecifiedClientUdpAddressPolicy,
        tcp_peer_ip: Option<IpAddr>,
    ) -> Self {
        self.unspecified_client_address_policy = policy;
        self.tcp_peer_ip = tcp_peer_ip;
        self
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

                        if !self.accept_north_source(src.into()) {
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
        let Some(client_address) = self.north_send_address() else {
            tracing::trace!(
                network.peer.address = %self.client_address.ip_addr,
                network.peer.port = %self.client_address.port,
                server.address = %server_address.ip_addr,
                server.port = %server_address.port,
                "drop packet north: client UDP address is not known yet",
            );
            return Ok(());
        };

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

            header.write_to_buf(&mut self.north_write_buf)?;
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
            header.write_to_buf(&mut self.north_write_buf)?;
            self.north_write_buf.extend_from_slice(&self.south_read_buf);
        };

        match self
            .north
            .send_to(&self.north_write_buf, client_address.into_std())
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

impl UdpSocketRelay {
    fn accept_north_source(&mut self, src: SocketAddress) -> bool {
        if !self.client_address.ip_addr.is_unspecified() {
            return self.client_address.eq(&src);
        }

        match self.unspecified_client_address_policy {
            UnspecifiedClientUdpAddressPolicy::PinToTcpPeerIp => {
                // Compare canonical forms so a v4-mapped IPv6 TCP peer
                // (`::ffff:a.b.c.d`, e.g. an IPv4 client on a dual-stack TCP
                // listener) matches the plain IPv4 source the UDP socket reports.
                if let Some(tcp_peer_ip) = self.tcp_peer_ip
                    && src.ip_addr.to_canonical() != tcp_peer_ip.to_canonical()
                {
                    return false;
                }
                self.pin_or_match_client_source(src)
            }
            UnspecifiedClientUdpAddressPolicy::PinToFirstPacket => {
                self.pin_or_match_client_source(src)
            }
            UnspecifiedClientUdpAddressPolicy::AnySource => {
                self.pinned_client_address = Some(src);
                true
            }
        }
    }

    fn pin_or_match_client_source(&mut self, src: SocketAddress) -> bool {
        if let Some(address) = self.pinned_client_address {
            address == src
        } else {
            self.pinned_client_address = Some(src);
            true
        }
    }

    fn north_send_address(&self) -> Option<SocketAddress> {
        if self.client_address.ip_addr.is_unspecified() {
            self.pinned_client_address
        } else {
            Some(self.client_address)
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
    #[cfg(feature = "dns")]
    pub(super) fn maybe_with_dns_resolver(
        mut self,
        extensions: &Extensions,
        resolver: MaybeDnsResolver,
    ) -> Self {
        self.dns_resolver = resolver;
        if let Some(mode) = extensions.get_ref().copied() {
            self.dns_resolve_mode = mode;
        }
        self
    }

    #[cfg(not(feature = "dns"))]
    pub(super) fn maybe_with_dns_resolver(
        self,
        extensions: &Extensions,
        resolver: MaybeDnsResolver,
    ) -> Self {
        _ = extensions;
        _ = resolver;
        self
    }

    pub(super) async fn authority_to_socket_address(
        &self,
        authority: HostWithPort,
    ) -> Result<SocketAddress, BoxError> {
        let HostWithPort { host, port } = authority;
        // IP fast path first — `try_as_ip` also bridges pct-encoded
        // dotted-quad inside `Uninterpreted`. Fall through to DNS
        // resolution of a typed `Domain` (bridged from `Uninterpreted`
        // via pct-decode + IDN). Non-promotable inputs (sub-delim,
        // IPvFuture) hit the error path inside `try_into_domain`.
        let ip_addr = match host.try_as_ip() {
            Ok(ip) => ip,
            Err(err) => self.resolve_domain_host(host, err.into_box_error()).await?,
        };
        Ok((ip_addr, port).into())
    }

    #[cfg(feature = "dns")]
    async fn resolve_domain_host(
        &self,
        host: rama_net::address::Host,
        source: BoxError,
    ) -> Result<IpAddr, BoxError> {
        use rama_dns::client::resolver::DnsAddressResolver as _;
        let _ = source;

        let domain = host
            .try_into_domain()
            .context("host is not resolvable as a domain via SOCKS5 udp relay")?;
        let dns_resolver = self
            .dns_resolver
            .clone()
            .context("domain cannot be resolved: no dns resolver defined")?;

        match self.dns_resolve_mode {
            DnsResolveIpMode::SingleIpV4 => Ok(IpAddr::V4(
                dns_resolver
                    .lookup_ipv4_rand(domain.clone())
                    .await
                    .context("no ipv4 addresses found during DNS lookup")?
                    .context("ipv4 dns lookup")?,
            )),
            DnsResolveIpMode::SingleIpV6 => Ok(IpAddr::V6(
                dns_resolver
                    .lookup_ipv6_rand(domain.clone())
                    .await
                    .context("no ipv6 addresses found during DNS lookup")?
                    .context("ipv6 dns lookup")?,
            )),
            DnsResolveIpMode::Dual | DnsResolveIpMode::DualPreferIpV4 => {
                crate::dns::race_resolve_dual(&dns_resolver, domain.clone(), self.dns_resolve_mode)
                    .await
                    .context("receive resolved ip address")
            }
        }
    }

    #[cfg(not(feature = "dns"))]
    async fn resolve_domain_host(
        &self,
        host: rama_net::address::Host,
        source: BoxError,
    ) -> Result<IpAddr, BoxError> {
        let _ = self;
        let _ = host;
        Err(source.context("domain cannot be resolved: rama-socks5 dns feature is disabled"))
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
        expected_header.write_to_buf(&mut expected).unwrap();
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
    // the relay accepts and pins the first valid UDP source instead of dropping
    // everything or accepting every later source.
    #[tokio::test]
    async fn test_recv_north_unspecified_client_addr_pins_first_source() {
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
        header.write_to_buf(&mut packet).unwrap();
        packet.extend_from_slice(b"data");
        sender.send_to(&packet, north_addr).await.unwrap();

        let state = tokio::time::timeout(std::time::Duration::from_millis(500), relay.recv())
            .await
            .expect("timed out")
            .unwrap()
            .expect("first packet must not be dropped when client_address is 0.0.0.0:0");

        assert!(
            matches!(state, UdpRelayState::ReadNorth(_)),
            "RFC 1928 §7: the first packet selects the client UDP source when client_address is 0.0.0.0:0"
        );

        let second_sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        second_sender.send_to(&packet, north_addr).await.unwrap();
        let state = tokio::time::timeout(std::time::Duration::from_millis(500), relay.recv())
            .await
            .expect("timed out")
            .unwrap();

        assert!(
            state.is_none(),
            "packets from a different UDP source must be dropped after the first source is pinned"
        );
    }

    #[tokio::test]
    async fn test_recv_north_unspecified_client_addr_any_source_policy() {
        let client_addr = SocketAddress::default_ipv4(0);

        let north = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let north_addr = north.local_addr().unwrap();
        let south = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut relay = UdpSocketRelay::new(client_addr, north, 4096, south, 4096)
            .with_unspecified_client_address_policy(
                UnspecifiedClientUdpAddressPolicy::AnySource,
                None,
            );

        let target: SocketAddress = SocketAddress::local_ipv4(9999);
        let header = UdpHeader {
            fragment_number: 0,
            destination: target.into(),
        };
        let mut packet = BytesMut::new();
        header.write_to_buf(&mut packet).unwrap();
        packet.extend_from_slice(b"data");

        for _ in 0..2 {
            let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender.send_to(&packet, north_addr).await.unwrap();

            let state = tokio::time::timeout(std::time::Duration::from_millis(500), relay.recv())
                .await
                .expect("timed out")
                .unwrap();

            assert!(
                matches!(state, Some(UdpRelayState::ReadNorth(_))),
                "AnySource policy must preserve the historical accept-any-source behavior"
            );
        }
    }

    #[tokio::test]
    async fn test_unspecified_client_addr_tcp_peer_ip_policy_rejects_other_ip() {
        let client_addr = SocketAddress::default_ipv4(0);
        let north = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let south = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut relay = UdpSocketRelay::new(client_addr, north, 4096, south, 4096)
            .with_unspecified_client_address_policy(
                UnspecifiedClientUdpAddressPolicy::PinToTcpPeerIp,
                Some(std::net::IpAddr::from([127, 0, 0, 2])),
            );

        assert!(!relay.accept_north_source(SocketAddress::local_ipv4(12345)));
    }

    #[tokio::test]
    async fn test_unspecified_client_addr_tcp_peer_ip_policy_accepts_and_pins_matching_ip() {
        let client_addr = SocketAddress::default_ipv4(0);
        let north = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let south = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut relay = UdpSocketRelay::new(client_addr, north, 4096, south, 4096)
            .with_unspecified_client_address_policy(
                UnspecifiedClientUdpAddressPolicy::PinToTcpPeerIp,
                Some(std::net::IpAddr::from([127, 0, 0, 1])),
            );

        // First packet from the matching TCP peer IP is accepted and pins the
        // full (ip, port) source.
        assert!(relay.accept_north_source(SocketAddress::local_ipv4(40000)));
        // A later packet from the same IP but a different port is rejected.
        assert!(!relay.accept_north_source(SocketAddress::local_ipv4(40001)));
        // North-bound replies now target the pinned source.
        assert_eq!(
            relay.north_send_address(),
            Some(SocketAddress::local_ipv4(40000))
        );
    }

    #[tokio::test]
    async fn test_unspecified_client_addr_tcp_peer_ip_policy_canonicalizes_v4_mapped() {
        let client_addr = SocketAddress::default_ipv4(0);
        let north = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let south = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // A v4-mapped IPv6 TCP peer (as a dual-stack listener reports an IPv4
        // client) must match the plain IPv4 UDP source.
        let v4_mapped = std::net::Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped();
        let mut relay = UdpSocketRelay::new(client_addr, north, 4096, south, 4096)
            .with_unspecified_client_address_policy(
                UnspecifiedClientUdpAddressPolicy::PinToTcpPeerIp,
                Some(std::net::IpAddr::V6(v4_mapped)),
            );

        assert!(relay.accept_north_source(SocketAddress::local_ipv4(40000)));
    }

    #[tokio::test]
    async fn test_send_to_north_dropped_when_unspecified_client_not_yet_pinned() {
        let client_addr = SocketAddress::default_ipv4(0);
        let north = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let south = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut relay = UdpSocketRelay::new(client_addr, north, 4096, south, 4096);

        // No north packet has pinned the client yet, so the reply target is unknown.
        assert_eq!(relay.north_send_address(), None);
        // Sending north in that state is a silent no-op (dropped), not an error.
        relay
            .send_to_north(
                Some(Bytes::from_static(b"data")),
                SocketAddress::local_ipv4(9999),
            )
            .await
            .unwrap();
        assert_eq!(relay.north_send_address(), None);
    }
}
