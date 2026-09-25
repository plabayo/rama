//! Reserve both address families instead of relying on Apple's dual-stack port allocation.
//!
//! An IPv6 wildcard UDP bind can otherwise succeed on a port already bound by an IPv4 socket;
//! the IPv4 socket then receives the traffic. Separate family sockets prevent this for both
//! ephemeral and explicitly requested ports, and are driven together by `UdpPacketSocket`.

use std::{io, net::SocketAddr};

use rama_net::{
    address::SocketAddress,
    socket::{SocketOptions, core::Socket, opts::Domain},
};

use crate::{DatagramError, UdpPacketSocket, UdpSocketFactory};

/// Bound construction work when the two ephemeral namespaces are heavily occupied. A collision
/// retries only during allocation; exhausted attempts report `AddrInUse`, never a partial bind.
const MAX_BIND_ATTEMPTS: usize = 32;

pub(super) fn bind(
    factory: &UdpSocketFactory,
    mut options: SocketOptions,
    mut ipv6: Socket,
    address: SocketAddress,
) -> Result<UdpPacketSocket, DatagramError> {
    options.only_v6 = Some(true);
    // Keep common options on both halves. IPv6-only controls remain on the IPv6 socket;
    // asking the IPv4 socket to apply them would fail with an unsupported socket option.
    // A newly added IPv6 option fails closed here until explicitly assigned to its family.
    let mut ipv4_options = options.clone();
    ipv4_options.only_v6 = None;
    ipv4_options.only_v6_best_effort = None;
    ipv4_options.multicast_loop_v6 = None;
    ipv4_options.multicast_hops_v6 = None;
    ipv4_options.multicast_interface_v6 = None;
    ipv4_options.unicast_hops_v6 = None;
    ipv4_options.recv_hoplimit_v6 = None;
    ipv4_options.recv_tclass_v6 = None;
    #[cfg(target_os = "macos")]
    {
        ipv4_options.tclass_v6 = None;
    }

    let mut attempts_remaining = MAX_BIND_ATTEMPTS;
    loop {
        ipv6.set_only_v6(true)?;
        ipv6.bind(&SocketAddr::from(address).into())?;
        let port = ipv6
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("bound IPv6 UDP socket has no IP address"))?
            .port();
        let ipv4 = ipv4_options.try_build_socket(Domain::IPv4)?;
        match ipv4.bind(&SocketAddr::from(SocketAddress::default_ipv4(port)).into()) {
            Ok(()) => {
                let ipv6 = factory.prepare_socket(ipv6, &options)?;
                let ipv4 = factory.prepare_socket(ipv4, &ipv4_options)?;
                return Ok(ipv6.with_ipv4(ipv4));
            }
            Err(error)
                if address.port == 0
                    && error.kind() == io::ErrorKind::AddrInUse
                    && attempts_remaining > 1 =>
            {
                // Release the collided port before asking the kernel for another. Neither
                // socket is published until both binds and metadata setup succeed.
                attempts_remaining -= 1;
                drop(ipv6);
                ipv6 = options.try_build_socket(Domain::IPv6)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::IoSliceMut,
        net::{IpAddr, UdpSocket as StdUdpSocket},
        sync::Arc,
        task::{Context, Wake, Waker},
        time::Duration,
    };

    use super::*;
    use crate::{
        DatagramMetadata, DatagramSender as _, DatagramSenderExt as _, DatagramSocket as _,
        DatagramSocketExt as _, EcnCodepoint, SendDatagram, UdpSocketConfig,
    };
    use rama_net::stream::Socket as _;

    fn factory() -> UdpSocketFactory {
        let mut options = SocketOptions::default_udp();
        options.only_v6 = Some(false);
        UdpSocketFactory::new(UdpSocketConfig::default().with_socket_options(options))
    }

    #[tokio::test]
    async fn a_dual_stack_fixed_port_rejects_an_existing_ipv4_binding() {
        for address in [SocketAddress::local_ipv4(0), SocketAddress::default_ipv4(0)] {
            let occupied = StdUdpSocket::bind(SocketAddr::from(address)).unwrap();
            let port = occupied.local_addr().unwrap().port();
            let error = factory()
                .bind(SocketAddress::default_ipv6(port))
                .await
                .unwrap_err();
            assert!(
                matches!(error, DatagramError::Io(error) if error.kind() == io::ErrorKind::AddrInUse)
            );

            // Explicit IPv6-only retains the independent port namespace promised by that option.
            let mut options = SocketOptions::default_udp();
            options.only_v6 = Some(true);
            let socket =
                UdpSocketFactory::new(UdpSocketConfig::default().with_socket_options(options))
                    .bind(SocketAddress::default_ipv6(port))
                    .await
                    .unwrap();
            assert_eq!(socket.local_addr().unwrap().port, port);
        }
    }

    #[tokio::test]
    async fn a_dual_stack_binding_reserves_both_families_until_its_senders_drop() {
        let socket = factory()
            .bind(SocketAddress::default_ipv6(0))
            .await
            .unwrap();
        let port = socket.local_addr().unwrap().port;
        let sender = socket.create_sender();
        drop(socket);
        for address in [
            SocketAddress::local_ipv4(port),
            SocketAddress::default_ipv4(port),
            SocketAddress::local_ipv6(port),
            SocketAddress::default_ipv6(port),
        ] {
            assert_eq!(
                StdUdpSocket::bind(SocketAddr::from(address))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AddrInUse
            );
        }
        drop(sender);
        let ipv4 = StdUdpSocket::bind(SocketAddr::from(SocketAddress::local_ipv4(port))).unwrap();
        let ipv6 = StdUdpSocket::bind(SocketAddr::from(SocketAddress::local_ipv6(port))).unwrap();
        drop((ipv4, ipv6));
    }

    #[tokio::test]
    async fn occupied_ipv4_ports_do_not_steal_ephemeral_dual_stack_traffic() {
        let held: Vec<_> = (0..64)
            .map(|_| StdUdpSocket::bind(SocketAddr::from(SocketAddress::local_ipv4(0))).unwrap())
            .collect();
        for _ in 0..16 {
            let mut socket = factory()
                .bind(SocketAddress::default_ipv6(0))
                .await
                .unwrap();
            let port = socket.local_addr().unwrap().port;
            assert!(
                held.iter()
                    .all(|held| held.local_addr().unwrap().port() != port)
            );
            let mut sender = socket.create_sender();
            assert_eq!(socket.capabilities(), sender.capabilities());
            for address in [SocketAddress::local_ipv4(0), SocketAddress::local_ipv6(0)] {
                let mut peer = UdpPacketSocket::bind(address).await.unwrap();
                let destination = SocketAddress::new(address.ip_addr, port);
                let peer_addr = peer.local_addr().unwrap();
                tokio::time::timeout(Duration::from_secs(2), async {
                    peer.create_sender()
                        .send(SendDatagram::new(destination, b"request"))
                        .await
                        .unwrap();
                    let mut buffer = [0; 16];
                    let metadata = socket.recv(&mut buffer).await.unwrap();
                    assert_eq!(&buffer[..metadata.len], b"request");
                    assert_eq!(metadata.peer, peer_addr);
                    assert_eq!(metadata.local.port, port);
                    if socket.capabilities().receive_local_ip {
                        assert_eq!(metadata.local, destination);
                    }
                    // Mapped IPv4 destinations still select the IPv4 socket and retain the
                    // endpoint's common port, just as canonical IPv4 destinations do.
                    let reply_target = match peer_addr.ip_addr {
                        IpAddr::V4(ip) => {
                            SocketAddress::new(ip.to_ipv6_mapped().into(), peer_addr.port)
                        }
                        IpAddr::V6(_) => peer_addr,
                    };
                    let mut reply = SendDatagram::new(reply_target, b"response");
                    if sender.capabilities().send_source_ip {
                        reply.set_source_ip(metadata.local.ip_addr);
                    }
                    if sender.capabilities().send_ecn {
                        reply.set_ecn(EcnCodepoint::Ect0);
                    }
                    sender.send(reply).await.unwrap();
                    let metadata = peer.recv(&mut buffer).await.unwrap();
                    assert_eq!(&buffer[..metadata.len], b"response");
                    assert_eq!(metadata.peer, destination);
                    if sender.capabilities().send_ecn && peer.capabilities().receive_ecn {
                        assert_eq!(metadata.ecn, Some(EcnCodepoint::Ect0));
                    }
                })
                .await
                .unwrap();
            }
        }
    }

    #[derive(Default)]
    struct NotifyWake(tokio::sync::Notify);

    impl Wake for NotifyWake {
        fn wake(self: Arc<Self>) {
            self.0.notify_one();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_dual_stack_socket_wakes_for_either_family_after_pending_receive() {
        for address in [SocketAddress::local_ipv4(0), SocketAddress::local_ipv6(0)] {
            let mut socket = factory()
                .bind(SocketAddress::default_ipv6(0))
                .await
                .unwrap();
            let peer = UdpPacketSocket::bind(address).await.unwrap();
            let wake = Arc::new(NotifyWake::default());
            let waker = Waker::from(wake.clone());
            let mut buffer = [0; 1];
            let mut metadata = [DatagramMetadata::default()];
            assert!(
                socket
                    .poll_recv(
                        &mut Context::from_waker(&waker),
                        &mut [IoSliceMut::new(&mut buffer)],
                        &mut metadata
                    )
                    .is_pending()
            );
            peer.create_sender()
                .send(SendDatagram::new(
                    SocketAddress::new(address.ip_addr, socket.local_addr().unwrap().port),
                    b"x",
                ))
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), wake.0.notified())
                .await
                .unwrap();
            let received = socket.recv(&mut buffer).await.unwrap();
            assert_eq!(received.len, 1);
            assert_eq!(&buffer, b"x");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_dual_stack_senders_keep_independent_readiness_per_family() {
        let socket = factory()
            .bind(SocketAddress::default_ipv6(0))
            .await
            .unwrap();
        let ipv4 = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let ipv6 = UdpPacketSocket::bind(SocketAddress::local_ipv6(0))
            .await
            .unwrap();
        let mut first = socket.create_sender();
        let mut second = socket.create_sender();
        let first_wake = Arc::new(NotifyWake::default());
        let second_wake = Arc::new(NotifyWake::default());
        assert!(
            first
                .poll_send(
                    &mut Context::from_waker(&Waker::from(first_wake.clone())),
                    &SendDatagram::new(ipv4.local_addr().unwrap(), b"v4")
                )
                .is_pending()
        );
        assert!(
            second
                .poll_send(
                    &mut Context::from_waker(&Waker::from(second_wake.clone())),
                    &SendDatagram::new(ipv6.local_addr().unwrap(), b"v6")
                )
                .is_pending()
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(first_wake.0.notified(), second_wake.0.notified());
            tokio::try_join!(
                first.send(SendDatagram::new(ipv4.local_addr().unwrap(), b"v4")),
                second.send(SendDatagram::new(ipv6.local_addr().unwrap(), b"v6"))
            )
            .unwrap();
        })
        .await
        .unwrap();
    }
}
