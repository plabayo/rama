use std::{
    io,
    io::IoSliceMut,
    net::IpAddr,
    num::NonZeroUsize,
    pin::pin,
    task::{Context, Poll},
    time::Duration,
};

use rama_core::{Service as _, futures::poll, io::BridgeIo};
use rama_net::{address::SocketAddress, stream::Socket};
use tokio::time::timeout;

use super::{DatagramForwardError, DatagramForwardService, EcnPolicy, Peer};
use crate::{
    DatagramCapabilities, DatagramError, DatagramFeature, DatagramMetadata, DatagramSenderExt as _,
    DatagramSocket, DatagramSocketExt as _, EcnCodepoint, SendDatagram,
    test_utils::{MemoryDatagramSender, MemoryDatagramSocket},
};

fn config(bytes: usize) -> DatagramForwardService {
    DatagramForwardService::new(NonZeroUsize::new(bytes).unwrap(), EcnPolicy::Preserve)
}

async fn relay<A: DatagramSocket, B: DatagramSocket>(
    service: DatagramForwardService,
    ingress: Peer<A>,
    egress: Peer<B>,
) -> Result<(), DatagramForwardError> {
    service.serve(BridgeIo(ingress, egress)).await
}

fn peer(socket: MemoryDatagramSocket) -> Peer<MemoryDatagramSocket> {
    let address = socket.peer_addr().unwrap();
    Peer {
        socket,
        address,
        source_ip: None,
    }
}

fn pair(port: u16) -> (MemoryDatagramSocket, MemoryDatagramSocket) {
    MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(port),
        SocketAddress::local_ipv4(port + 1),
        NonZeroUsize::MIN,
    )
}

#[tokio::test(start_paused = true)]
async fn forwarding_preserves_both_directions_empty_packets_and_ecn() {
    timeout(Duration::from_secs(1), async {
        let (mut client, down) = pair(24000);
        let (up, mut origin) = pair(25000);
        let relay = tokio::spawn(relay(config(64), peer(down), peer(up)));
        for reverse in [false, true] {
            let (from, to) = if reverse {
                (&mut origin, &mut client)
            } else {
                (&mut client, &mut origin)
            };
            let mut sender = from.create_sender();
            for (payload, ecn) in [
                (b"".as_slice(), EcnCodepoint::NotEct),
                (b"one", EcnCodepoint::Ect0),
                (b"second packet", EcnCodepoint::Ce),
            ] {
                sender
                    .send(
                        SendDatagram::new(from.peer_addr().unwrap(), payload)
                            .maybe_with_ecn(Some(ecn)),
                    )
                    .await
                    .unwrap();
                let mut bytes = [0; 64];
                let metadata = to.recv(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..metadata.len], payload);
                assert_eq!(metadata.ecn, Some(ecn));
                assert!(metadata.segment_size.is_none());
            }
        }
        relay.abort();
        assert!(relay.await.unwrap_err().is_cancelled());
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn forwarding_splits_buffered_gro_before_later_packets() {
    timeout(Duration::from_secs(1), async {
        let (client, down) = pair(24000);
        let (up, mut origin) = pair(25000);
        let mut metadata = DatagramMetadata::empty();
        metadata.peer = client.local_addr().unwrap();
        metadata.local = down.local_addr().unwrap();
        metadata.ecn = Some(EcnCodepoint::Ect1);
        metadata.segment_size = NonZeroUsize::new(3);
        down.inject_received(b"aaabbbc".to_vec(), metadata).unwrap();
        let relay = tokio::spawn(relay(config(7), peer(down), peer(up)));
        let mut bytes = [0; 16];
        for expected in [b"aaa".as_slice(), b"bbb", b"c"] {
            let metadata = origin.recv(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..metadata.len], expected);
            assert_eq!(metadata.ecn, Some(EcnCodepoint::Ect1));
        }
        client
            .create_sender()
            .send(
                SendDatagram::new(client.peer_addr().unwrap(), b"later")
                    .maybe_with_ecn(Some(EcnCodepoint::Ect0)),
            )
            .await
            .unwrap();
        let metadata = origin.recv(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..metadata.len], b"later");
        relay.abort();
        let _cancelled = relay.await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn forwarding_rejects_truncation_and_peer_changes_before_send() {
    timeout(Duration::from_secs(1), async {
        for (wrong_peer, buffer, flag) in [(false, 7, false), (false, 8, true), (true, 8, false)] {
            let (client, down) = pair(24000);
            let (up, mut origin) = pair(25000);
            let mut metadata = DatagramMetadata::empty();
            metadata.peer = if wrong_peer {
                SocketAddress::local_ipv4(24002)
            } else {
                client.local_addr().unwrap()
            };
            metadata.local = down.local_addr().unwrap();
            metadata.ecn = Some(EcnCodepoint::Ect0);
            metadata.truncated = flag;
            down.inject_received(vec![42; 8], metadata).unwrap();
            let result = relay(config(buffer), peer(down), peer(up)).await;
            if wrong_peer {
                assert!(matches!(
                    result,
                    Err(DatagramForwardError::UnexpectedPeer { .. })
                ));
            } else {
                assert!(matches!(result, Err(DatagramForwardError::Truncated)));
            }
            // Closing the relay may be visible, but never the retained prefix.
            let mut bytes = [0; 16];
            origin.recv(&mut bytes).await.unwrap_err();
        }
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct NoEcn(MemoryDatagramSocket);
impl Socket for NoEcn {
    fn local_addr(&self) -> io::Result<SocketAddress> {
        self.0.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddress> {
        self.0.peer_addr()
    }
}
impl DatagramSocket for NoEcn {
    type Sender = MemoryDatagramSender;
    fn create_sender(&self) -> Self::Sender {
        self.0.create_sender()
    }
    fn capabilities(&self) -> DatagramCapabilities {
        let mut c = self.0.capabilities();
        c.receive_ecn = false;
        c
    }
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>> {
        self.0.poll_recv(cx, buffers, metadata)
    }
}

#[tokio::test(start_paused = true)]
async fn forwarding_requires_metadata_capability_or_explicit_discard() {
    timeout(Duration::from_secs(1), async {
        let (_client, down) = pair(24000);
        let (up, _origin) = pair(25000);
        let address = down.peer_addr().unwrap();
        assert!(matches!(
            relay(
                config(64),
                Peer {
                    socket: NoEcn(down),
                    address,
                    source_ip: None
                },
                peer(up)
            )
            .await,
            Err(DatagramForwardError::Datagram(DatagramError::Unsupported(
                DatagramFeature::ReceiveEcn
            )))
        ));
        let (client, down) = pair(24000);
        let (up, mut origin) = pair(25000);
        let address = down.peer_addr().unwrap();
        let relay = tokio::spawn(relay(
            config(64).with_ecn(EcnPolicy::Discard),
            Peer {
                socket: NoEcn(down),
                address,
                source_ip: None,
            },
            peer(up),
        ));
        client
            .create_sender()
            .send(
                SendDatagram::new(client.peer_addr().unwrap(), b"payload")
                    .maybe_with_ecn(Some(EcnCodepoint::Ce)),
            )
            .await
            .unwrap();
        let mut bytes = [0; 64];
        let metadata = origin.recv(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..metadata.len], b"payload");
        // The memory socket reports the unmarked IP default when send ECN is omitted.
        assert_eq!(metadata.ecn, Some(EcnCodepoint::NotEct));
        relay.abort();
        let _cancelled = relay.await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn forwarding_reports_failure_of_a_backpressured_send() {
    timeout(Duration::from_secs(1), async {
        let (client, down) = pair(24000);
        let (up, origin) = pair(25000);
        // Fill the origin queue, then make the relay hold a pending second send.
        up.create_sender()
            .send(SendDatagram::new(origin.local_addr().unwrap(), b"full"))
            .await
            .unwrap();
        client
            .create_sender()
            .send(
                SendDatagram::new(client.peer_addr().unwrap(), b"pending")
                    .maybe_with_ecn(Some(EcnCodepoint::NotEct)),
            )
            .await
            .unwrap();
        let mut relay = pin!(relay(config(64), peer(down), peer(up)));
        // The input is already queued; one poll reaches the full output queue.
        assert!(poll!(relay.as_mut()).is_pending());
        drop(origin);
        assert!(matches!(
            relay.await,
            Err(DatagramForwardError::Datagram(DatagramError::Closed))
        ));
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn forwarding_cancellation_drops_both_pending_directions() {
    timeout(Duration::from_secs(1), async {
        let (mut client, down) = pair(24000);
        let (up, mut origin) = pair(25000);
        up.create_sender()
            .send(SendDatagram::new(origin.local_addr().unwrap(), b"full"))
            .await
            .unwrap();
        client
            .create_sender()
            .send(
                SendDatagram::new(client.peer_addr().unwrap(), b"pending")
                    .maybe_with_ecn(Some(EcnCodepoint::NotEct)),
            )
            .await
            .unwrap();
        let mut relay = Box::pin(relay(config(64), peer(down), peer(up)));
        assert!(poll!(relay.as_mut()).is_pending());
        drop(relay);
        let mut bytes = [0; 64];
        assert!(matches!(
            client.recv(&mut bytes).await,
            Err(DatagramError::Closed)
        ));
        let metadata = origin.recv(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..metadata.len], b"full");
        assert!(matches!(
            origin.recv(&mut bytes).await,
            Err(DatagramError::Closed)
        ));
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn forwarding_unpolled_service_drops_both_socket_owners() {
    let (mut client, ingress) = pair(24000);
    let (egress, mut origin) = pair(25000);
    let service = config(64);
    let future = service.serve(BridgeIo(peer(ingress), peer(egress)));
    drop(future);

    let mut bytes = [0; 64];
    assert!(matches!(
        client.recv(&mut bytes).await,
        Err(DatagramError::Closed)
    ));
    assert!(matches!(
        origin.recv(&mut bytes).await,
        Err(DatagramError::Closed)
    ));
}

#[tokio::test(start_paused = true)]
async fn forwarding_takes_a_v4_mapped_peer_as_that_peer() {
    timeout(Duration::from_secs(1), async {
        // A v4-mapped peer is the same peer, as everywhere the validator is used.
        for (segment_size, mapped_peer) in [(3, false), (3, true), (0, true)] {
            let (client, down) = pair(24000);
            let (up, mut origin) = pair(25000);
            let address = client.local_addr().unwrap();
            let mut metadata = DatagramMetadata::empty();
            metadata.peer = match (mapped_peer, address.ip_addr) {
                (true, IpAddr::V4(ip)) => {
                    SocketAddress::new(ip.to_ipv6_mapped().into(), address.port)
                }
                _ => address,
            };
            metadata.local = down.local_addr().unwrap();
            metadata.ecn = Some(EcnCodepoint::Ect0);
            metadata.segment_size = NonZeroUsize::new(segment_size);
            down.inject_received(b"aaabbbc".to_vec(), metadata).unwrap();
            let relay = tokio::spawn(relay(config(7), peer(down), peer(up)));
            let expected: &[&[u8]] = if segment_size == 0 {
                &[b"aaabbbc"]
            } else {
                &[b"aaa", b"bbb", b"c"]
            };
            let mut bytes = [0; 16];
            for expected in expected {
                let metadata = origin.recv(&mut bytes).await.unwrap();
                assert_eq!(
                    &bytes[..metadata.len],
                    *expected,
                    "segment size {segment_size}"
                );
            }
            relay.abort();
            let _cancelled = relay.await;
        }
    })
    .await
    .unwrap();
}
