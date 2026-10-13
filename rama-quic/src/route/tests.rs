use std::{
    future::pending,
    num::NonZeroUsize,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{Service as _, futures::poll, io::BridgeIo};
use rama_net::{address::SocketAddress, stream::Socket as _};
use rama_quic_proto::{
    capture::{CaptureLimits, KeyProvider},
    peek::PeekError,
};
use rama_udp::{
    DatagramError, DatagramMetadata, DatagramSenderExt as _, DatagramSocket,
    DatagramSocketExt as _, SendDatagram,
    proxy::{DatagramForwardService, EcnPolicy, Peer},
    test_utils::MemoryDatagramSocket,
};
use rama_utils::{hex::decode, octets::kib};
use tokio::time::{Instant, advance, timeout};

use super::*;

#[cfg(feature = "boring")]
fn keys() -> impl KeyProvider {
    crate::tls::BoringTlsProvider
}

#[cfg(not(feature = "boring"))]
fn keys() -> impl KeyProvider {
    crate::tls::RustlsTlsProvider::new(crate::proto::crypto::rustls::configured_provider())
}

fn admission() -> Admission {
    Admission::new(AdmissionLimits {
        active: NonZeroUsize::new(4).unwrap(),
        active_per_source: NonZeroUsize::new(4).unwrap(),
        sources: NonZeroUsize::new(4).unwrap(),
        tuples: NonZeroUsize::new(8).unwrap(),
        starts_per_window: NonZeroUsize::new(8).unwrap(),
        starts_per_source_window: NonZeroUsize::new(8).unwrap(),
        window: Duration::from_secs(10),
        quarantine: Duration::from_secs(1),
    })
    .unwrap()
}

fn router() -> QuicPeekRouter {
    QuicPeekRouter::new(
        admission(),
        RouterConfig {
            capture: CaptureLimits::default(),
            receive_bytes: NonZeroUsize::new(kib(4)).unwrap(),
            inspect_timeout: Duration::from_secs(1),
            policy_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(5),
        },
    )
    .unwrap()
}

fn fixture() -> (MemoryDatagramSocket, MemoryDatagramSocket, RouteContext) {
    let (client, down) = MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(24000),
        SocketAddress::local_ipv4(24001),
        NonZeroUsize::new(8).unwrap(),
    );
    let context = RouteContext {
        key: AssociationKey {
            ingress: down.local_addr().unwrap(),
            peer: client.local_addr().unwrap(),
        },
        original_destination: None,
        egress: SocketAddress::local_ipv4(25001),
    };
    (client, down, context)
}

fn packet(down: &MemoryDatagramSocket, context: RouteContext, bytes: &[u8]) {
    let mut metadata = DatagramMetadata::empty();
    metadata.peer = context.key.peer;
    metadata.local = context.key.ingress;
    down.inject_received(bytes.to_vec(), metadata).unwrap();
}

#[tokio::test(start_paused = true)]
async fn router_forwarding_replays_gro_prefix_once_before_future_datagrams() {
    timeout(Duration::from_secs(20), async {
        timeout(Duration::from_secs(2), async {
            let (mut client, down, context) = fixture();
            let mut metadata = DatagramMetadata::empty();
            metadata.peer = context.key.peer;
            metadata.local = context.key.ingress;
            metadata.segment_size = NonZeroUsize::new(2);
            down.inject_received(b"abcde".to_vec(), metadata).unwrap();
            let router = router();
            let keys = keys();
            let routed = router
                .route(down, context, &keys, |inspection, trusted| async move {
                    assert!(matches!(&*inspection, Inspection::Inconclusive(_)));
                    assert_eq!(trusted.egress, SocketAddress::local_ipv4(25001));
                    Decision::<()>::Forward
                })
                .await
                .unwrap();
            let Routed::Forward { socket, context } = routed else {
                panic!("expected fixed-path forwarding")
            };
            let (up, mut origin) = MemoryDatagramSocket::pair(
                SocketAddress::local_ipv4(25000),
                context.egress,
                NonZeroUsize::new(8).unwrap(),
            );
            let service =
                DatagramForwardService::new(NonZeroUsize::new(kib(4)).unwrap(), EcnPolicy::Discard);
            let mut relay = Box::pin(service.serve(BridgeIo(
                Peer {
                    socket,
                    address: context.key.peer,
                    source_ip: None,
                },
                Peer {
                    socket: up,
                    address: context.egress,
                    source_ip: None,
                },
            )));
            assert!(poll!(relay.as_mut()).is_pending());
            let mut bytes = [0; 32];
            for expected in [b"ab".as_slice(), b"cd", b"e"] {
                let meta = origin.recv(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..meta.len], expected);
            }
            client
                .create_sender()
                .send(SendDatagram::new(context.key.ingress, b"later"))
                .await
                .unwrap();
            assert!(poll!(relay.as_mut()).is_pending());
            let meta = origin.recv(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..meta.len], b"later");
            origin
                .create_sender()
                .send(SendDatagram::new(origin.peer_addr().unwrap(), b"reply"))
                .await
                .unwrap();
            assert!(poll!(relay.as_mut()).is_pending());
            let meta = client.recv(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..meta.len], b"reply");
            drop(relay);
        })
        .await
        .unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn router_cancellation_during_inspection_or_policy_produces_no_output() {
    timeout(Duration::from_secs(20), async {
        for in_policy in [false, true] {
            let (mut client, down, context) = fixture();
            let fragment = decode::<Vec<u8>>(
                include_str!("../profile/fixtures/chrome-153-initial-1.hex")
                    .split_whitespace()
                    .collect::<String>(),
            )
            .unwrap();
            packet(
                &down,
                context,
                if in_policy { b"not quic" } else { &fragment },
            );
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = calls.clone();
            let router = router();
            let keys = keys();
            let mut route = Box::pin(router.route(down, context, &keys, move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                pending::<Decision<()>>()
            }));
            assert!(poll!(route.as_mut()).is_pending());
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(in_policy));
            let mut bytes = [0; kib(4)];
            let mut received = pin!(client.recv(&mut bytes));
            assert!(poll!(received.as_mut()).is_pending());
            drop(route);
            assert!(matches!(received.await, Err(DatagramError::Closed)));
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn router_deadlines_do_not_renew_and_rejection_releases_input() {
    timeout(Duration::from_secs(20), async {
        let (mut client, down, context) = fixture();
        let first_router = router();
        let keys = keys();
        let start = Instant::now();
        let result = first_router
            .route(down, context, &keys, |inspection, _| async move {
                assert!(matches!(
                    &*inspection,
                    Inspection::Inconclusive(PeekError::Deadline)
                ));
                Decision::<()>::Reject
            })
            .await
            .unwrap();
        assert!(matches!(result, Routed::Rejected));
        assert_eq!(Instant::now() - start, Duration::from_secs(1));
        let mut bytes = [0; 1];
        assert!(matches!(
            client.recv(&mut bytes).await,
            Err(DatagramError::Closed)
        ));

        let router = router();
        let (_client, down, context) = fixture();
        packet(&down, context, b"unknown");
        let start = Instant::now();
        router
            .route(down, context, &keys, |_, _| pending::<Decision<()>>())
            .await
            .unwrap_err();
        assert_eq!(Instant::now() - start, Duration::from_secs(2));
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn router_interception_commits_without_generating_packets_and_preserves_prefix() {
    timeout(Duration::from_secs(20), async {
        let (mut client, down, context) = fixture();
        let router = router();
        let keys = keys();
        let packets = [
            include_str!("../profile/fixtures/chrome-153-initial-1.hex"),
            include_str!("../profile/fixtures/chrome-153-initial-2.hex"),
        ]
        .map(|hex| decode::<Vec<u8>>(hex.split_whitespace().collect::<String>()).unwrap());
        for bytes in &packets {
            packet(&down, context, bytes);
        }
        let routed = router
            .route(down, context, &keys, |inspection, _| async move {
                assert!(matches!(&*inspection, Inspection::ClientHello(_)));
                Decision::Intercept("h3")
            })
            .await
            .unwrap();
        let Routed::Intercept {
            mut socket,
            handler,
            ..
        } = routed
        else {
            panic!("expected interception")
        };
        assert_eq!(handler, "h3");
        let mut received = [0; kib(4)];
        assert!(poll!(pin!(client.recv(&mut received))).is_pending());
        for expected in packets {
            let meta = socket.recv(&mut received).await.unwrap();
            assert_eq!(&received[..meta.len], expected);
        }
        assert!(poll!(pin!(socket.recv(&mut received))).is_pending());
        drop(socket);
        assert!(matches!(
            client.recv(&mut received).await,
            Err(DatagramError::Closed)
        ));
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn router_rejects_truncation_and_tuple_changes_before_policy_or_delivery() {
    timeout(Duration::from_secs(20), async {
        for after_decision in [false, true] {
            for change in 0..3 {
                let (_client, down, context) = fixture();
                if after_decision {
                    packet(&down, context, b"first");
                }
                let mut metadata = DatagramMetadata::empty();
                metadata.peer = context.key.peer;
                metadata.local = context.key.ingress;
                match change {
                    0 => metadata.peer.port += 1,
                    1 => metadata.local.port += 1,
                    _ => metadata.truncated = true,
                }
                down.inject_received(b"invalid".to_vec(), metadata).unwrap();
                let router = router();
                let keys = keys();
                let calls = Arc::new(AtomicUsize::new(0));
                let seen = calls.clone();
                let result = router
                    .route(down, context, &keys, move |_, _| async move {
                        seen.fetch_add(1, Ordering::SeqCst);
                        Decision::<()>::Forward
                    })
                    .await;
                if after_decision {
                    let Routed::Forward { mut socket, .. } = result.unwrap() else {
                        panic!("expected forwarding")
                    };
                    let mut bytes = [0; 32];
                    let meta = socket.recv(&mut bytes).await.unwrap();
                    assert_eq!(&bytes[..meta.len], b"first");
                    socket.recv(&mut bytes).await.unwrap_err();
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                } else {
                    result.unwrap_err();
                    assert_eq!(calls.load(Ordering::SeqCst), 0);
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn router_idle_expiry_and_receiver_drop_cancel_pending_senders() {
    timeout(Duration::from_secs(20), async {
        for expire in [false, true] {
            let (mut client, down, context) = fixture();
            packet(&down, context, b"first");
            let router = router();
            let keys = keys();
            let Routed::Forward { mut socket, .. } = router
                .route(down, context, &keys, |_, _| async {
                    Decision::<()>::Forward
                })
                .await
                .unwrap()
            else {
                panic!("expected forwarding")
            };
            let mut sender = socket.create_sender();
            for _ in 0..8 {
                sender
                    .send(SendDatagram::new(context.key.peer, b"full"))
                    .await
                    .unwrap();
            }
            let datagram = SendDatagram::new(context.key.peer, b"pending");
            let mut sending = pin!(sender.send(datagram));
            assert!(poll!(sending.as_mut()).is_pending());
            if expire {
                advance(Duration::from_secs(5)).await;
                let mut bytes = [0; 32];
                socket.recv(&mut bytes).await.unwrap_err();
            }
            drop(socket);
            assert!(matches!(sending.await, Err(DatagramError::Closed)));
            let mut bytes = [0; 32];
            for _ in 0..8 {
                client.recv(&mut bytes).await.unwrap();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn router_send_handles_cannot_change_peer_or_source() {
    timeout(Duration::from_secs(20), async {
        for change_peer in [false, true] {
            let (_client, down, context) = fixture();
            packet(&down, context, b"first");
            let router = router();
            let keys = keys();
            let Routed::Forward { mut socket, .. } = router
                .route(down, context, &keys, |_, _| async {
                    Decision::<()>::Forward
                })
                .await
                .unwrap()
            else {
                panic!("expected forwarding")
            };
            let mut sender = socket.create_sender();
            let mut other = socket.create_sender();
            let mut bytes = [0; 32];
            socket.recv(&mut bytes).await.unwrap();
            let mut reading = pin!(socket.recv(&mut bytes));
            assert!(poll!(reading.as_mut()).is_pending());
            let bad = if change_peer {
                SendDatagram::new(SocketAddress::local_ipv4(24002), b"bad")
            } else {
                SendDatagram::new(context.key.peer, b"bad")
                    .maybe_with_source_ip(Some("192.0.2.1".parse().unwrap()))
            };
            sender.send(bad).await.unwrap_err();
            assert!(matches!(reading.await, Err(DatagramError::Closed)));
            assert!(matches!(
                other
                    .send(SendDatagram::new(context.key.peer, b"later"))
                    .await,
                Err(DatagramError::Closed)
            ));
        }
    })
    .await
    .unwrap();
}
