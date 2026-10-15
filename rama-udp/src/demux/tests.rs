use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
};

use rama_core::{error::BoxErrorExt as _, graceful::Shutdown, service::service_fn};
use tokio::{
    sync::{mpsc::UnboundedReceiver, oneshot},
    time::timeout,
};

use super::*;
use rama_net::{address::HostWithPort, client::ConnectorTarget};
use rama_utils::octets::kib;

use crate::{
    DatagramSenderExt as _, UdpPacketSender, UdpPacketSocket,
    proxy::{DatagramForwardService, DatagramToProxyBridge, EcnPolicy},
    test_utils::MemoryDatagramSocket,
};

const LIMIT: Duration = Duration::from_secs(20);

fn config() -> DemuxConfig {
    DemuxConfig {
        associations: NonZeroUsize::new(4).unwrap(),
        queue: NonZeroUsize::new(4).unwrap(),
        idle_timeout: Duration::from_secs(30),
        receive_bytes: NonZeroUsize::new(2048).unwrap(),
        queued_bytes: NonZeroUsize::new(kib(64)).unwrap(),
    }
}

/// Client ⇄ listener.
fn listener() -> (MemoryDatagramSocket, MemoryDatagramSocket) {
    MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(5000),
        SocketAddress::local_ipv4(443),
        NonZeroUsize::new(64).unwrap(),
    )
}

fn peer(last: u8) -> SocketAddress {
    SocketAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), 4000)
}

fn inject(listener: &MemoryDatagramSocket, from: SocketAddress, payload: &[u8]) {
    let mut metadata = DatagramMetadata::empty();
    metadata.peer = from;
    metadata.local = SocketAddress::local_ipv4(443);
    listener
        .inject_received(payload.to_vec(), metadata)
        .unwrap();
}

type Sockets = UnboundedReceiver<DemuxedSocket<crate::test_utils::MemoryDatagramSender>>;

/// Serve `listener`, handing every association to the test.
fn serve(listener: MemoryDatagramSocket, config: DemuxConfig) -> (Sockets, DemuxStatsHandle) {
    serve_demux(DatagramDemux::new(listener, config))
}

/// Serve `demux`, handing every association to the test.
fn serve_demux(demux: DatagramDemux<MemoryDatagramSocket>) -> (Sockets, DemuxStatsHandle) {
    let stats = demux.stats();
    let (sockets, received) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(demux.serve(
        Executor::new(),
        service_fn(move |socket| {
            let sockets = sockets.clone();
            async move {
                sockets.send(socket).unwrap();
                Ok::<_, BoxError>(())
            }
        }),
    ));
    (received, stats)
}

async fn next(socket: &mut DemuxedSocket<crate::test_utils::MemoryDatagramSender>) -> Vec<u8> {
    let mut buffer = [0; 2048];
    let metadata = socket.recv(&mut buffer).await.unwrap();
    buffer[..metadata.len].to_vec()
}

#[tokio::test]
async fn each_peer_gets_its_own_association_in_order() {
    timeout(LIMIT, async {
        let (_client, listener) = listener();
        for (from, payload) in [(1, b"a1"), (2, b"b1"), (1, b"a2"), (2, b"b2")] {
            inject(&listener, peer(from), payload);
        }
        let (mut sockets, _stats) = serve(listener, config());
        let mut first = sockets.recv().await.unwrap();
        let mut second = sockets.recv().await.unwrap();
        assert_eq!(first.peer_addr().unwrap(), peer(1));
        assert_eq!(first.local_addr().unwrap(), SocketAddress::local_ipv4(443));
        assert_eq!(
            (next(&mut first).await, next(&mut first).await),
            (b"a1".to_vec(), b"a2".to_vec())
        );
        assert_eq!(second.peer_addr().unwrap(), peer(2));
        assert_eq!(
            (next(&mut second).await, next(&mut second).await),
            (b"b1".to_vec(), b"b2".to_vec())
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn queues_and_association_count_are_bounded_and_counted() {
    timeout(LIMIT, async {
        let (_client, listener) = listener();
        let config = DemuxConfig {
            associations: NonZeroUsize::MIN,
            queue: NonZeroUsize::new(2).unwrap(),
            ..config()
        };
        for payload in [b"1", b"2", b"3"] {
            inject(&listener, peer(1), payload);
        }
        inject(&listener, peer(2), b"other");
        let (mut sockets, stats) = serve(listener, config);
        let mut first = sockets.recv().await.unwrap();
        // The queue held two; the third was dropped, as was the second peer's datagram.
        assert_eq!(next(&mut first).await, b"1");
        assert_eq!(next(&mut first).await, b"2");
        let stats = stats.get();
        assert_eq!(stats.dropped_queue_full, 1);
        assert_eq!(stats.dropped_association_limit, 1);
        sockets.try_recv().unwrap_err();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_released_association_lets_its_peer_open_a_new_one() {
    timeout(LIMIT, async {
        let (client, listener) = listener();
        let config = DemuxConfig {
            associations: NonZeroUsize::MIN,
            ..config()
        };
        let mut sender = client.create_sender();
        let target = SocketAddress::local_ipv4(443);
        sender
            .send(SendDatagram::new(target, b"first"))
            .await
            .unwrap();
        let (mut sockets, _stats) = serve(listener, config);
        let mut first = sockets.recv().await.unwrap();
        assert_eq!(next(&mut first).await, b"first");
        drop(first);
        sender
            .send(SendDatagram::new(target, b"again"))
            .await
            .unwrap();
        let mut second = sockets.recv().await.unwrap();
        assert_eq!(next(&mut second).await, b"again");
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_idle_association_closes_and_releases_its_peer() {
    timeout(LIMIT, async {
        let (client, listener) = listener();
        let mut sender = client.create_sender();
        let target = SocketAddress::local_ipv4(443);
        sender
            .send(SendDatagram::new(target, b"first"))
            .await
            .unwrap();
        let config = DemuxConfig {
            idle_timeout: Duration::from_secs(5),
            ..config()
        };
        let (mut sockets, _stats) = serve(listener, config);
        let mut first = sockets.recv().await.unwrap();
        assert_eq!(next(&mut first).await, b"first");
        let mut buffer = [0; 64];
        // Nothing arrives within the idle timeout.
        assert!(matches!(
            first.recv(&mut buffer).await,
            Err(DatagramError::Closed)
        ));
        sender
            .send(SendDatagram::new(target, b"later"))
            .await
            .unwrap();
        let mut second = sockets.recv().await.unwrap();
        assert_eq!(next(&mut second).await, b"later");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn replies_go_to_the_associations_peer_only() {
    timeout(LIMIT, async {
        let (mut client, listener) = listener();
        let client_address = client.local_addr().unwrap();
        client
            .create_sender()
            .send(SendDatagram::new(SocketAddress::local_ipv4(443), b"hello"))
            .await
            .unwrap();
        let (mut sockets, _stats) = serve(listener, config());
        let association = sockets.recv().await.unwrap();
        let mut reply = association.create_sender();
        assert!(matches!(
            reply.send(SendDatagram::new(peer(9), b"elsewhere")).await,
            Err(DatagramError::ForeignDestination(_))
        ));
        reply
            .send(SendDatagram::new(client_address, b"reply"))
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let metadata = client.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..metadata.len], b"reply");
        assert_eq!(metadata.peer, SocketAddress::local_ipv4(443));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn datagrams_that_cannot_be_answered_or_are_invalid_are_dropped_and_counted() {
    timeout(LIMIT, async {
        let (_client, listener) = listener();
        // Redirected here from another destination: a reply from this socket would come from
        // the wrong address.
        let mut redirected = DatagramMetadata::empty();
        redirected.peer = peer(1);
        redirected.local = SocketAddress::local_ipv4(443);
        redirected.original_destination = Some(SocketAddress::local_ipv4(8443));
        listener.inject_received(b"x".to_vec(), redirected).unwrap();
        let mut cut = DatagramMetadata::empty();
        cut.peer = peer(2);
        cut.local = SocketAddress::local_ipv4(443);
        cut.truncated = true;
        cut.original_len = 2;
        listener.inject_received(b"x".to_vec(), cut).unwrap();
        inject(&listener, peer(3), b"fine");
        let (mut sockets, stats) = serve(listener, config());
        let mut association = sockets.recv().await.unwrap();
        assert_eq!(association.peer_addr().unwrap(), peer(3));
        assert_eq!(next(&mut association).await, b"fine");
        let stats = stats.get();
        assert_eq!((stats.dropped_reply_source, stats.dropped_invalid), (1, 1));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn graceful_shutdown_stops_serving_and_ends_its_associations() {
    timeout(LIMIT, async {
        let (_client, listener) = listener();
        inject(&listener, peer(1), b"live");
        let (signal, cancelled) = oneshot::channel::<()>();
        let shutdown = Shutdown::new(async move {
            cancelled.await.unwrap_err();
        });
        let (sockets, mut received) = tokio::sync::mpsc::unbounded_channel();
        let serving = tokio::spawn(DatagramDemux::new(listener, config()).serve(
            Executor::graceful(shutdown.guard()),
            service_fn(move |socket: DemuxedSocket<_>| {
                let sockets = sockets.clone();
                async move {
                    sockets.send(socket).unwrap();
                    Ok::<_, BoxError>(())
                }
            }),
        ));
        let mut association = received.recv().await.unwrap();
        assert_eq!(next(&mut association).await, b"live");
        drop(signal);
        serving.await.unwrap().unwrap();
        // Nothing more arrives for an association once its demux stopped.
        let mut buffer = [0; 64];
        assert!(matches!(
            association.recv(&mut buffer).await,
            Err(DatagramError::Closed)
        ));
        drop(association);
        shutdown.shutdown().await;
    })
    .await
    .unwrap();
}

/// A released association whose socket is dropped late leaves the peer's next association
/// open: only its own entry is removed.
#[tokio::test(start_paused = true)]
async fn a_stale_association_dropped_late_leaves_its_successor_open() {
    timeout(LIMIT, async {
        let (client, listener) = listener();
        let mut sender = client.create_sender();
        let target = SocketAddress::local_ipv4(443);
        sender
            .send(SendDatagram::new(target, b"first"))
            .await
            .unwrap();
        let config = DemuxConfig {
            idle_timeout: Duration::from_secs(5),
            ..config()
        };
        let (mut sockets, _stats) = serve(listener, config);
        let mut stale = sockets.recv().await.unwrap();
        assert_eq!(next(&mut stale).await, b"first");
        let mut buffer = [0; 64];
        assert!(matches!(
            stale.recv(&mut buffer).await,
            Err(DatagramError::Closed)
        ));
        sender
            .send(SendDatagram::new(target, b"second"))
            .await
            .unwrap();
        let mut current = sockets.recv().await.unwrap();
        assert_eq!(next(&mut current).await, b"second");
        drop(stale);
        sender
            .send(SendDatagram::new(target, b"third"))
            .await
            .unwrap();
        assert_eq!(next(&mut current).await, b"third");
        sockets.try_recv().unwrap_err();
    })
    .await
    .unwrap();
}

/// Every received datagram restarts the idle timeout, so a busy association outlives it.
#[tokio::test(start_paused = true)]
async fn an_association_receiving_within_its_idle_timeout_stays_open() {
    timeout(LIMIT, async {
        let (client, listener) = listener();
        let mut sender = client.create_sender();
        let target = SocketAddress::local_ipv4(443);
        sender
            .send(SendDatagram::new(target, b"first"))
            .await
            .unwrap();
        let config = DemuxConfig {
            idle_timeout: Duration::from_secs(5),
            ..config()
        };
        let (mut sockets, _stats) = serve(listener, config);
        let mut association = sockets.recv().await.unwrap();
        assert_eq!(next(&mut association).await, b"first");
        // Three idle timeouts past its start, never idle for one.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(3)).await;
            sender
                .send(SendDatagram::new(target, b"more"))
                .await
                .unwrap();
            assert_eq!(next(&mut association).await, b"more");
        }
        sockets.try_recv().unwrap_err();
    })
    .await
    .unwrap();
}

/// A wildcard listener answers from the address each client sent to, which a multi-homed
/// host would otherwise choose itself.
#[tokio::test]
async fn a_wildcard_listener_replies_from_the_address_the_client_sent_to() {
    timeout(LIMIT, async {
        let sent_to = SocketAddress::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 443);
        let (mut client, listener) = MemoryDatagramSocket::pair(
            peer(1),
            SocketAddress::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443),
            NonZeroUsize::new(64).unwrap(),
        );
        let mut metadata = DatagramMetadata::empty();
        metadata.peer = peer(1);
        metadata.local = sent_to;
        listener
            .inject_received(b"hello".to_vec(), metadata)
            .unwrap();
        let (mut sockets, _stats) = serve(listener, config());
        let association = sockets.recv().await.unwrap();
        association
            .create_sender()
            .send(SendDatagram::new(peer(1), b"reply"))
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let metadata = client.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..metadata.len], b"reply");
        assert_eq!(metadata.peer, sent_to);
    })
    .await
    .unwrap();
}

/// A socket that selects a reply's whole source answers every original destination: each is
/// an association of its own for the same peer, and its replies leave from that destination.
#[tokio::test]
async fn a_full_source_socket_answers_every_original_destination_from_it() {
    timeout(LIMIT, async {
        let (mut client, listener) = listener();
        listener.set_send_source_port(true);
        let client_address = client.local_addr().unwrap();
        let destinations = [
            SocketAddress::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 443),
            SocketAddress::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 8443),
        ];
        for destination in destinations {
            let mut metadata = DatagramMetadata::empty();
            metadata.peer = client_address;
            metadata.local = SocketAddress::local_ipv4(443);
            metadata.original_destination = Some(destination);
            listener
                .inject_received(b"hello".to_vec(), metadata)
                .unwrap();
        }
        let (mut sockets, stats) = serve(listener, config());
        for destination in destinations {
            let mut association = sockets.recv().await.unwrap();
            assert_eq!(association.local_addr().unwrap(), destination);
            assert_eq!(next(&mut association).await, b"hello");
            association
                .create_sender()
                .send(SendDatagram::new(client_address, b"reply"))
                .await
                .unwrap();
            let mut buffer = [0; 64];
            let metadata = client.recv(&mut buffer).await.unwrap();
            assert_eq!(metadata.peer, destination);
        }
        assert_eq!(stats.get().dropped_reply_source, 0);
    })
    .await
    .unwrap();
}

/// A redirected association carries its original destination as its target; one sent to the
/// proxy itself has none.
#[tokio::test]
async fn only_a_redirected_association_carries_a_target() {
    timeout(LIMIT, async {
        let (client, listener) = listener();
        // Answerable from its original destination, as a transparent proxy flow is.
        listener.set_send_source_port(true);
        let client_address = client.local_addr().unwrap();
        let elsewhere = SocketAddress::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 443);
        let mut metadata = DatagramMetadata::empty();
        metadata.peer = client_address;
        metadata.local = SocketAddress::local_ipv4(443);
        metadata.original_destination = Some(elsewhere);
        listener
            .inject_received(b"hello".to_vec(), metadata)
            .unwrap();
        let (mut sockets, _stats) = serve(listener, config());
        let redirected = sockets.recv().await.unwrap();
        assert_eq!(
            redirected.extensions().get_ref::<ConnectorTarget>(),
            Some(&ConnectorTarget(HostWithPort::from(elsewhere)))
        );
    })
    .await
    .unwrap();

    timeout(LIMIT, async {
        let (client, listener) = listener();
        inject(&listener, client.local_addr().unwrap(), b"direct");
        let (mut sockets, _stats) = serve(listener, config());
        let direct = sockets.recv().await.unwrap();
        assert!(direct.extensions().get_ref::<ConnectorTarget>().is_none());
    })
    .await
    .unwrap();
}

/// A datagram sent to the listener itself is not bridged anywhere, so it cannot come back as
/// a new association and fill the table.
#[tokio::test]
async fn a_datagram_to_the_proxy_itself_is_not_bridged_back_to_it() {
    timeout(LIMIT, async {
        let listener = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let listening = listener.local_addr().unwrap();
        let demux = DatagramDemux::new(
            listener,
            DemuxConfig {
                associations: NonZeroUsize::new(16).unwrap(),
                ..config()
            },
        );
        let stats = demux.stats();
        let associations = Arc::new(AtomicUsize::new(0));
        let counted = associations.clone();
        let bridge = DatagramToProxyBridge::extension_connector_target(
            DatagramForwardService::new(NonZeroUsize::new(2048).unwrap(), EcnPolicy::Discard),
        );
        tokio::spawn(demux.serve(
            Executor::new(),
            service_fn(move |association: DemuxedSocket<UdpPacketSender>| {
                counted.fetch_add(1, AtomicOrdering::SeqCst);
                let bridge = bridge.clone();
                async move { bridge.serve(association).await.map(drop) }
            }),
        ));
        let client = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        client
            .create_sender()
            .send(SendDatagram::new(listening, b"loop?"))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(associations.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(stats.get().dropped_association_limit, 0);
    })
    .await
    .unwrap();
}

/// The target an association gets when its first datagram was redirected from `destination`
/// to a listener at `listening`, on a host whose addresses `host` enumerates.
async fn target_for(
    listening: SocketAddress,
    destination: SocketAddress,
    host: fn() -> io::Result<Vec<IpAddr>>,
) -> (Option<ConnectorTarget>, DemuxStats) {
    let (client, listener) =
        MemoryDatagramSocket::pair(peer(1), listening, NonZeroUsize::new(64).unwrap());
    listener.set_send_source_port(true);
    let mut metadata = DatagramMetadata::empty();
    metadata.peer = client.local_addr().unwrap();
    metadata.local = destination;
    metadata.original_destination = Some(destination);
    listener
        .inject_received(b"hello".to_vec(), metadata)
        .unwrap();
    let mut demux = DatagramDemux::new(listener, config());
    demux.host = HostAddresses {
        source: host,
        cached: None,
    };
    let (mut sockets, stats) = serve_demux(demux);
    let association = sockets.recv().await.unwrap();
    let target = association
        .extensions()
        .get_ref::<ConnectorTarget>()
        .cloned();
    (target, stats.get())
}

const HOST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
const OTHER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

fn host_addresses() -> io::Result<Vec<IpAddr>> {
    Ok(vec![HOST_IP])
}

fn unknown_host_addresses() -> io::Result<Vec<IpAddr>> {
    Err(io::ErrorKind::Unsupported.into())
}

/// A datagram addressed to the listener itself gets no target, so a bridge cannot send it
/// back in as a new association; one redirected beyond this listener keeps its destination.
#[tokio::test]
async fn only_a_destination_beyond_this_listener_is_a_target() {
    timeout(LIMIT, async {
        let specific = SocketAddress::new(HOST_IP, 443);
        let wildcard = SocketAddress::default_ipv4(443);
        let wildcard_v6 = SocketAddress::default_ipv6(443);
        let mapped_host: SocketAddress = "[::ffff:203.0.113.9]:443".parse().unwrap();
        let own: [(
            SocketAddress,
            SocketAddress,
            fn() -> io::Result<Vec<IpAddr>>,
        ); 7] = [
            (specific, specific, host_addresses),
            (specific, SocketAddress::default_ipv4(443), host_addresses),
            (wildcard, SocketAddress::local_ipv4(443), host_addresses),
            (wildcard, SocketAddress::new(HOST_IP, 443), host_addresses),
            (wildcard_v6, SocketAddress::local_ipv6(443), host_addresses),
            (wildcard_v6, mapped_host, host_addresses),
            // Unknown host addresses count as its own: a lost target beats a loop.
            (
                wildcard,
                SocketAddress::new(OTHER_IP, 443),
                unknown_host_addresses,
            ),
        ];
        for (listening, destination, host) in own {
            let (target, stats) = target_for(listening, destination, host).await;
            assert_eq!(target, None, "{destination} to {listening}");
            assert_eq!(
                stats.addressed_to_listener, 1,
                "{destination} to {listening}"
            );
        }
        let beyond = [
            (specific, SocketAddress::new(OTHER_IP, 443)),
            (specific, SocketAddress::local_ipv4(443)),
            (wildcard, SocketAddress::new(OTHER_IP, 443)),
            (wildcard, SocketAddress::local_ipv4(8443)),
            (wildcard, SocketAddress::new(HOST_IP, 8443)),
        ];
        for (listening, destination) in beyond {
            let (target, stats) = target_for(listening, destination, host_addresses).await;
            assert_eq!(
                target,
                Some(ConnectorTarget(HostWithPort::from(destination))),
                "{destination} to {listening}"
            );
            assert_eq!(
                stats.addressed_to_listener, 0,
                "{destination} to {listening}"
            );
        }
    })
    .await
    .unwrap();
}

/// On a wildcard listener that reports original destinations, as a transparent one does, a
/// datagram sent straight to it is one association, not bridged back into the listener.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn a_datagram_to_a_wildcard_listener_is_not_bridged_back_to_it() {
    timeout(LIMIT, async {
        let socket = crate::UdpSocketConfig::new().with_receive_original_destination(true);
        let listener = crate::UdpSocketFactory::new(socket)
            .bind(SocketAddress::default_ipv4(0))
            .await
            .unwrap();
        assert!(listener.capabilities().receive_original_destination);
        let port = listener.local_addr().unwrap().port;
        let demux = DatagramDemux::new(
            listener,
            DemuxConfig {
                associations: NonZeroUsize::new(16).unwrap(),
                ..config()
            },
        );
        let stats = demux.stats();
        let associations = Arc::new(AtomicUsize::new(0));
        let counted = associations.clone();
        let bridge = DatagramToProxyBridge::extension_connector_target(
            DatagramForwardService::new(NonZeroUsize::new(2048).unwrap(), EcnPolicy::Discard),
        );
        tokio::spawn(demux.serve(
            Executor::new(),
            service_fn(move |association| {
                counted.fetch_add(1, AtomicOrdering::SeqCst);
                let bridge = bridge.clone();
                async move { bridge.serve(association).await.map(drop) }
            }),
        ));
        let client = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        client
            .create_sender()
            .send(SendDatagram::new(SocketAddress::local_ipv4(port), b"loop?"))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(associations.load(AtomicOrdering::SeqCst), 1);
        let stats = stats.get();
        assert_eq!(stats.addressed_to_listener, 1);
        assert_eq!(stats.dropped_association_limit, 0);
    })
    .await
    .unwrap();
}

/// What all associations hold queued stays within the byte budget: a datagram beyond it is
/// dropped, and reading or ending an association frees its share.
#[tokio::test]
async fn queued_bytes_stay_within_the_budget() {
    timeout(LIMIT, async {
        let (_client, listener) = listener();
        for _ in 0..10 {
            for last in 1..=4 {
                inject(&listener, peer(last), &[7; 1000]);
            }
        }
        let (mut sockets, stats) = serve(
            listener,
            DemuxConfig {
                associations: NonZeroUsize::new(8).unwrap(),
                queue: NonZeroUsize::new(64).unwrap(),
                queued_bytes: NonZeroUsize::new(4096).unwrap(),
                ..config()
            },
        );
        let mut associations = Vec::new();
        for _ in 0..4 {
            associations.push(sockets.recv().await.unwrap());
        }
        while stats.get().dropped_queue_full < 36 {
            tokio::task::yield_now().await;
        }
        let held = stats.get();
        assert_eq!((held.queued_bytes, held.dropped_queue_full), (4000, 36));
        assert_eq!(next(&mut associations[0]).await.len(), 1000);
        assert_eq!(stats.get().queued_bytes, 3000);
        drop(associations.pop());
        assert_eq!(stats.get().queued_bytes, 2000);
    })
    .await
    .unwrap();
}

/// Binds memory sockets where the demux asks, each paired with `far`, the client side, which
/// the test keeps; refuses every bind when `refuse` is set.
#[derive(Clone)]
struct MemoryBinder {
    far: SocketAddress,
    refuse: bool,
    bound: Arc<Mutex<Vec<(SocketAddress, MemoryDatagramSocket)>>>,
}

impl MemoryBinder {
    fn new(far: SocketAddress) -> Self {
        Self {
            far,
            refuse: false,
            bound: Arc::default(),
        }
    }

    fn take(&self) -> Vec<(SocketAddress, MemoryDatagramSocket)> {
        std::mem::take(&mut *self.bound.lock())
    }
}

impl Service<SocketAddress> for MemoryBinder {
    type Output = MemoryDatagramSocket;
    type Error = BoxError;

    async fn serve(&self, local: SocketAddress) -> Result<Self::Output, Self::Error> {
        if self.refuse {
            return Err(BoxError::from_static_str("bind refused"));
        }
        let (socket, far) =
            MemoryDatagramSocket::pair(local, self.far, NonZeroUsize::new(64).unwrap());
        self.bound.lock().push((local, far));
        Ok(socket)
    }
}

/// Queue `payload` on `listener` as a datagram from `from` redirected from `destination`.
fn inject_redirected(
    listener: &MemoryDatagramSocket,
    from: SocketAddress,
    destination: SocketAddress,
    payload: &[u8],
) {
    let mut metadata = DatagramMetadata::empty();
    metadata.peer = from;
    metadata.local = destination;
    metadata.original_destination = Some(destination);
    listener
        .inject_received(payload.to_vec(), metadata)
        .unwrap();
}

/// A redirected datagram the listener cannot answer is answered from a socket bound at its
/// destination, and what that socket receives joins the association.
#[tokio::test]
async fn a_redirected_association_replies_from_a_socket_bound_at_its_destination() {
    timeout(LIMIT, async {
        let (mut client, listener) = listener();
        let client_address = client.local_addr().unwrap();
        let destination = SocketAddress::new(OTHER_IP, 443);
        inject_redirected(&listener, client_address, destination, b"hello");
        let binder = MemoryBinder::new(client_address);
        let (mut sockets, stats) =
            serve_demux(DatagramDemux::new(listener, config()).with_reply_sockets(binder.clone()));
        let mut association = sockets.recv().await.unwrap();
        assert_eq!(next(&mut association).await, b"hello");
        assert_eq!(association.local_addr().unwrap(), destination);
        association
            .create_sender()
            .send(SendDatagram::new(client_address, b"reply"))
            .await
            .unwrap();
        let mut bound = binder.take();
        assert_eq!(bound.len(), 1);
        let (bound_at, mut far) = bound.pop().unwrap();
        assert_eq!(bound_at, destination);
        let mut buffer = [0; 64];
        let metadata = far.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..metadata.len], b"reply");
        assert_eq!(
            metadata.peer, destination,
            "the reply leaves from the destination"
        );
        timeout(Duration::from_millis(50), client.recv(&mut buffer))
            .await
            .expect_err("nothing leaves from the listener");
        far.create_sender()
            .send(SendDatagram::new(destination, b"again"))
            .await
            .unwrap();
        assert_eq!(next(&mut association).await, b"again");
        assert_eq!(stats.get().dropped_reply_source, 0);
    })
    .await
    .unwrap();
}

/// Associations addressed to one destination share its socket, which closes with the last of
/// them; one opened by a datagram that socket received is a redirected association too.
#[tokio::test]
async fn associations_share_their_destinations_reply_socket_until_the_last_ends() {
    timeout(LIMIT, async {
        let (client, listener) = listener();
        let client_address = client.local_addr().unwrap();
        let first = SocketAddress::new(OTHER_IP, 443);
        let second = SocketAddress::new(OTHER_IP, 8443);
        inject_redirected(&listener, peer(1), first, b"one");
        inject_redirected(&listener, peer(2), first, b"two");
        inject_redirected(&listener, peer(1), second, b"three");
        let binder = MemoryBinder::new(client_address);
        let (mut sockets, _stats) = serve_demux(
            DatagramDemux::new(
                listener,
                DemuxConfig {
                    associations: NonZeroUsize::new(8).unwrap(),
                    ..config()
                },
            )
            .with_reply_sockets(binder.clone()),
        );
        let mut associations = Vec::new();
        for _ in 0..3 {
            associations.push(sockets.recv().await.unwrap());
        }
        let bound = binder.take();
        let bound_at: Vec<_> = bound.iter().map(|(local, _)| *local).collect();
        assert_eq!(bound_at, [first, second], "one socket per destination");
        let (_, far_first) = &bound[0];
        far_first
            .create_sender()
            .send(SendDatagram::new(first, b"from the socket"))
            .await
            .unwrap();
        let mut joined = sockets.recv().await.unwrap();
        assert_eq!(joined.peer_addr().unwrap(), client_address);
        assert_eq!(
            joined.extensions().get_ref::<ConnectorTarget>(),
            Some(&ConnectorTarget(HostWithPort::from(first)))
        );
        assert_eq!(next(&mut joined).await, b"from the socket");
        assert!(
            binder.take().is_empty(),
            "the socket at its destination is reused"
        );

        associations.retain(|association| association.local_addr().unwrap() != first);
        drop(joined);
        let mut buffer = [0; 64];
        let (_, mut far_first) = bound.into_iter().next().unwrap();
        assert!(matches!(
            far_first.recv(&mut buffer).await,
            Err(DatagramError::Closed)
        ));
    })
    .await
    .unwrap();
}

/// A destination the demux cannot bind at is counted, not answered from the listener.
#[tokio::test]
async fn a_destination_without_a_reply_socket_is_dropped_and_counted() {
    timeout(LIMIT, async {
        let (client, listener) = listener();
        let client_address = client.local_addr().unwrap();
        inject_redirected(
            &listener,
            client_address,
            SocketAddress::new(OTHER_IP, 443),
            b"hello",
        );
        inject(&listener, client_address, b"direct");
        let binder = MemoryBinder {
            refuse: true,
            ..MemoryBinder::new(client_address)
        };
        let (mut sockets, stats) =
            serve_demux(DatagramDemux::new(listener, config()).with_reply_sockets(binder));
        let mut direct = sockets.recv().await.unwrap();
        assert_eq!(next(&mut direct).await, b"direct");
        assert_eq!(stats.get().dropped_reply_source, 1);
    })
    .await
    .unwrap();
}

/// Through a real TPROXY redirect of UDP/443 to port 15000, in a network namespace of its own:
/// replies leave from the original destination, and the client's next datagrams reach its
/// association whichever socket the host delivers them to.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN and a TPROXY redirect of UDP/443 to port 15000"]
async fn a_tproxy_listener_answers_from_the_original_destination() {
    let listener = crate::TransparentUdpSocketFactory::new(
        crate::UdpSocketConfig::new().with_receive_original_destination(true),
    )
    .serve(SocketAddress::default_ipv4(15000))
    .await
    .unwrap();
    let echoed = Arc::new(AtomicUsize::new(0));
    let counted = echoed.clone();
    let demux = DatagramDemux::new(listener, config())
        .with_reply_sockets(crate::TransparentUdpSocketFactory::default());
    tokio::spawn(demux.serve(
        Executor::new(),
        service_fn(move |mut association: DemuxedSocket<UdpPacketSender>| {
            let counted = counted.clone();
            async move {
                let peer = association.peer_addr()?;
                let mut sender = association.create_sender();
                let mut buffer = [0; 2048];
                while let Ok(metadata) = association.recv(&mut buffer).await {
                    sender
                        .send(SendDatagram::new(peer, &buffer[..metadata.len]))
                        .await?;
                    counted.fetch_add(1, AtomicOrdering::SeqCst);
                }
                Ok::<_, BoxError>(())
            }
        }),
    ));
    timeout(Duration::from_secs(30), async {
        while echoed.load(AtomicOrdering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("three datagrams echoed from the original destination");
}
