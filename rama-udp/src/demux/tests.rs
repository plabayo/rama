use std::net::{IpAddr, Ipv4Addr};

use rama_core::{graceful::Shutdown, service::service_fn};
use tokio::{
    sync::{mpsc::UnboundedReceiver, oneshot},
    time::timeout,
};

use super::*;
use crate::{DatagramSenderExt as _, test_utils::MemoryDatagramSocket};

const LIMIT: Duration = Duration::from_secs(20);

fn config() -> DemuxConfig {
    DemuxConfig {
        associations: NonZeroUsize::new(4).unwrap(),
        queue: NonZeroUsize::new(4).unwrap(),
        idle_timeout: Duration::from_secs(30),
        receive_bytes: NonZeroUsize::new(2048).unwrap(),
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
    let demux = DatagramDemux::new(listener, config);
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
