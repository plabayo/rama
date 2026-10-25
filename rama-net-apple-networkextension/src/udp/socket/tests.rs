use std::{num::NonZeroUsize, sync::atomic::AtomicUsize, time::Duration};

use parking_lot::Mutex;
use rama_core::{error::BoxError, rt::Executor, service::service_fn};
use rama_udp::{
    DatagramDemux, DatagramSenderExt as _, DatagramSocketExt as _, DemuxConfig, DemuxedSocket,
};
use rama_utils::octets::kib;
use tokio::{
    sync::mpsc::{self, UnboundedReceiver},
    time::timeout,
};

use super::*;

const LIMIT: Duration = Duration::from_secs(20);

/// A flow fed by `incoming`, whose writes back to the app land in the returned list, with
/// its read demands counted.
fn flow() -> (
    UdpFlow,
    mpsc::Sender<Datagram>,
    Arc<Mutex<Vec<Datagram>>>,
    Arc<AtomicUsize>,
) {
    let (incoming, receiver) = mpsc::channel(16);
    let written = Arc::new(Mutex::new(Vec::new()));
    let sink = written.clone();
    let demands = Arc::new(AtomicUsize::new(0));
    let demand = demands.clone();
    let flow = UdpFlow::new_with_io_demand(
        receiver,
        Arc::new(move |datagram| sink.lock().push(datagram)),
        Some(Arc::new(move || {
            demand.fetch_add(1, Ordering::SeqCst);
        })),
        None,
        None,
        None,
    );
    (flow, incoming, written, demands)
}

fn destination(last: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, last)), port)
}

type Associations = UnboundedReceiver<DemuxedSocket<UdpFlowSender>>;

fn demux(socket: UdpFlowSocket) -> Associations {
    let (associations, received) = mpsc::unbounded_channel();
    let demux = DatagramDemux::new(
        socket,
        DemuxConfig {
            associations: NonZeroUsize::new(8).unwrap(),
            queue: NonZeroUsize::new(8).unwrap(),
            idle_timeout: Duration::from_secs(30),
            receive_bytes: NonZeroUsize::new(2048).unwrap(),
            queued_bytes: NonZeroUsize::new(kib(64)).unwrap(),
        },
    );
    tokio::spawn(demux.serve(
        Executor::new(),
        service_fn(move |association| {
            let associations = associations.clone();
            async move {
                associations.send(association).unwrap();
                Ok::<_, BoxError>(())
            }
        }),
    ));
    received
}

/// Every destination of one flow is an association of its own, and each one's replies reach
/// the app as sent by that destination: a second server on the same app socket does not end
/// the first.
#[tokio::test]
async fn each_destination_of_a_flow_is_its_own_association() {
    timeout(LIMIT, async {
        let (flow, incoming, written, _demands) = flow();
        let mut associations = demux(UdpFlowSocket::new(flow));
        let destinations = [
            destination(1, 443),
            destination(2, 443),
            destination(1, 8443),
        ];
        for destination in destinations {
            incoming
                .send(Datagram::new(Bytes::from_static(b"hello"), destination))
                .await
                .unwrap();
        }
        for destination in destinations {
            let mut association = associations.recv().await.unwrap();
            assert_eq!(
                association.local_addr().unwrap(),
                SocketAddress::from(destination)
            );
            let mut buffer = [0; 64];
            let metadata = association.recv(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..metadata.len], b"hello");
            let app = association.peer_addr().unwrap();
            association
                .create_sender()
                .send(SendDatagram::new(app, b"reply"))
                .await
                .unwrap();
        }
        let written = written.lock();
        let sent_by: Vec<_> = written.iter().map(|datagram| datagram.peer).collect();
        assert_eq!(sent_by, destinations.map(Some));
        assert!(written.iter().all(|datagram| datagram.payload == "reply"));
    })
    .await
    .unwrap();
}

/// A datagram without a destination cannot be attributed: it is dropped and counted, and the
/// next one is still delivered.
#[tokio::test]
async fn a_datagram_without_a_destination_is_dropped_and_counted() {
    timeout(LIMIT, async {
        let (flow, incoming, _written, _demands) = flow();
        let mut socket = UdpFlowSocket::new(flow);
        incoming
            .send(Datagram::without_peer(Bytes::from_static(b"lost")))
            .await
            .unwrap();
        incoming
            .send(Datagram::new(
                Bytes::from_static(b"kept"),
                destination(1, 443),
            ))
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let metadata = socket.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..metadata.len], b"kept");
        assert_eq!(socket.dropped_without_destination(), 1);
    })
    .await
    .unwrap();
}

/// A datagram larger than the receive buffer is reported truncated, as a kernel socket does, and
/// costs only itself: a demux drops it as invalid and keeps serving the flow.
#[tokio::test]
async fn an_oversized_datagram_costs_only_itself() {
    timeout(LIMIT, async {
        let (first, incoming, _written, _demands) = flow();
        let mut socket = UdpFlowSocket::new(first);
        incoming
            .send(Datagram::new(
                Bytes::from_static(b"twelve bytes"),
                destination(1, 443),
            ))
            .await
            .unwrap();
        let mut small = [0; 4];
        let metadata = socket.recv(&mut small).await.unwrap();
        assert_eq!((metadata.len, metadata.original_len), (4, 12));

        let (second, incoming, _written, _demands) = flow();
        let mut associations = demux(UdpFlowSocket::new(second));
        incoming
            .send(Datagram::new(
                Bytes::from(vec![0; 4096]),
                destination(1, 443),
            ))
            .await
            .unwrap();
        incoming
            .send(Datagram::new(
                Bytes::from_static(b"small"),
                destination(2, 443),
            ))
            .await
            .unwrap();
        // The oversized datagram, received first, opened no association.
        let mut association = associations.recv().await.unwrap();
        assert_eq!(
            association.local_addr().unwrap(),
            SocketAddress::from(destination(2, 443))
        );
        let mut buffer = [0; 64];
        let metadata = association.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..metadata.len], b"small");
        associations.try_recv().unwrap_err();
    })
    .await
    .unwrap();
}

/// A reply reaches the app as sent by its destination whatever the families of the two: the
/// app endpoint labels the flow, and an IPv6 app socket gets an IPv4 source v4-mapped.
#[tokio::test]
async fn a_reply_crosses_families_as_the_app_addressed_it() {
    let v4 = destination(1, 443);
    let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let mapped: SocketAddr = "[::ffff:198.51.100.1]:443".parse().unwrap();
    let rows: [(&str, SocketAddr, SocketAddr); 7] = [
        ("0.0.0.0:0", v4, v4),
        ("0.0.0.0:0", v6, v6),
        ("192.0.2.10:5000", v4, v4),
        ("[2001:db8::10]:5000", v6, v6),
        ("[::]:5000", v6, v6),
        ("[::]:5000", v4, mapped),
        ("[2001:db8::10]:5000", mapped, mapped),
    ];
    for (app, source, sent_by) in rows {
        let app: SocketAddress = app.parse().unwrap();
        let (app_flow, _incoming, written, _demands) = flow();
        let socket = UdpFlowSocket::with_app(app_flow, app);
        // As a demuxed association sends: its canonical local address as the source.
        let source = SocketAddress::from(source).into_canonical_ip_addr();
        socket
            .create_sender()
            .send(
                SendDatagram::new(app, b"reply")
                    .with_source_ip(source.ip_addr)
                    .with_source_port(source.port),
            )
            .await
            .unwrap_or_else(|error| panic!("app {app}, source {source}: {error}"));
        assert_eq!(
            written.lock()[0].peer,
            Some(sent_by),
            "app {app}, source {source}"
        );
    }
}

/// A link-local destination is only reachable through its zone. The socket hands it on as
/// the interface it names, and a reply names the zone of its source; none is guessed.
#[tokio::test]
async fn a_link_local_zone_survives_the_round_trip() {
    timeout(LIMIT, async {
        let (flow, incoming, written, _demands) = flow();
        let mut socket = UdpFlowSocket::with_app(flow, "[fe80::10]:5353".parse().unwrap());
        let app = socket.peer_addr().unwrap();
        let scoped: SocketAddr = "[fe80::1%4]:5353".parse().unwrap();
        let multicast: SocketAddr = "[ff02::fb%7]:5353".parse().unwrap();
        for (destination, scope) in [(scoped, 4), (multicast, 7)] {
            incoming
                .send(Datagram::new(Bytes::from_static(b"query"), destination))
                .await
                .unwrap();
            let mut buffer = [0; 64];
            let metadata = socket.recv(&mut buffer).await.unwrap();
            assert_eq!(metadata.interface_index, Some(scope), "{destination}");
            assert_eq!(metadata.local, SocketAddress::from(destination));
        }

        let mut sender = socket.create_sender();
        // (source, interface the reply names, sent by)
        let replies: [(&str, Option<u32>, SocketAddr); 4] = [
            ("fe80::1", Some(4), "[fe80::1%4]:5353".parse().unwrap()),
            ("fe80::99", Some(7), "[fe80::99%7]:5353".parse().unwrap()),
            // Named no zone: none is invented.
            ("fe80::1", None, "[fe80::1]:5353".parse().unwrap()),
            // A global source has no zone, whatever the reply names.
            (
                "2001:db8::1",
                Some(4),
                "[2001:db8::1]:5353".parse().unwrap(),
            ),
        ];
        for (source, interface, _) in replies {
            sender
                .send(
                    SendDatagram::new(app, b"answer")
                        .with_source_ip(source.parse::<IpAddr>().unwrap())
                        .with_source_port(5353)
                        .maybe_with_source_interface(interface),
                )
                .await
                .unwrap();
        }
        let sent_by: Vec<_> = written
            .lock()
            .iter()
            .map(|datagram| datagram.peer)
            .collect();
        let expected: Vec<_> = replies
            .iter()
            .map(|(_, _, sent_by)| Some(*sent_by))
            .collect();
        assert_eq!(sent_by, expected);
    })
    .await
    .unwrap();
}

/// A reply must name the destination it comes from, and go to the app only.
#[tokio::test]
async fn a_reply_names_its_source_and_goes_to_the_app() {
    timeout(LIMIT, async {
        let (flow, _incoming, written, _demands) = flow();
        let socket = UdpFlowSocket::new(flow);
        let app = socket.peer_addr().unwrap();
        let mut sender = socket.create_sender();
        assert!(matches!(
            sender.send(SendDatagram::new(app, b"anonymous")).await,
            Err(DatagramError::Io(_))
        ));
        let elsewhere = SocketAddress::from(destination(9, 9));
        assert!(matches!(
            sender
                .send(
                    SendDatagram::new(elsewhere, b"stray")
                        .with_source_ip(destination(1, 443).ip())
                        .with_source_port(443)
                )
                .await,
            Err(DatagramError::ForeignDestination(_))
        ));
        assert!(written.lock().is_empty());
    })
    .await
    .unwrap();
}

/// Each receive asks the kernel for one read, however often it is polled while waiting.
#[tokio::test]
async fn each_receive_asks_for_one_read() {
    timeout(LIMIT, async {
        let (flow, incoming, _written, demands) = flow();
        let mut socket = UdpFlowSocket::new(flow);
        let mut buffer = [0; 64];
        for _ in 0..3 {
            timeout(Duration::from_millis(10), socket.recv(&mut buffer))
                .await
                .unwrap_err();
        }
        assert_eq!(demands.load(Ordering::SeqCst), 1);
        incoming
            .send(Datagram::new(
                Bytes::from_static(b"one"),
                destination(1, 443),
            ))
            .await
            .unwrap();
        socket.recv(&mut buffer).await.unwrap();
        timeout(Duration::from_millis(10), socket.recv(&mut buffer))
            .await
            .unwrap_err();
        assert_eq!(demands.load(Ordering::SeqCst), 2);
    })
    .await
    .unwrap();
}

#[test]
fn only_link_local_unicast_and_multicast_sources_need_scopes() {
    for address in [
        "fe80::1", "febf::1", "ff01::1", "ff11::1", "ff02::fb", "ff12::fb", "ff32::1",
    ] {
        assert!(needs_scope(address.parse().unwrap()), "{address}");
    }
    for address in [
        "fe7f::1",
        "fec0::1",
        "ff05::1",
        "ff0e::1",
        "2001:db8::1",
        "::1",
    ] {
        assert!(!needs_scope(address.parse().unwrap()), "{address}");
    }
}

/// The same link-local address on two links is two destinations: each is an association
/// of its own, and each one's replies (a multicast responder's too) go back over its link.
#[tokio::test]
async fn scoped_destinations_on_two_interfaces_are_distinct_associations() {
    timeout(LIMIT, async {
        let (flow, incoming, written, _demands) = flow();
        let mut associations = demux(UdpFlowSocket::new(flow));
        let destinations: [(SocketAddr, u32); 5] = [
            ("[fe80::1%4]:443".parse().unwrap(), 4),
            ("[fe80::1%7]:443".parse().unwrap(), 7),
            ("[ff02::fb%7]:5353".parse().unwrap(), 7),
            ("[ff01::123%4]:5353".parse().unwrap(), 4),
            ("[ff01::123%7]:5353".parse().unwrap(), 7),
        ];
        let mut opened = Vec::new();
        for (destination, scope) in destinations {
            incoming
                .send(Datagram::new(Bytes::from_static(b"query"), destination))
                .await
                .unwrap();
            let mut association = timeout(Duration::from_millis(500), associations.recv())
                .await
                .unwrap_or_else(|_| panic!("{destination} must open an association of its own"))
                .unwrap();
            let mut buffer = [0; 64];
            assert_eq!(
                association.recv(&mut buffer).await.unwrap().interface_index,
                Some(scope)
            );
            assert_eq!(association.interface_index(), Some(scope));
            opened.push(association);
        }

        let app = opened[0].peer_addr().unwrap();
        // The two unicast associations answer as themselves.
        for association in &opened[..2] {
            association
                .create_sender()
                .send(SendDatagram::new(app, b"answer"))
                .await
                .unwrap();
        }
        // The multicast association relays a responder's answer from its own address.
        opened[2]
            .create_sender()
            .send(
                SendDatagram::new(app, b"answer")
                    .with_source_ip("fe80::99".parse::<IpAddr>().unwrap())
                    .with_source_port(5353),
            )
            .await
            .unwrap();
        // Each interface-local group answers on its own interface.
        for association in &opened[3..] {
            association
                .create_sender()
                .send(SendDatagram::new(app, b"answer"))
                .await
                .unwrap();
        }
        let sent_by: Vec<_> = written
            .lock()
            .iter()
            .map(|datagram| datagram.peer)
            .collect();
        let expected: [SocketAddr; 5] = [
            "[fe80::1%4]:443".parse().unwrap(),
            "[fe80::1%7]:443".parse().unwrap(),
            "[fe80::99%7]:5353".parse().unwrap(),
            "[ff01::123%4]:5353".parse().unwrap(),
            "[ff01::123%7]:5353".parse().unwrap(),
        ];
        assert_eq!(sent_by, expected.map(Some));
    })
    .await
    .unwrap();
}
