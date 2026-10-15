use std::{num::NonZeroUsize, sync::atomic::AtomicUsize, time::Duration};

use parking_lot::Mutex;
use rama_core::{error::BoxError, rt::Executor, service::service_fn};
use rama_udp::{
    DatagramDemux, DatagramSenderExt as _, DatagramSocketExt as _, DemuxConfig, DemuxedSocket,
};
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

/// A datagram larger than the receive buffer is reported, never cut, and stays for the next
/// receive.
#[tokio::test]
async fn a_datagram_is_never_cut() {
    timeout(LIMIT, async {
        let (flow, incoming, _written, _demands) = flow();
        let mut socket = UdpFlowSocket::new(flow);
        incoming
            .send(Datagram::new(
                Bytes::from_static(b"twelve bytes"),
                destination(1, 443),
            ))
            .await
            .unwrap();
        let mut small = [0; 4];
        assert!(matches!(
            socket.recv(&mut small).await,
            Err(DatagramError::PayloadTooLarge { len: 12, max: 4 })
        ));
        let mut buffer = [0; 64];
        let metadata = socket.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..metadata.len], b"twelve bytes");
        assert_eq!(
            metadata.original_destination,
            Some(destination(1, 443).into())
        );
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
