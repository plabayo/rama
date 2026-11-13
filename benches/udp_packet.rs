//! Datagram contract and native socket baselines. Native cases verify delivered payloads.
//! Socket setup and first-use warmup are excluded; each sample drains all its sends.
#![expect(
    clippy::unwrap_used,
    reason = "benchmark setup and packet delivery must succeed"
)]

use divan::{black_box, counter::ItemsCount};
use rama::{
    Service,
    error::BoxError,
    io::BridgeIo,
    net::client::ConnectRequest,
    net::{socket::SocketOptions, stream::Socket as _},
    service::service_fn,
    udp::proxy::{
        DatagramForwardService, DatagramRecovery, DatagramRecoveryConfig,
        DatagramRecoveryFailureAction, DatagramRecoverySignal, EcnPolicy, Peer, UdpConnector,
    },
    udp::{
        DatagramCapabilities, DatagramError, DatagramSender, DatagramSenderExt as _,
        DatagramSocket, DatagramSocketExt as _, SendDatagram, UdpPacketSender, UdpPacketSocket,
        UdpSocketConfig, UdpSocketFactory,
    },
    utils::octets,
};
use std::assert_matches;
use std::{
    task::{Context, Poll, Waker},
    time::Duration,
};

mod bench_alloc;

fn main() {
    divan::main();
}

#[derive(Debug, Default)]
struct ReadySender {
    bytes: usize,
}

impl DatagramSender for ReadySender {
    fn poll_send(
        &mut self,
        _: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        self.bytes += black_box(datagram.payload()).len();
        Poll::Ready(Ok(()))
    }

    fn capabilities(&self) -> DatagramCapabilities {
        DatagramCapabilities::portable()
    }
}

#[divan::bench(args = [1, 16, 64])]
fn generic_batch(bencher: divan::Bencher, count: usize) {
    let payload = [0xa5; 1200];
    let datagrams: Vec<_> = (0..count)
        .map(|_| SendDatagram::new(([127, 0, 0, 1], 4433), &payload))
        .collect();
    let mut sender = ReadySender::default();
    let mut cx = Context::from_waker(Waker::noop());
    bencher.counter(ItemsCount::new(count)).bench_local(|| {
        assert_matches!(sender.poll_send_batch(&mut cx, black_box(&datagrams)), Poll::Ready(Ok(n)) if n == count);
        black_box(sender.bytes);
    });
}

struct NativePair {
    receiver: UdpPacketSocket,
    senders: Vec<UdpPacketSender>,
    destination: rama::net::address::SocketAddress,
    payload: Vec<u8>,
    received: Vec<u8>,
}

impl NativePair {
    async fn new(handles: usize, bytes: usize) -> Self {
        let mut options = SocketOptions::default_udp();
        options.recv_buffer_size = Some(octets::mib(2));
        let factory = UdpSocketFactory::new(UdpSocketConfig::new().with_socket_options(options));
        let receiver = factory.bind(([127, 0, 0, 1], 0)).await.unwrap();
        let source = UdpPacketSocket::bind(([127, 0, 0, 1], 0)).await.unwrap();
        let destination = receiver.local_addr().unwrap();
        Self {
            receiver,
            senders: (0..handles).map(|_| source.create_sender()).collect(),
            destination,
            payload: vec![0xa5; bytes],
            // Includes possible coalesced receives, while keeping setup allocation unmeasured.
            received: vec![0; bytes * 64],
        }
    }

    async fn transfer(&mut self) {
        let expected = self.senders.len();
        let transmit = async {
            for sender in &mut self.senders {
                sender
                    .send(SendDatagram::new(self.destination, &self.payload))
                    .await
                    .unwrap();
            }
        };
        let receive = async {
            let mut count = 0;
            while count < expected {
                let meta = self.receiver.recv(&mut self.received).await.unwrap();
                assert!(!meta.truncated);
                for packet in self.received[..meta.len]
                    .chunks(meta.segment_size.map_or(meta.len, |n| n.get()))
                {
                    assert_eq!(packet, self.payload);
                    count += 1;
                }
            }
            assert_eq!(count, expected);
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(transmit, receive);
        })
        .await
        .unwrap();
    }
}

fn native(bencher: divan::Bencher, handles: usize, bytes: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut pair = runtime.block_on(NativePair::new(handles, bytes));
    runtime.block_on(pair.transfer());
    bencher
        .counter(ItemsCount::new(handles))
        .bench_local(|| runtime.block_on(pair.transfer()));
}

#[divan::bench(args = [1, 16, 64])]
fn native_64_bytes(bencher: divan::Bencher, handles: usize) {
    native(bencher, handles, 64);
}

#[divan::bench(args = [1, 16, 64])]
fn native_1200_bytes(bencher: divan::Bencher, handles: usize) {
    native(bencher, handles, 1200);
}

#[divan::bench(args = [1, 16, 64])]
fn sender_creation(bencher: divan::Bencher, handles: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let socket = runtime
        .block_on(UdpPacketSocket::bind(([127, 0, 0, 1], 0)))
        .unwrap();
    bencher.counter(ItemsCount::new(handles)).bench_local(|| {
        for _ in 0..handles {
            black_box(socket.create_sender());
        }
    });
}

/// Isolate the steady-state path lookup and independently cached sender cost. There are no
/// tasks, network operations or payload allocations in the measured round; one sender models
/// each QUIC connection. Path creation and the first sender lookup are warmed up beforehand.
#[divan::bench(args = [1, 16, 64])]
fn grouped_ready_senders(bencher: divan::Bencher, paths: usize) {
    use rama::{
        net::address::SocketAddress,
        udp::{DatagramMetadata, DatagramSocketGroup},
    };
    use std::{io, io::IoSliceMut, num::NonZeroUsize};
    #[derive(Debug)]
    struct ReadySocket {
        peer: SocketAddress,
    }

    impl rama::net::stream::Socket for ReadySocket {
        fn local_addr(&self) -> io::Result<SocketAddress> {
            Ok(([127, 0, 0, 1], 443).into())
        }

        fn peer_addr(&self) -> io::Result<SocketAddress> {
            Ok(self.peer)
        }
    }

    impl DatagramSocket for ReadySocket {
        type Sender = ReadySender;
        fn create_sender(&self) -> ReadySender {
            ReadySender::default()
        }

        fn capabilities(&self) -> DatagramCapabilities {
            DatagramCapabilities::portable()
        }

        fn poll_recv(
            &mut self,
            _: &mut Context<'_>,
            _: &mut [IoSliceMut<'_>],
            _: &mut [DatagramMetadata],
        ) -> Poll<Result<usize, DatagramError>> {
            Poll::Pending
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let (socket, group) = DatagramSocketGroup::new(
        ([127, 0, 0, 1], 443).into(),
        rama::udp::DatagramSocketGroupConfig {
            max_paths: NonZeroUsize::new(paths).unwrap(),
            capabilities: rama::udp::DatagramCapabilities::portable(),
        },
    );
    let payload = [0xa5; 1200];
    let attachments: Vec<_> = (0..paths)
        .map(|i| {
            group
                .attach(ReadySocket {
                    peer: ([127, 0, 0, 1], u16::try_from(i + 1000).unwrap()).into(),
                })
                .unwrap()
        })
        .collect();
    let mut senders: Vec<_> = attachments.iter().map(|_| socket.create_sender()).collect();
    let packets: Vec<_> = attachments
        .iter()
        .map(|a| SendDatagram::new(a.peer_addr(), &payload))
        .collect();
    let mut cx = Context::from_waker(Waker::noop());
    for (sender, packet) in senders.iter_mut().zip(&packets) {
        assert_matches!(sender.poll_send(&mut cx, packet), Poll::Ready(Ok(())));
    }
    bencher.counter(ItemsCount::new(paths)).bench_local(|| {
        for (sender, packet) in senders.iter_mut().zip(&packets) {
            assert_matches!(
                sender.poll_send(&mut cx, black_box(packet)),
                Poll::Ready(Ok(()))
            );
        }
    });
}

/// Native forwarding baseline versus opt-in recovery with no network changes.
/// Setup is excluded; every measured batch verifies delivery. No telemetry recorder is enabled.
#[divan::bench(args = [false, true])]
fn forwarding_recovery_idle(bencher: divan::Bencher, enabled: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut pair, forwarding) = runtime.block_on(async {
        let mut pair = NativePair::new(32, 1200).await;
        let destination = pair.receiver.local_addr().unwrap();
        let ingress = UdpPacketSocket::bind(([127, 0, 0, 1], 0)).await.unwrap();
        pair.destination = ingress.local_addr().unwrap();
        let client = UdpPacketSocket::bind(([127, 0, 0, 1], 0)).await.unwrap();
        let client_address = client.local_addr().unwrap();
        pair.senders = (0..32).map(|_| client.create_sender()).collect();
        let egress = UdpConnector::new()
            .serve(ConnectRequest::new(destination.into()))
            .await
            .unwrap()
            .conn;
        let peers = BridgeIo(
            Peer {
                socket: ingress,
                address: client_address,
                source_ip: None,
            },
            Peer::connected(egress).unwrap(),
        );
        let forward =
            DatagramForwardService::new(rama::utils::macros::nonzero!(65536), EcnPolicy::Discard);
        let task = tokio::spawn(async move {
            // Retain the client receive owner for the entire association.
            let _client = client;
            if enabled {
                let recovery = DatagramRecovery::new(
                    DatagramRecoverySignal::new(),
                    DatagramRecoveryConfig {
                        preparation_timeout: Duration::from_secs(5),
                        unavailable_timeout: Duration::from_secs(5),
                        failure_action: DatagramRecoveryFailureAction::Close,
                    },
                );
                let factory = service_fn(move |()| async move {
                    Ok::<_, BoxError>(
                        UdpConnector::new()
                            .serve(ConnectRequest::new(destination.into()))
                            .await?
                            .conn,
                    )
                });
                forward
                    .forward_with_recovery(peers, &recovery, factory)
                    .await
                    .unwrap();
            } else {
                forward.serve(peers).await.unwrap();
            }
        });
        pair.transfer().await;
        (pair, task)
    });
    bencher
        .counter(ItemsCount::new(32usize))
        .bench_local(|| runtime.block_on(pair.transfer()));
    forwarding.abort();
    let _cancelled = runtime.block_on(forwarding);
}
