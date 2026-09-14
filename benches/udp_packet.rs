//! Datagram contract and native socket baselines. Native cases verify delivered payloads.
//! Socket setup and first-use warmup are excluded; each sample drains all its sends.
#![expect(
    clippy::unwrap_used,
    reason = "benchmark setup and packet delivery must succeed"
)]

use divan::{AllocProfiler, black_box, counter::ItemsCount};
use rama::{
    net::{socket::SocketOptions, stream::Socket as _},
    udp::{
        DatagramCapabilities, DatagramError, DatagramSender, DatagramSenderExt as _,
        DatagramSocket, DatagramSocketExt as _, SendDatagram, UdpPacketSender, UdpPacketSocket,
        UdpSocketConfig, UdpSocketFactory,
    },
    utils::octets,
};
use std::{
    task::{Context, Poll, Waker},
    time::Duration,
};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

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
        assert!(matches!(sender.poll_send_batch(&mut cx, black_box(&datagrams)), Poll::Ready(Ok(n)) if n == count));
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
