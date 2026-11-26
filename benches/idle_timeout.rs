//! Idle-timeout cost per forwarded datagram: the HTTP datagram relay and a CONNECT-UDP
//! socket over capsule carriers, in memory or on loopback TCP, and the idle guard itself.
//! Each sample moves a burst of `BURST` small datagrams between spawned tasks, as a proxy's
//! tunnel tasks run; carrier setup is excluded. The `per_event` benches set the cost of
//! recording one activity on the shared idle primitive against the shapes it replaced.

#![expect(
    clippy::unwrap_used,
    reason = "benchmark setup and delivery must succeed"
)]

use std::{
    assert_matches,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Waker},
    time::Duration,
};

use divan::{black_box, counter::ItemsCount};
use rama::{
    Service as _, ServiceInput,
    bytes::Bytes,
    graceful::Scope,
    http::datagram::{HttpDatagramRelay, HttpDatagramSession, SessionEvent},
    io::BridgeIo,
    net::address::SocketAddress,
    proxy::masque::connect_udp::{ConnectUdpSocket, ConnectUdpSocketConfig, session_config},
    rt::{IdleActivity, IdleGuard, IdleProgress},
    udp::{DatagramSenderExt as _, DatagramSocket as _, DatagramSocketExt as _, SendDatagram},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    runtime::{Builder, Runtime},
    time::{Instant, Sleep},
};

mod bench_alloc;

fn main() {
    divan::main();
}

const BURST: usize = 4096;
const PAYLOAD: usize = 64;
const CARRIER: usize = 64 * 1024;
const LOCAL: SocketAddress = SocketAddress::local_ipv4(4433);
const PEER: SocketAddress = SocketAddress::local_ipv4(443);

fn runtime(threaded: bool) -> Runtime {
    if threaded {
        Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    } else {
        Builder::new_current_thread().enable_all().build().unwrap()
    }
}

const CARRIERS: &[&str] = &["memory", "tcp"];

/// Both ends of a byte stream carrying capsules.
trait Carrier: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    fn pair(rt: &Runtime) -> (ServiceInput<Self>, ServiceInput<Self>)
    where
        Self: Sized;
}

impl Carrier for tokio::io::DuplexStream {
    fn pair(_: &Runtime) -> (ServiceInput<Self>, ServiceInput<Self>) {
        let (a, b) = tokio::io::duplex(CARRIER);
        (ServiceInput::new(a), ServiceInput::new(b))
    }
}

impl Carrier for TcpStream {
    fn pair(rt: &Runtime) -> (ServiceInput<Self>, ServiceInput<Self>) {
        rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (a, b) = tokio::join!(Self::connect(address), listener.accept());
            let (a, b) = (a.unwrap(), b.unwrap().0);
            a.set_nodelay(true).unwrap();
            b.set_nodelay(true).unwrap();
            (ServiceInput::new(a), ServiceInput::new(b))
        })
    }
}

const IDLE: Duration = Duration::from_mins(2);

/// Per-activity cost of the shared primitive and of the shapes it replaced.
#[divan::bench_group]
mod per_event {
    use tokio::time::sleep;

    use super::{
        AtomicU64, Context, Duration, IDLE, IdleActivity, IdleGuard, IdleProgress, Instant,
        Ordering, Pin, Sleep, Waker, black_box, runtime,
    };

    /// Shared: the guard's own reset, a timestamp of its owner.
    #[divan::bench]
    fn idle_guard_reset(bencher: divan::Bencher) {
        let rt = runtime(false);
        let _entered = rt.enter();
        let mut guard = IdleGuard::new(IDLE);
        bencher.bench_local(|| guard.reset());
    }

    /// Shared: recording on the activity stamp of other tasks.
    #[divan::bench]
    fn idle_activity_record(bencher: divan::Bencher) {
        let rt = runtime(false);
        let _entered = rt.enter();
        let activity = IdleActivity::new();
        bencher.bench_local(|| activity.record());
    }

    /// Shared: counting on the progress of other tasks.
    #[divan::bench]
    fn idle_progress_record(bencher: divan::Bencher) {
        let progress = IdleProgress::new();
        bencher.bench_local(|| black_box(&progress).record());
    }

    /// Replaced: a registered timer moved on every event (datagram demux, guard reset).
    #[divan::bench]
    fn sleep_reset(bencher: divan::Bencher) {
        let rt = runtime(false);
        let _entered = rt.enter();
        let mut sleep: Pin<Box<Sleep>> = Box::pin(sleep(IDLE));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(sleep.as_mut().poll(&mut cx).is_pending());
        bencher.bench_local(|| sleep.as_mut().reset(Instant::now() + IDLE));
    }

    /// Replaced: a progress counter read when the timer fires (stream and I/O bridges).
    #[divan::bench]
    fn progress_counter(bencher: divan::Bencher) {
        let progress = AtomicU64::new(0);
        bencher.bench_local(|| black_box(&progress).fetch_add(1, Ordering::Relaxed));
    }

    /// Replaced: nanoseconds since an epoch, raised atomically (CONNECT-IP session).
    #[divan::bench]
    fn epoch_fetch_max(bencher: divan::Bencher) {
        let rt = runtime(false);
        let _entered = rt.enter();
        let epoch = Instant::now();
        let last = AtomicU64::new(0);
        bencher.bench_local(|| {
            let elapsed = u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
            black_box(&last).fetch_max(elapsed, Ordering::Relaxed);
        });
    }

    /// The deadline a fired timer computes from a record: paid once per timeout, not per event.
    #[divan::bench]
    fn activity_deadline(bencher: divan::Bencher) {
        let rt = runtime(false);
        let _entered = rt.enter();
        let activity = IdleActivity::new();
        bencher.bench_local(|| black_box(&activity).deadline(Duration::from_secs(1)));
    }
}

/// Run both ends of a burst as tasks of `rt` and hand back what they own.
fn burst<A, B>(rt: &Runtime, send: A, receive: B) -> (A::Output, B::Output)
where
    A: Future<Output: Send + 'static> + Send + 'static,
    B: Future<Output: Send + 'static> + Send + 'static,
{
    rt.block_on(async {
        let send = tokio::spawn(send);
        let receive = tokio::spawn(receive);
        (send.await.unwrap(), receive.await.unwrap())
    })
}

/// A burst through a relay with its default idle timeout, in one direction.
#[divan::bench(consts = [false, true], args = CARRIERS, sample_count = 50)]
fn relay_idle<const THREADED: bool>(bencher: divan::Bencher, carrier: &str) {
    relay_forward(bencher, THREADED, carrier, true);
}

/// As [`relay_idle`], without an idle timeout.
#[divan::bench(consts = [false, true], args = CARRIERS, sample_count = 50)]
fn relay_no_idle<const THREADED: bool>(bencher: divan::Bencher, carrier: &str) {
    relay_forward(bencher, THREADED, carrier, false);
}

fn relay_forward(bencher: divan::Bencher, threaded: bool, carrier: &str, idle: bool) {
    let rt = runtime(threaded);
    match carrier {
        "memory" => relay_forward_on::<tokio::io::DuplexStream>(bencher, &rt, idle),
        _ => relay_forward_on::<TcpStream>(bencher, &rt, idle),
    }
}

fn relay_forward_on<T: Carrier>(bencher: divan::Bencher, rt: &Runtime, idle: bool) {
    let (left, client) = T::pair(rt);
    let (right, origin) = T::pair(rt);
    let relay = if idle {
        HttpDatagramRelay::default()
    } else {
        HttpDatagramRelay::default().without_idle_timeout()
    };
    let relay = rt.spawn(async move { relay.serve(BridgeIo(left, right)).await });
    let (client, _client_receive) = HttpDatagramSession::new(client).split();
    let (_origin_send, origin) = HttpDatagramSession::new(origin).split();
    let mut ends = Some((client, origin));
    let payload = Bytes::from(vec![7; PAYLOAD]);
    bencher.counter(ItemsCount::new(BURST)).bench_local(|| {
        let (mut client, mut origin) = ends.take().unwrap();
        let payload = payload.clone();
        let send = async move {
            for _ in 0..BURST {
                client.send_datagram(payload.clone()).await.unwrap();
            }
            client
        };
        let receive = async move {
            for _ in 0..BURST {
                let event = origin.recv().await.unwrap();
                assert_matches!(event, Some(SessionEvent::Datagram { .. }));
            }
            origin
        };
        ends = Some(burst(rt, send, receive));
    });
    relay.abort();
}

fn tunnel<T: Carrier>(
    rt: &Runtime,
) -> (
    ConnectUdpSocket<ServiceInput<T>>,
    HttpDatagramSession<ServiceInput<T>>,
) {
    let (a, b) = T::pair(rt);
    let _entered = rt.enter();
    let socket = ConnectUdpSocket::new(
        &Scope::new(),
        HttpDatagramSession::with_config(a, session_config()),
        LOCAL,
        PEER,
        ConnectUdpSocketConfig::default(),
    );
    (
        socket,
        HttpDatagramSession::with_config(b, session_config()),
    )
}

/// A burst sent through a CONNECT-UDP socket to the peer at the other end of its carrier.
#[divan::bench(consts = [false, true], args = CARRIERS, sample_count = 50)]
fn connect_udp_send<const THREADED: bool>(bencher: divan::Bencher, carrier: &str) {
    let rt = runtime(THREADED);
    match carrier {
        "memory" => connect_udp_send_on::<tokio::io::DuplexStream>(bencher, &rt),
        _ => connect_udp_send_on::<TcpStream>(bencher, &rt),
    }
}

fn connect_udp_send_on<T: Carrier>(bencher: divan::Bencher, rt: &Runtime) {
    let (socket, peer) = tunnel::<T>(rt);
    let (_peer_send, peer) = peer.split();
    let mut ends = Some((socket.create_sender(), peer));
    bencher.counter(ItemsCount::new(BURST)).bench_local(|| {
        let (mut sender, mut peer) = ends.take().unwrap();
        let send = async move {
            let payload = [7; PAYLOAD];
            for _ in 0..BURST {
                sender
                    .send(SendDatagram::new(PEER, black_box(&payload)))
                    .await
                    .unwrap();
            }
            sender
        };
        let receive = async move {
            for _ in 0..BURST {
                let event = peer.recv().await.unwrap();
                assert_matches!(event, Some(SessionEvent::Datagram { .. }));
            }
            peer
        };
        ends = Some(burst(rt, send, receive));
    });
    drop(socket);
}

/// A burst from the peer received through a CONNECT-UDP socket.
#[divan::bench(consts = [false, true], args = CARRIERS, sample_count = 50)]
fn connect_udp_recv<const THREADED: bool>(bencher: divan::Bencher, carrier: &str) {
    let rt = runtime(THREADED);
    match carrier {
        "memory" => connect_udp_recv_on::<tokio::io::DuplexStream>(bencher, &rt),
        _ => connect_udp_recv_on::<TcpStream>(bencher, &rt),
    }
}

fn connect_udp_recv_on<T: Carrier>(bencher: divan::Bencher, rt: &Runtime) {
    let (socket, peer) = tunnel::<T>(rt);
    let (peer, _peer_receive) = peer.split();
    let mut ends = Some((peer, socket));
    let mut datagram = vec![7; PAYLOAD + 1];
    datagram[0] = 0;
    let datagram = Bytes::from(datagram);
    bencher.counter(ItemsCount::new(BURST)).bench_local(|| {
        let (mut peer, mut socket) = ends.take().unwrap();
        let datagram = datagram.clone();
        let send = async move {
            for _ in 0..BURST {
                peer.send_datagram(datagram.clone()).await.unwrap();
            }
            peer
        };
        let receive = async move {
            let mut buffer = [0; PAYLOAD];
            for _ in 0..BURST {
                let meta = socket.recv(&mut buffer).await.unwrap();
                assert_eq!(meta.len, PAYLOAD);
            }
            socket
        };
        ends = Some(burst(rt, send, receive));
    });
}
