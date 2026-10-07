//! [`PostedRecv`] keeps every byte that arrives before a reset. These run on
//! every platform; elsewhere than Windows they exercise the pass-through.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use rama_core::{
    Layer as _, Service as _, ServiceInput,
    extensions::ExtensionsRef as _,
    io::{AbortIo, BridgeIo},
};
use rama_net::{
    address::SocketAddress,
    client::{ConnectRequest, EstablishedClientConnection},
    proxy::{IoForwardService, LingeringClose},
    stream::{Socket as _, SocketInfo},
};
use rama_utils::octets::kib;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};

use super::harness::{
    Close, FORCED_DELAY, REQUEST, Received, SIZES, exchange, read_until_end, reply, spawn_origin,
    spawn_origin_fn, tally,
};
use crate::{
    TcpStream, TokioTcpStream,
    client::service::TcpConnector,
    posted_recv::{PostedRecv, PostedRecvConfig, PostedRecvLayer},
};

const RUNS: usize = 1000;

async fn connect(addr: std::net::SocketAddr) -> PostedRecv<TcpStream> {
    connect_with(addr, &PostedRecvConfig::default()).await
}

async fn connect_with(
    addr: std::net::SocketAddr,
    config: &PostedRecvConfig,
) -> PostedRecv<TcpStream> {
    let stream = TokioTcpStream::connect(addr).await.unwrap();
    PostedRecv::with_config(TcpStream::new(stream), config)
}

/// Waits until every watched flow is gone, which means its socket is closed
/// and none of its receives is outstanding.
#[derive(Default)]
struct Watches {
    #[cfg(target_os = "windows")]
    flows: parking_lot::Mutex<Vec<crate::posted_recv::iocp::FlowWatch>>,
}

#[cfg(target_os = "windows")]
impl Watches {
    fn add<S: crate::posted_recv::RawTcpStream>(&self, stream: &PostedRecv<S>) {
        self.flows.lock().push(stream.reader().unwrap().watch());
    }

    async fn all_closed(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let open = self.flows.lock().iter().filter(|w| !w.is_closed()).count();
            if open == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "{open} flows were never closed");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Elsewhere dropping closes the socket right away, so there is nothing to
/// watch.
#[cfg(not(target_os = "windows"))]
impl Watches {
    #[expect(clippy::unused_self, reason = "same API as on Windows")]
    fn add<S: crate::posted_recv::RawTcpStream>(&self, _: &PostedRecv<S>) {}

    async fn all_closed(&self) {}
}

/// The process-wide counters return to zero once every dropped flow's
/// cancelled receives completed. Only meaningful when this test is the only
/// one in the process, as under nextest.
async fn assert_no_outstanding_receives() {
    #[cfg(target_os = "windows")]
    if std::env::var_os("NEXTEST").is_some() {
        use crate::posted_recv::iocp::{live_flows, outstanding_receives};
        let deadline = Instant::now() + Duration::from_secs(10);
        while outstanding_receives() + live_flows() > 0 {
            assert!(
                Instant::now() < deadline,
                "receives outstanding={} live flows={}",
                outstanding_receives(),
                live_flows()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_reply_sent_right_before_reset() {
    // Replies up to what the posted receives hold, with the default slots
    // and with more of them.
    let default_slots = SIZES
        .into_iter()
        .chain([kib(16), kib(32)])
        .map(|len| (len, 2));
    for (len, slots) in default_slots.chain([(kib(64), 4)]) {
        let config = PostedRecvConfig::new().with_slots(slots);
        assert!(len <= config.slots() * config.slot_size());
        let origin = spawn_origin(len, Close::Reset).await;
        let addr = origin.addr;
        let tally = tally(RUNS, 100, len, move || {
            let config = config.clone();
            async move {
                let mut stream = connect_with(addr, &config).await;
                exchange(&mut stream, FORCED_DELAY).await
            }
        })
        .await;
        assert_eq!(tally.complete, RUNS, "N={len}: {tally}");
        assert_eq!(
            tally.ends,
            [(Some(reset_code()), Some(io::ErrorKind::ConnectionReset))],
            "N={len}: {tally}"
        );
    }
    assert_no_outstanding_receives().await;
}

fn reset_code() -> i32 {
    #[cfg(target_os = "windows")]
    {
        windows_sys::Win32::Networking::WinSock::WSAECONNRESET
    }
    #[cfg(not(target_os = "windows"))]
    {
        libc::ECONNRESET
    }
}

/// Also without a forced delay, and on a runtime whose only worker is kept
/// busy, which is where a plain stream loses most.
#[test]
fn keeps_reply_without_forced_delay_on_a_busy_runtime() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let busy = super::harness::spawn_filler(8);
        for len in SIZES {
            let origin = spawn_origin(len, Close::Reset).await;
            let addr = origin.addr;
            let tally = tally(RUNS, 32, len, move || async move {
                let mut stream = connect(addr).await;
                exchange(&mut stream, Duration::ZERO).await
            })
            .await;
            assert_eq!(tally.complete, RUNS, "N={len}: {tally}");
        }
        busy.stop().await;
    });
}

/// The rama#1156 shape and the send-after-peer-close shape.
#[tokio::test(flavor = "multi_thread")]
async fn keeps_reply_on_close_with_unread_input_and_after_late_send() {
    for len in SIZES {
        let origin = spawn_origin(len, Close::UnreadInput).await;
        let addr = origin.addr;
        let seen = tally(200, 32, len, move || async move {
            let mut stream = connect(addr).await;
            exchange(&mut stream, FORCED_DELAY).await
        })
        .await;
        assert_eq!(seen.complete, 200, "unread input, N={len}: {seen}");

        let origin = spawn_origin(len, Close::Fin).await;
        let addr = origin.addr;
        let seen = tally(200, 32, len, move || async move {
            let mut stream = connect(addr).await;
            stream.write_all(REQUEST).await.unwrap();
            tokio::time::sleep(FORCED_DELAY).await;
            _ = stream.write_all(b"late").await;
            tokio::time::sleep(FORCED_DELAY).await;
            read_until_end(&mut stream).await
        })
        .await;
        assert_eq!(seen.complete, 200, "late send, N={len}: {seen}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn graceful_end_of_stream_after_all_bytes() {
    for len in SIZES.into_iter().chain([0, kib(200)]) {
        let origin = spawn_origin(len, Close::Fin).await;
        let addr = origin.addr;
        let seen = tally(200, 32, len, move || async move {
            let mut stream = connect(addr).await;
            exchange(&mut stream, FORCED_DELAY).await
        })
        .await;
        assert_eq!(seen.complete, 200, "N={len}: {seen}");
        assert_eq!(seen.ends, [(None, None)], "N={len}: {seen}");
    }
    assert_no_outstanding_receives().await;
}

/// With a stalled reader at most [`PostedRecvConfig::max_buffered`] bytes, plus
/// what the posted receives hold, are kept; what is left in the kernel buffer is
/// lost to the reset. What is kept must still be an intact prefix, then the reset.
#[tokio::test(flavor = "multi_thread")]
async fn reply_beyond_capacity_keeps_an_intact_prefix() {
    let len = kib(1024);
    let origin = spawn_origin_fn(move |mut stream| async move {
        let mut req = vec![0; REQUEST.len()];
        _ = stream.read_exact(&mut req).await;
        _ = tokio::time::timeout(Duration::from_millis(200), stream.write_all(&reply(len))).await;
        _ = stream.set_zero_linger();
    })
    .await;
    let mut stream = connect(origin.addr).await;
    let received = exchange(&mut stream, Duration::from_millis(400)).await;
    eprintln!(
        "beyond capacity: kept {} of {len} bytes, end={:?}",
        received.bytes.len(),
        received.end
    );
    assert_eq!(received.bytes, reply(len)[..received.bytes.len()]);
    if received.bytes.len() < len {
        assert!(matches!(
            received.end_kind(),
            Some(io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
        ));
    }
    #[cfg(target_os = "windows")]
    {
        // A conservative floor: at least what the posted receives hold.
        let config = PostedRecvConfig::default();
        assert!(received.bytes.len() >= config.slots() * config.slot_size());
    }
}

/// Many small posted receives, resumed from the reader: the stream must come
/// out in order. Such tiny slots cannot keep up, so with a reset only an
/// intact prefix is expected.
#[tokio::test(flavor = "multi_thread")]
async fn tiny_slots_keep_stream_order() {
    let config = PostedRecvConfig::new()
        .with_slots(3)
        .with_slot_size(7)
        .with_max_buffered(0);
    let len = kib(64);
    for close in [Close::Fin, Close::Reset] {
        let origin = spawn_origin(len, close).await;
        let mut stream = connect_with(origin.addr, &config).await;
        let received = exchange(&mut stream, Duration::ZERO).await;
        assert_eq!(
            received.bytes,
            reply(len)[..received.bytes.len()],
            "{close:?}"
        );
        match close {
            Close::Reset if received.bytes.len() < len => {
                assert_eq!(received.end_kind(), Some(io::ErrorKind::ConnectionReset));
            }
            _ => assert!(
                received.is_complete(len),
                "{close:?}: {}",
                received.bytes.len()
            ),
        }
    }
}

/// Shutting down our write side keeps reading working.
#[tokio::test(flavor = "multi_thread")]
async fn half_close_keeps_reading() {
    let len = kib(100);
    let origin = spawn_origin_fn(move |mut stream| async move {
        let mut req = Vec::new();
        _ = stream.read_to_end(&mut req).await;
        assert_eq!(req, REQUEST);
        _ = stream.write_all(&reply(len)).await;
    })
    .await;
    let mut stream = connect(origin.addr).await;
    stream.write_all(REQUEST).await.unwrap();
    stream.shutdown().await.unwrap();
    let received = read_until_end(&mut stream).await;
    assert!(received.is_complete(len));
    received.end.unwrap();
}

/// Writes still go through tokio while receives are posted.
#[tokio::test(flavor = "multi_thread")]
async fn echo_while_receives_are_posted() {
    let origin = spawn_origin_fn(|stream| async move {
        let (mut r, mut w) = stream.into_split();
        _ = tokio::io::copy(&mut r, &mut w).await;
    })
    .await;
    let mut stream = connect(origin.addr).await;
    for i in 0..1000u32 {
        let msg = i.to_be_bytes().repeat(1 + (i as usize % 64));
        stream.write_all(&msg).await.unwrap();
        let mut back = vec![0; msg.len()];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(back, msg);
    }
    stream.shutdown().await.unwrap();
    let rest = read_until_end(&mut stream).await;
    assert!(rest.bytes.is_empty() && rest.end.is_ok());
}

/// A writer waiting in tokio for send buffer space wakes up when the peer
/// resets, even though tokio never reads this socket.
#[tokio::test(flavor = "multi_thread")]
async fn blocked_writer_wakes_on_reset() {
    let origin = spawn_origin_fn(|stream| async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        _ = stream.set_zero_linger();
    })
    .await;
    let mut stream = connect(origin.addr).await;
    let chunk = vec![7; kib(64)];
    let err = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Err(err) = stream.write_all(&chunk).await {
                return err;
            }
        }
    })
    .await
    .expect("the blocked writer never woke up");
    eprintln!("blocked writer woke with: {err}");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerSaw {
    Fin,
    Reset,
}

async fn peer_saw(mut stream: tokio::net::TcpStream) -> PeerSaw {
    let mut buf = [0; 64];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return PeerSaw::Fin,
            Ok(_) => {}
            Err(_) => return PeerSaw::Reset,
        }
    }
}

/// Dropping while receives are posted cancels them and closes gracefully
/// once they completed, without blocking.
#[tokio::test(flavor = "multi_thread")]
async fn drop_with_posted_receives_closes_gracefully() {
    let listener = super::harness::listen();
    let addr = listener.local_addr().unwrap();
    let watches = Watches::default();
    let mut peers = JoinSet::new();
    let mut slowest_drop = Duration::ZERO;
    for _ in 0..2000 {
        let (client, accepted) = tokio::join!(connect(addr), listener.accept());
        peers.spawn(peer_saw(accepted.unwrap().0));
        watches.add(&client);
        let started = Instant::now();
        drop(client);
        slowest_drop = slowest_drop.max(started.elapsed());
    }
    let mut reset = 0;
    while let Some(seen) = peers.join_next().await {
        if seen.unwrap() == PeerSaw::Reset {
            reset += 1;
        }
    }
    watches.all_closed().await;
    eprintln!(
        "drop with posted receives: peers reset={reset} of 2000, slowest drop={slowest_drop:?}"
    );
    assert_eq!(reset, 0, "a drop reset the peer");
    assert!(
        slowest_drop < Duration::from_secs(1),
        "drop blocked for {slowest_drop:?}"
    );
    assert_no_outstanding_receives().await;
}

/// Dropping a pending read and reading again later loses nothing.
#[tokio::test(flavor = "multi_thread")]
async fn dropped_read_future_loses_nothing() {
    let len = kib(32);
    let origin = spawn_origin_fn(move |mut stream| async move {
        let body = reply(len);
        for chunk in body.chunks(kib(1)) {
            _ = stream.write_all(chunk).await;
            tokio::time::sleep(Duration::from_micros(300)).await;
        }
    })
    .await;
    let mut stream = connect(origin.addr).await;
    let mut bytes = Vec::new();
    let mut buf = vec![0; 100];
    let mut dropped = 0;
    loop {
        tokio::select! {
            read = stream.read(&mut buf) => match read.unwrap() {
                0 => break,
                n => bytes.extend_from_slice(&buf[..n]),
            },
            () = tokio::time::sleep(Duration::from_micros(50)) => dropped += 1,
        }
    }
    eprintln!("dropped read futures: {dropped}");
    assert_eq!(bytes, reply(len));
}

/// Thousands of flows dropped at every point around a reset: all of them
/// release their receives and close.
#[tokio::test(flavor = "multi_thread")]
async fn drop_around_reset_stress() {
    let origin = spawn_origin(SIZES[1], Close::Reset).await;
    let addr = origin.addr;
    let watches = Arc::new(Watches::default());
    let mut set = JoinSet::new();
    for i in 0..3000u64 {
        let watches = watches.clone();
        set.spawn(async move {
            let mut stream = connect(addr).await;
            watches.add(&stream);
            match i % 4 {
                0 => {}
                1 => _ = stream.write_all(REQUEST).await,
                2 => {
                    _ = stream.write_all(REQUEST).await;
                    tokio::time::sleep(Duration::from_micros(i % 2000)).await;
                }
                _ => {
                    _ = exchange(&mut stream, Duration::ZERO).await;
                }
            }
            drop(stream);
        });
        if set.len() >= 64 {
            set.join_next().await.unwrap().unwrap();
        }
    }
    while let Some(done) = set.join_next().await {
        done.unwrap();
    }
    watches.all_closed().await;
    assert_no_outstanding_receives().await;
}

/// Many concurrent flows each receive a bulk transfer intact.
#[tokio::test(flavor = "multi_thread")]
async fn many_concurrent_bulk_flows() {
    let len = kib(128);
    let origin = spawn_origin(len, Close::Fin).await;
    let addr = origin.addr;
    let tally = tally(1000, 1000, len, move || async move {
        let mut stream = connect(addr).await;
        exchange(&mut stream, Duration::ZERO).await
    })
    .await;
    assert_eq!(tally.complete, 1000, "{tally}");
}

/// Client ↔ [`IoForwardService`] ↔ an origin that replies and resets, with
/// the egress leg wrapped: the bridge gets every reply, even though it only
/// starts reading after the reply and the reset arrived. The client leg
/// cannot be reset, so the client sees what the bridge got.
#[tokio::test(flavor = "multi_thread")]
async fn forward_keeps_reply_of_resetting_origin() {
    for len in SIZES {
        let origin = spawn_origin(len, Close::Reset).await;
        let proxy = spawn_proxy(origin.addr, true, true).await;
        let proxy_addr = proxy.addr;
        let tally = tally(RUNS, 100, len, move || async move {
            let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
            exchange(&mut client, Duration::ZERO).await
        })
        .await;
        assert_eq!(tally.complete, RUNS, "N={len}: {tally}");
    }
}

/// Both fixes together: the origin resets right after replying while the
/// client is still sending and only reads later. The posted receives keep the
/// reply on the egress leg, and lingering keeps the client leg, which cannot
/// be reset, from being closed with unread input.
#[tokio::test(flavor = "multi_thread")]
async fn forward_with_lingering_keeps_reply_while_client_sends() {
    let len = SIZES[2];
    let origin = spawn_origin(len, Close::Reset).await;
    let origin_addr = origin.addr;
    let proxy = spawn_origin_fn(move |client| async move {
        let egress = TcpStream::new(TokioTcpStream::connect(origin_addr).await.unwrap());
        let egress = PostedRecv::new(egress);
        let svc = IoForwardService::default().with_lingering_close(LingeringClose::default());
        _ = svc.serve(BridgeIo(ServiceInput::new(client), egress)).await;
    })
    .await;
    let proxy_addr = proxy.addr;
    let tally = tally(100, 16, len, move || async move {
        let client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let (mut client_r, mut client_w) = client.into_split();
        client_w.write_all(REQUEST).await.unwrap();
        let writer = tokio::spawn(async move {
            for _ in 0..10 {
                if client_w.write_all(&[1; 1024]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            client_w
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let received = read_until_end(&mut client_r).await;
        drop(writer.await.unwrap());
        received
    })
    .await;
    assert_eq!(tally.complete, 100, "{tally}");
    assert_eq!(tally.ends, [(None, None)], "{tally}");
}

/// How the proxy holds the client leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ingress {
    Plain,
    Posted,
    /// Publishes no [`AbortIo`], so the bridge cannot reset it.
    Unabortable,
}

/// The bridge reflects a reset from the origin to the client, after the
/// reply, with the client leg wrapped or not; a client that reads with
/// posted receives too keeps that reply. A client leg that cannot be reset
/// is closed in order instead, which hides the truncation.
#[tokio::test(flavor = "multi_thread")]
async fn forward_reflects_origin_reset_after_the_reply() {
    let len = SIZES[2];
    let origin = spawn_origin(len, Close::Reset).await;
    for ingress in [Ingress::Plain, Ingress::Posted, Ingress::Unabortable] {
        let origin_addr = origin.addr;
        let proxy = spawn_origin_fn(move |client| async move {
            let egress = TcpStream::new(TokioTcpStream::connect(origin_addr).await.unwrap());
            let egress = PostedRecv::new(egress);
            let svc = IoForwardService::default();
            _ = match ingress {
                Ingress::Plain => svc.serve(BridgeIo(TcpStream::new(client), egress)).await,
                Ingress::Posted => {
                    let client = PostedRecv::new(TcpStream::new(client));
                    svc.serve(BridgeIo(client, egress)).await
                }
                Ingress::Unabortable => {
                    svc.serve(BridgeIo(ServiceInput::new(client), egress)).await
                }
            };
        })
        .await;
        let proxy_addr = proxy.addr;
        let tally = tally(100, 16, len, move || async move {
            let mut client = connect(proxy_addr).await;
            exchange(&mut client, FORCED_DELAY).await
        })
        .await;
        assert_eq!(tally.complete, 100, "{ingress:?}: {tally}");
        let expected_end = if ingress == Ingress::Unabortable {
            (None, None)
        } else {
            (Some(reset_code()), Some(io::ErrorKind::ConnectionReset))
        };
        assert_eq!(tally.ends, [expected_end], "{ingress:?}: {tally}");
    }
}

/// The [`AbortIo`] of the inner stream works through the wrapper: once
/// called, dropping it resets the peer, also while receives are posted.
/// Calling it after the drop does nothing.
#[tokio::test]
async fn an_aborted_posted_recv_resets_its_peer() {
    let listener = super::harness::listen();
    let addr = listener.local_addr().unwrap();
    for abort in [true, false] {
        let (client, accepted) = tokio::join!(connect(addr), listener.accept());
        let peer = tokio::spawn(peer_saw(accepted.unwrap().0));
        let handle = client.extensions().self_get_arc::<AbortIo>().unwrap();
        if abort {
            handle.abort();
        }
        drop(client);
        let expected = if abort { PeerSaw::Reset } else { PeerSaw::Fin };
        assert_eq!(peer.await.unwrap(), expected, "abort={abort}");
        handle.abort();
    }
}

/// The same bridge, for the baseline loss rates: a plain egress stream, with
/// the bridge reading late and in the natural race (an origin that resets
/// right after replying and a bridge that reads right away), and the posted
/// egress in that natural race.
#[cfg(target_os = "windows")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "characterization: prints the baseline loss rate"]
async fn forward_baseline_loses_reply_of_resetting_origin() {
    if !super::harness::characterizing() {
        return;
    }
    for (posted, read_late) in [(false, true), (false, false), (true, false)] {
        for len in SIZES {
            let origin = spawn_origin(len, Close::Reset).await;
            let proxy = spawn_proxy(origin.addr, posted, read_late).await;
            let proxy_addr = proxy.addr;
            let tally = tally(RUNS, 32, len, move || async move {
                let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
                exchange(&mut client, Duration::ZERO).await
            })
            .await;
            eprintln!("forward, posted={posted} read_late={read_late}, N={len}: {tally}");
        }
    }
}

/// A proxy that bridges each client to `origin` with [`IoForwardService`].
///
/// With `read_late` it forwards the request itself and only starts the
/// bridge once the reply and the reset had time to arrive. The client leg
/// cannot be reset, so the client sees what the bridge got.
async fn spawn_proxy(
    origin: std::net::SocketAddr,
    posted: bool,
    read_late: bool,
) -> super::harness::Origin {
    async fn bridge<E: rama_core::io::Io + Unpin + rama_core::extensions::ExtensionsRef>(
        mut client: tokio::net::TcpStream,
        mut egress: E,
        read_late: bool,
    ) {
        if read_late {
            let mut req = vec![0; REQUEST.len()];
            client.read_exact(&mut req).await.unwrap();
            egress.write_all(&req).await.unwrap();
            tokio::time::sleep(FORCED_DELAY).await;
        }
        _ = IoForwardService::default()
            .serve(BridgeIo(ServiceInput::new(client), egress))
            .await;
    }

    spawn_origin_fn(move |client| async move {
        let egress = TcpStream::new(TokioTcpStream::connect(origin).await.unwrap());
        if posted {
            bridge(client, PostedRecv::new(egress), read_late).await;
        } else {
            bridge(client, egress, read_late).await;
        }
    })
    .await
}

/// The layer over a real TCP connector yields a wrapped stream that keeps
/// the connector's extensions.
#[tokio::test(flavor = "multi_thread")]
async fn layer_wraps_tcp_connector_output() {
    let len = SIZES[2];
    let origin = spawn_origin(len, Close::Reset).await;
    let connector = PostedRecvLayer::new().into_layer(TcpConnector::new());
    let connected = Arc::new(AtomicUsize::new(0));
    let mut set = JoinSet::new();
    for _ in 0..100 {
        let connector = connector.clone();
        let connected = connected.clone();
        let addr = origin.addr;
        set.spawn(async move {
            let EstablishedClientConnection { conn, .. } = connector
                .serve(ConnectRequest::new(addr.into()))
                .await
                .unwrap();
            let mut conn: PostedRecv<TcpStream> = conn;
            assert!(conn.extensions().contains::<SocketInfo>());
            assert_eq!(conn.peer_addr().unwrap(), SocketAddress::from(addr));
            connected.fetch_add(1, Ordering::Relaxed);
            exchange(&mut conn, FORCED_DELAY).await
        });
    }
    while let Some(received) = set.join_next().await {
        let received: Received = received.unwrap();
        assert!(received.is_complete(len));
    }
    assert_eq!(connected.load(Ordering::Relaxed), 100);
}

/// A socket already attached to another completion port cannot have its
/// receives posted: `try_with_config` hands it back, and `new` falls back to
/// passing reads through.
#[cfg(target_os = "windows")]
#[tokio::test]
async fn wrapping_a_socket_attached_elsewhere_fails_open() {
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        System::IO::CreateIoCompletionPort,
    };

    let listener = super::harness::listen();
    let (stream, peer) = tokio::join!(
        TokioTcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let (stream, mut peer) = (stream.unwrap(), peer.unwrap().0);
    // SAFETY: creates a new port without borrowing any handle.
    let other = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1) };
    // SAFETY: the socket is open.
    let attached = unsafe { CreateIoCompletionPort(stream.as_raw_socket() as HANDLE, other, 0, 0) };
    assert_eq!(attached, other);

    let (err, stream) = PostedRecv::try_with_config(stream, &PostedRecvConfig::default())
        .expect_err("the socket is attached elsewhere");
    eprintln!("wrapping a socket attached elsewhere: {err}");
    let mut stream = PostedRecv::new(stream);
    assert!(!stream.is_posted());
    peer.write_all(b"hello").await.unwrap();
    let mut buf = [0; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");

    drop(stream);
    // SAFETY: the port is ours.
    let closed = unsafe { CloseHandle(other) };
    assert_ne!(closed, 0);
}

/// The control for everything above: without the wrapper, Windows drops a
/// reply that arrived before the reset, and the read fails with the reset.
#[cfg(target_os = "windows")]
#[tokio::test(flavor = "multi_thread")]
async fn control_plain_stream_loses_reply_before_reset() {
    let len = SIZES[2];
    let origin = spawn_origin(len, Close::Reset).await;
    let addr = origin.addr;
    let tally = tally(20, 20, len, move || async move {
        let mut stream = TokioTcpStream::connect(addr).await.unwrap();
        exchange(&mut stream, FORCED_DELAY).await
    })
    .await;
    assert_eq!(tally.empty, 20, "{tally}");
    assert_eq!(
        tally.ends,
        [(Some(reset_code()), Some(io::ErrorKind::ConnectionReset))],
        "{tally}"
    );
}

/// When the system runs out of buffers for receives, reads pass through
/// tokio until receives can be posted again, without losing order.
#[cfg(target_os = "windows")]
#[tokio::test(flavor = "multi_thread")]
async fn out_of_buffers_falls_back_to_plain_reads() {
    let len = kib(200);
    for failures in [3, usize::MAX] {
        let origin = spawn_origin(len, Close::Fin).await;
        let mut stream = connect(origin.addr).await;
        stream.reader().unwrap().fail_next_posts(failures);
        let received = exchange(&mut stream, Duration::ZERO).await;
        assert!(
            received.is_complete(len),
            "failures={failures}: {}",
            received.bytes.len()
        );
        received.end.unwrap();
    }
}

/// A posted receive completes with whatever arrived, however little. A reply
/// in more parts than there are slots can so outrun a completion thread that
/// lags: a part that arrives while no receive is posted waits in the kernel,
/// where the reset discards it, even though the reply is far smaller than
/// the slots together.
#[cfg(target_os = "windows")]
#[tokio::test(flavor = "multi_thread")]
async fn a_reply_in_more_parts_than_slots_is_exposed_while_completions_lag() {
    const PARTS: usize = 3;
    const PART: usize = 100;
    let origin = spawn_origin_fn(|mut stream| async move {
        _ = async {
            let mut req = vec![0; REQUEST.len()];
            stream.read_exact(&mut req).await?;
            stream.set_nodelay(true)?;
            for part in reply(PARTS * PART).chunks(PART) {
                stream.write_all(part).await?;
                // Each part arrives on its own and completes a receive.
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            super::harness::wait_until_acked(&stream, PARTS * PART).await?;
            stream.set_zero_linger()?;
            drop(stream);
            io::Result::Ok(())
        }
        .await;
    })
    .await;
    for slots in [PARTS - 1, PARTS] {
        let mut stream =
            connect_with(origin.addr, &PostedRecvConfig::default().with_slots(slots)).await;
        // Well past the parts and the reset, which take some 300 ms at most.
        stream
            .reader()
            .unwrap()
            .delay_completions(Duration::from_millis(600));
        let received = exchange(&mut stream, Duration::ZERO).await;
        stream.reader().unwrap().delay_completions(Duration::ZERO);
        assert_eq!(
            received.bytes,
            reply(slots.min(PARTS) * PART),
            "slots={slots}"
        );
        assert_eq!(
            received.end_kind(),
            Some(io::ErrorKind::ConnectionReset),
            "slots={slots}"
        );
    }
}
