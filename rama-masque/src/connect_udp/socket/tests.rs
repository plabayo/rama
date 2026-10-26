use super::*;
use rama_core::ServiceInput;
use rama_http::{
    datagram::{DatagramTransport, NativeDatagramChannel, NativeRecvError, NativeSendReady},
    proto::capsule::CapsuleType,
};
use rama_udp::{DatagramSenderExt as _, DatagramSocketExt as _};
use std::sync::atomic::AtomicUsize;
use tokio::io::{DuplexStream, ReadBuf};

type Io = ServiceInput<DuplexStream>;

const LOCAL: SocketAddress = SocketAddress::local_ipv4(4433);
const PEER: SocketAddress = SocketAddress::local_ipv4(443);

/// A socket on one end of an in-memory capsule carrier and a raw session on the other.
fn pair(config: ConnectUdpSocketConfig) -> (ConnectUdpSocket<Io>, HttpDatagramSession<Io>) {
    let (a, b) = tokio::io::duplex(kib(256));
    let socket = ConnectUdpSocket::new(
        &Executor::default(),
        HttpDatagramSession::with_config(ServiceInput::new(a), session_config()),
        LOCAL,
        PEER,
        config,
    );
    let peer = HttpDatagramSession::with_config(ServiceInput::new(b), session_config());
    (socket, peer)
}

fn kib(n: usize) -> usize {
    n * 1024
}

fn context0(payload: &[u8]) -> Bytes {
    let mut encoded = vec![0x00];
    encoded.extend_from_slice(payload);
    Bytes::from(encoded)
}

async fn recv(
    socket: &mut ConnectUdpSocket<Io>,
) -> Result<(Vec<u8>, DatagramMetadata), DatagramError> {
    let mut buffer = [0u8; 2048];
    let metadata = socket.recv(&mut buffer).await?;
    Ok((buffer[..metadata.len].to_vec(), metadata))
}

#[tokio::test]
async fn payloads_travel_with_context_zero_both_ways() {
    let (mut socket, mut peer) = pair(ConnectUdpSocketConfig::default());
    socket
        .create_sender()
        .send(SendDatagram::new(PEER, b"ping"))
        .await
        .unwrap();
    let Some(SessionEvent::Datagram { payload, transport }) = peer.recv().await.unwrap() else {
        panic!("no datagram");
    };
    assert_eq!(payload, context0(b"ping"));
    assert_eq!(transport, DatagramTransport::Capsule);

    // Empty UDP payloads are data too.
    peer.send_datagram(context0(b"")).await.unwrap();
    peer.send_datagram(context0(b"pong")).await.unwrap();
    let (empty, _) = recv(&mut socket).await.unwrap();
    assert!(empty.is_empty());
    let (pong, metadata) = recv(&mut socket).await.unwrap();
    assert_eq!(pong, b"pong");
    assert_eq!(metadata.peer, PEER);
    assert_eq!(metadata.local, LOCAL);
    assert!(!metadata.truncated);
}

#[tokio::test]
async fn other_and_truncated_contexts_are_dropped() {
    let (mut socket, mut peer) = pair(ConnectUdpSocketConfig::default());
    peer.send_datagram(Bytes::from_static(b"\x02other"))
        .await
        .unwrap();
    peer.send_datagram(Bytes::from_static(b"\x40"))
        .await
        .unwrap();
    // A non-minimal encoding of zero is still the UDP context.
    peer.send_datagram(Bytes::from_static(b"\x40\x00ok"))
        .await
        .unwrap();
    // The first payload delivered is the UDP context's: the other two were dropped.
    let (ok, _) = recv(&mut socket).await.unwrap();
    assert_eq!(ok, b"ok");
}

#[tokio::test]
async fn short_receive_buffers_report_truncation() {
    let (mut socket, mut peer) = pair(ConnectUdpSocketConfig::default());
    peer.send_datagram(context0(b"0123456789")).await.unwrap();
    let mut buffer = [0u8; 4];
    let metadata = socket.recv(&mut buffer).await.unwrap();
    assert!(metadata.truncated);
    assert_eq!(metadata.len, 4);
    assert_eq!(metadata.original_len, 10);
}

#[tokio::test]
async fn oversized_context_zero_payloads_abort_the_stream() {
    // Within the capsule decoder's limit, and above it (only the prefix is seen).
    for len in [MAX_UDP_PAYLOAD + 1, kib(70)] {
        let (mut socket, mut peer) = pair(ConnectUdpSocketConfig::default());
        peer.send_capsule(CapsuleType::DATAGRAM, context0(&vec![7; len]))
            .await
            .unwrap();
        assert!(recv(&mut socket).await.is_err(), "{len}");
        assert_eq!(socket.close_reason(), Some(ConnectUdpClose::Failed));
        // Dropping the aborted carrier ends the in-memory stream for the peer.
        assert!(!matches!(peer.recv().await, Ok(Some(_))), "{len}");
    }
}

#[tokio::test]
async fn oversized_payloads_of_other_contexts_are_skipped() {
    let (mut socket, mut peer) = pair(ConnectUdpSocketConfig::default());
    let mut other = vec![0x02];
    other.extend(std::iter::repeat_n(7u8, kib(70)));
    peer.send_capsule(CapsuleType::DATAGRAM, Bytes::from(other))
        .await
        .unwrap();
    peer.send_datagram(context0(b"after")).await.unwrap();
    let (after, _) = recv(&mut socket).await.unwrap();
    assert_eq!(after, b"after");
}

#[tokio::test]
async fn sends_are_bound_to_the_peer_and_the_udp_limit() {
    let (socket, _peer) = pair(ConnectUdpSocketConfig::default());
    let mut sender = socket.create_sender();
    let foreign = SocketAddress::local_ipv4(9);
    assert!(matches!(
        sender.send(SendDatagram::new(foreign, b"x")).await,
        Err(DatagramError::ForeignDestination(address)) if address == foreign
    ));
    let too_large = vec![0; MAX_UDP_PAYLOAD + 1];
    assert!(matches!(
        sender.send(SendDatagram::new(PEER, &too_large)).await,
        Err(DatagramError::PayloadTooLarge { max, .. }) if max == MAX_UDP_PAYLOAD
    ));
    assert_eq!(socket.max_payload(), MAX_UDP_PAYLOAD);
    assert!(!socket.capabilities().send_ecn);
    assert!(socket.capabilities().may_fragment);
}

#[tokio::test]
async fn a_finished_peer_closes_the_socket() {
    let (mut socket, mut peer) = pair(ConnectUdpSocketConfig::default());
    peer.close().await.unwrap();
    assert!(matches!(
        recv(&mut socket).await,
        Err(DatagramError::Closed)
    ));
    assert_eq!(socket.close_reason(), Some(ConnectUdpClose::Closed));
}

#[tokio::test(start_paused = true)]
async fn an_idle_tunnel_closes_at_the_local_bound() {
    let config = ConnectUdpSocketConfig::default().with_idle_timeout(Duration::from_secs(120));
    let (mut socket, _peer) = pair(config);
    let received = tokio::spawn(async move {
        let result = recv(&mut socket).await;
        (result.map(drop), socket.close_reason())
    });
    tokio::time::sleep(Duration::from_secs(121)).await;
    let (result, reason) = received.await.unwrap();
    assert!(matches!(result, Err(DatagramError::Closed)));
    assert_eq!(reason, Some(ConnectUdpClose::Idle));
}

#[tokio::test(start_paused = true)]
async fn forwarded_payloads_keep_the_tunnel_open() {
    let config = ConnectUdpSocketConfig::default().with_idle_timeout(Duration::from_secs(120));
    let (mut socket, mut peer) = pair(config);
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(60)).await;
        peer.send_datagram(context0(b"tick")).await.unwrap();
        let (tick, _) = recv(&mut socket).await.unwrap();
        assert_eq!(tick, b"tick");
    }
    assert_eq!(socket.close_reason(), None);
}

#[tokio::test(start_paused = true)]
async fn dropped_datagrams_do_not_count_as_progress() {
    let config = ConnectUdpSocketConfig::default().with_idle_timeout(Duration::from_secs(120));
    let (mut socket, mut peer) = pair(config);
    let received = tokio::spawn(async move {
        let result = recv(&mut socket).await;
        (result.map(drop), socket.close_reason())
    });
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_secs(40)).await;
        // Unknown contexts are dropped: the tunnel still idles out.
        _ = peer.send_datagram(Bytes::from_static(b"\x02x")).await;
    }
    let (result, reason) = received.await.unwrap();
    assert!(result.is_err());
    assert_eq!(reason, Some(ConnectUdpClose::Idle));
}

#[tokio::test]
async fn v4_mapped_addresses_are_reported_and_accepted_as_ipv4() {
    let (a, b) = tokio::io::duplex(kib(64));
    let mapped: SocketAddress = "[::ffff:127.0.0.1]:443".parse().unwrap();
    let socket = ConnectUdpSocket::new(
        &Executor::default(),
        HttpDatagramSession::with_config(ServiceInput::new(a), session_config()),
        LOCAL,
        mapped,
        ConnectUdpSocketConfig::default(),
    );
    let mut peer = HttpDatagramSession::with_config(ServiceInput::new(b), session_config());
    assert_eq!(socket.peer_addr().unwrap(), PEER);
    socket
        .create_sender()
        .send(SendDatagram::new(PEER, b"canonical"))
        .await
        .unwrap();
    let Some(SessionEvent::Datagram { payload, .. }) = peer.recv().await.unwrap() else {
        panic!("no datagram");
    };
    assert_eq!(payload, context0(b"canonical"));
}

/// A socket whose carrier holds a few bytes only, so its queue fills while the peer is idle.
fn narrow_pair() -> (ConnectUdpSocket<Io>, HttpDatagramSession<Io>) {
    let (a, b) = tokio::io::duplex(16);
    let config = ConnectUdpSocketConfig::default().with_queue(NonZeroUsize::MIN);
    let socket = ConnectUdpSocket::new(
        &Executor::default(),
        HttpDatagramSession::with_config(ServiceInput::new(a), session_config()),
        LOCAL,
        PEER,
        config,
    );
    let peer = HttpDatagramSession::with_config(ServiceInput::new(b), session_config());
    (socket, peer)
}

/// Send until a send stays pending: the carrier and the queue are full.
async fn fill(sender: &mut ConnectUdpSender) -> usize {
    let payload = [1u8; 64];
    let mut sent = 0;
    loop {
        let send = sender.send(SendDatagram::new(PEER, &payload));
        if tokio::time::timeout(Duration::from_millis(50), send)
            .await
            .is_err()
        {
            return sent;
        }
        sent += 1;
    }
}

#[tokio::test]
async fn a_full_queue_applies_backpressure_until_drained() {
    let (socket, mut peer) = narrow_pair();
    let mut sender = socket.create_sender();
    let accepted = fill(&mut sender).await;
    assert!(accepted >= 1, "the queue takes at least one payload");

    // An independent handle is held back too, and woken by the drain on its own.
    let mut other = socket.create_sender();
    let blocked = tokio::spawn(async move {
        other
            .send(SendDatagram::new(PEER, b"after the drain"))
            .await
            .map(|()| other)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!blocked.is_finished());

    let mut delivered = Vec::new();
    while delivered.last().map(Bytes::as_ref) != Some(&context0(b"after the drain")[..]) {
        let Some(SessionEvent::Datagram { payload, .. }) = peer.recv().await.unwrap() else {
            panic!("no datagram");
        };
        delivered.push(payload);
    }
    blocked.await.unwrap().unwrap();
    // Every accepted payload arrives once, in order, before the one sent after the drain;
    // the send cancelled by `fill` neither arrived nor was duplicated.
    assert_eq!(delivered.len(), accepted + 1);
    assert!(
        delivered[..accepted]
            .iter()
            .all(|payload| *payload == context0(&[1; 64]))
    );
}

#[tokio::test]
async fn closing_wakes_blocked_senders_with_closed() {
    let (socket, peer) = narrow_pair();
    let mut sender = socket.create_sender();
    fill(&mut sender).await;
    let blocked = tokio::spawn(async move { sender.send(SendDatagram::new(PEER, b"never")).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!blocked.is_finished());
    drop(peer);
    let result = tokio::time::timeout(Duration::from_secs(5), blocked)
        .await
        .expect("the blocked sender is woken")
        .unwrap();
    assert!(matches!(result, Err(DatagramError::Closed)), "{result:?}");
}

/// Receive on the raw peer until the stream ends or fails.
async fn until_the_stream_ends(peer: &mut HttpDatagramSession<Io>) {
    while let Ok(Some(_)) = peer.recv().await {}
}

#[tokio::test(start_paused = true)]
async fn a_carrier_that_stops_taking_data_idles_out_and_is_released() {
    // The peer never reads: the carrier fills and the pump's send stalls.
    let (mut socket, mut peer) = narrow_pair();
    let mut sender = socket.create_sender();
    fill(&mut sender).await;
    let blocked = tokio::spawn(async move { sender.send(SendDatagram::new(PEER, b"stuck")).await });
    let started = Instant::now();
    let received = tokio::time::timeout(Duration::from_secs(150), recv(&mut socket))
        .await
        .expect("the idle bound ends a stalled send");
    assert!(matches!(received, Err(DatagramError::Closed)));
    assert_eq!(socket.close_reason(), Some(ConnectUdpClose::Idle));
    assert!(started.elapsed() <= Duration::from_secs(121));
    assert!(matches!(blocked.await.unwrap(), Err(DatagramError::Closed)));
    // The graceful close cannot finish either: after its grace the carrier is dropped.
    tokio::time::timeout(Duration::from_secs(10), until_the_stream_ends(&mut peer))
        .await
        .expect("the carrier is released");
}

#[tokio::test(start_paused = true)]
async fn inbound_payloads_extend_the_deadline_of_a_stalled_carrier() {
    let (mut socket, mut peer) = narrow_pair();
    let mut sender = socket.create_sender();
    fill(&mut sender).await;
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(60)).await;
        // The peer still sends, it only stopped reading.
        peer.send_datagram(context0(b"inbound")).await.unwrap();
        let (inbound, _) = recv(&mut socket).await.unwrap();
        assert_eq!(inbound, b"inbound");
    }
    assert_eq!(socket.close_reason(), None);
    assert!(matches!(
        recv(&mut socket).await,
        Err(DatagramError::Closed)
    ));
    assert_eq!(socket.close_reason(), Some(ConnectUdpClose::Idle));
}

#[tokio::test(start_paused = true)]
async fn a_peer_fin_wakes_a_sender_blocked_on_a_stalled_carrier() {
    let (mut socket, peer) = narrow_pair();
    let (mut peer_sender, mut peer_receiver) = peer.split();
    let mut sender = socket.create_sender();
    fill(&mut sender).await;
    let blocked = tokio::spawn(async move { sender.send(SendDatagram::new(PEER, b"stuck")).await });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!blocked.is_finished());
    // The peer finishes its direction but keeps (and never drains) the other one.
    peer_sender.close().await.unwrap();
    assert!(matches!(
        recv(&mut socket).await,
        Err(DatagramError::Closed)
    ));
    assert_eq!(socket.close_reason(), Some(ConnectUdpClose::Closed));
    let woken = tokio::time::timeout(Duration::from_secs(1), blocked)
        .await
        .expect("the blocked sender is woken by the close")
        .unwrap();
    assert!(matches!(woken, Err(DatagramError::Closed)));
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Ok(Some(_)) = peer_receiver.recv().await {}
    })
    .await
    .expect("the carrier is released within the grace");
}

/// A native carrier that is permanently full and never signals room.
struct FullNative;

impl NativeDatagramChannel for FullNative {
    fn max_payload_size(&self) -> Option<usize> {
        Some(1200)
    }

    fn send(&self, _payload: Bytes, _policy: NativeSendPolicy) -> Result<(), NativeSendError> {
        Err(NativeSendError::Full)
    }

    fn send_ready(&self) -> NativeSendReady {
        NativeSendReady::new(std::future::pending())
    }

    fn poll_recv(&self, _cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        Poll::Pending
    }

    fn dropped(&self) -> u64 {
        0
    }
}

#[tokio::test(start_paused = true)]
async fn a_permanently_full_native_carrier_idles_out() {
    let (a, _b) = tokio::io::duplex(kib(64));
    let a = ServiceInput::new(a);
    a.extensions().insert(NativeDatagrams::new(FullNative));
    let mut socket = ConnectUdpSocket::new(
        &Executor::default(),
        HttpDatagramSession::with_config(a, session_config()),
        LOCAL,
        PEER,
        ConnectUdpSocketConfig::default().with_queue(NonZeroUsize::MIN),
    );
    let mut sender = socket.create_sender();
    fill(&mut sender).await;
    let blocked = tokio::spawn(async move { sender.send(SendDatagram::new(PEER, b"stuck")).await });
    let received = tokio::time::timeout(Duration::from_secs(150), recv(&mut socket))
        .await
        .expect("the idle bound ends a native wait");
    assert!(matches!(received, Err(DatagramError::Closed)));
    assert_eq!(socket.close_reason(), Some(ConnectUdpClose::Idle));
    assert!(matches!(blocked.await.unwrap(), Err(DatagramError::Closed)));
}

/// A carrier that never takes a byte, reporting when it is dropped.
struct Stuck(Arc<AtomicBool>);

impl Drop for Stuck {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl AsyncRead for Stuck {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Stuck {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn a_stalled_close_releases_the_carrier_after_its_grace() {
    let dropped = Arc::new(AtomicBool::new(false));
    // Held for the whole test: only an abort can release the carrier.
    let socket = ConnectUdpSocket::new(
        &Executor::default(),
        HttpDatagramSession::with_config(
            ServiceInput::new(Stuck(dropped.clone())),
            session_config(),
        ),
        LOCAL,
        PEER,
        ConnectUdpSocketConfig::default(),
    );
    socket
        .create_sender()
        .send(SendDatagram::new(PEER, b"never written"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(121)).await;
    assert_eq!(socket.close_reason(), Some(ConnectUdpClose::Idle));
    assert!(!dropped.load(Ordering::Acquire), "the close gets its grace");
    tokio::time::sleep(CLOSE_GRACE).await;
    assert!(
        dropped.load(Ordering::Acquire),
        "then the carrier is dropped"
    );
}

/// A native carrier with a payload limit the test changes.
#[derive(Clone, Default)]
struct ShrinkingNative(Arc<AtomicUsize>);

impl NativeDatagramChannel for ShrinkingNative {
    fn max_payload_size(&self) -> Option<usize> {
        Some(self.0.load(Ordering::Relaxed))
    }

    fn send(&self, payload: Bytes, _policy: NativeSendPolicy) -> Result<(), NativeSendError> {
        let max = self.0.load(Ordering::Relaxed);
        if payload.len() > max {
            return Err(NativeSendError::TooLarge { max });
        }
        Ok(())
    }

    fn send_ready(&self) -> NativeSendReady {
        NativeSendReady::now()
    }

    fn poll_recv(&self, _cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        Poll::Pending
    }

    fn dropped(&self) -> u64 {
        0
    }
}

#[tokio::test]
async fn a_limit_below_the_owners_minimum_fails_typed_and_closes() {
    let native = ShrinkingNative::default();
    native.0.store(1301, Ordering::Relaxed);
    let (a, _b) = tokio::io::duplex(kib(64));
    let a = ServiceInput::new(a);
    a.extensions().insert(NativeDatagrams::new(native.clone()));
    let mut socket = ConnectUdpSocket::new(
        &Executor::default(),
        HttpDatagramSession::with_config(a, session_config()),
        LOCAL,
        PEER,
        ConnectUdpSocketConfig::default().with_min_payload(1200),
    );
    let mut sender = socket.create_sender();
    sender
        .send(SendDatagram::new(PEER, &[1; 1200]))
        .await
        .unwrap();
    assert_eq!(socket.max_payload(), 1300);

    // The outer path shrank: one byte of Context ID leaves 1199 for UDP.
    native.0.store(1200, Ordering::Relaxed);
    let error = sender
        .send(SendDatagram::new(PEER, &[1; 1000]))
        .await
        .unwrap_err();
    let DatagramError::Io(error) = error else {
        panic!("{error:?}");
    };
    assert_eq!(
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<ConnectUdpCapacityError>()),
        Some(&ConnectUdpCapacityError {
            max_payload: 1199,
            min_payload: 1200,
        })
    );
    assert_eq!(socket.close_reason(), Some(ConnectUdpClose::Capacity));
    assert!(matches!(
        recv(&mut socket).await,
        Err(DatagramError::Closed)
    ));
}

#[tokio::test]
async fn without_a_minimum_a_small_limit_only_drops_large_payloads() {
    let native = ShrinkingNative::default();
    native.0.store(600, Ordering::Relaxed);
    let (a, _b) = tokio::io::duplex(kib(64));
    let a = ServiceInput::new(a);
    a.extensions().insert(NativeDatagrams::new(native));
    let socket = ConnectUdpSocket::new(
        &Executor::default(),
        HttpDatagramSession::with_config(a, session_config()),
        LOCAL,
        PEER,
        ConnectUdpSocketConfig::default(),
    );
    let mut sender = socket.create_sender();
    sender
        .send(SendDatagram::new(PEER, &[1; 500]))
        .await
        .unwrap();
    assert!(matches!(
        sender.send(SendDatagram::new(PEER, &[1; 700])).await,
        Err(DatagramError::PayloadTooLarge { max: 599, .. })
    ));
    assert_eq!(socket.close_reason(), None);
}

#[tokio::test(start_paused = true)]
async fn a_week_of_sparse_traffic_and_connection_churn_releases_every_owner() {
    let (mut socket, mut peer) = pair(ConnectUdpSocketConfig::default());
    let owner = Arc::downgrade(&socket.shared);
    for minute in 0..(7 * 24 * 60) {
        tokio::time::advance(Duration::from_secs(60)).await;
        peer.send_datagram(context0(&[(minute % 256) as u8]))
            .await
            .unwrap();
        assert_eq!(recv(&mut socket).await.unwrap().0, [(minute % 256) as u8]);
        assert_eq!(socket.close_reason(), None);
    }
    drop(socket);
    drop(peer);
    tokio::time::sleep(CLOSE_GRACE + Duration::from_secs(1)).await;
    assert!(
        owner.upgrade().is_none(),
        "long-lived socket retained a task/owner"
    );

    for _ in 0..256 {
        let (mut socket, mut peer) = pair(ConnectUdpSocketConfig::default());
        let owner = Arc::downgrade(&socket.shared);
        peer.send_datagram(context0(b"last")).await.unwrap();
        peer.close().await.unwrap();
        assert_eq!(recv(&mut socket).await.unwrap().0, b"last");
        assert!(matches!(
            recv(&mut socket).await,
            Err(DatagramError::Closed)
        ));
        drop(socket);
        drop(peer);
        tokio::time::sleep(CLOSE_GRACE + Duration::from_secs(1)).await;
        assert!(
            owner.upgrade().is_none(),
            "closed association retained an owner"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_failed_destination_keeps_the_shorter_idle_deadline() {
    let idle = Duration::from_millis(50);
    let (socket, peer) = pair(ConnectUdpSocketConfig::default().with_idle_timeout(idle));
    drop(peer);
    let mut sender = socket.create_sender();
    sender
        .send(SendDatagram::new(PEER, b"reply"))
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert!(matches!(
        sender.send(SendDatagram::new(PEER, b"later")).await,
        Err(DatagramError::Closed)
    ));
    assert_eq!(socket.close_reason(), None);
    tokio::time::sleep(idle).await;
    tokio::task::yield_now().await;
    assert_eq!(socket.close_reason(), Some(ConnectUdpClose::Idle));
}

#[tokio::test(start_paused = true)]
async fn discarded_contexts_yield_before_reaching_a_later_udp_payload() {
    let (mut socket, mut peer) = pair(ConnectUdpSocketConfig::default());
    for _ in 0..64 {
        peer.send_datagram(Bytes::from_static(b"\x02ignored"))
            .await
            .unwrap();
    }
    peer.send_datagram(context0(b"after")).await.unwrap();
    // Start a fresh executor turn so the carrier's own cooperative budget cannot
    // stand in for the socket's bound on immediately available skipped contexts.
    tokio::task::yield_now().await;
    let mut receiving = pin!(recv(&mut socket));
    assert!(rama_core::futures::poll!(receiving.as_mut()).is_pending());
    assert_eq!(receiving.await.unwrap().0, b"after");
}

#[tokio::test(start_paused = true)]
async fn discarded_contexts_yield_and_do_not_extend_the_idle_deadline() {
    let (mut socket, mut peer) = pair(ConnectUdpSocketConfig::default());
    for _ in 0..128 {
        peer.send_datagram(Bytes::from_static(b"\x02ignored"))
            .await
            .unwrap();
    }
    let mut buffer = [0; 64];
    let mut receiving = pin!(socket.recv(&mut buffer));
    assert!(rama_core::futures::poll!(receiving.as_mut()).is_pending());
    let started = Instant::now();
    assert!(matches!(receiving.await, Err(DatagramError::Closed)));
    assert_eq!(started.elapsed(), Duration::from_mins(2));
}
