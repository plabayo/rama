//! A tunnel socket driven by an input-chosen sequence of peer, socket, carrier and clock
//! operations, checking its accounting after every step and its release at the end.

#![expect(
    clippy::panic,
    reason = "a broken invariant must fail the fuzz case or the regression test"
)]

use std::{
    collections::VecDeque,
    io::IoSliceMut,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use parking_lot::Mutex;
use rama_core::{
    ServiceInput,
    bytes::Bytes,
    extensions::ExtensionsRef as _,
    rt::{Executor, future::now_or_never},
};
use rama_http::{
    datagram::{
        HttpDatagramSession, NativeDatagramChannel, NativeDatagrams, NativeRecvError,
        NativeSendError, NativeSendPolicy, NativeSendReady, SessionEvent,
    },
    proto::capsule::CapsuleType,
};
use rama_net::address::SocketAddress;
use rama_udp::{DatagramMetadata, DatagramSender as _, DatagramSocket as _, SendDatagram};
use rama_utils::rate::Rate;
use tokio::{io::DuplexStream, runtime::Runtime, sync::Notify, time::timeout};

use super::{
    CLOSE_GRACE, ConnectUdpClose, ConnectUdpSender, ConnectUdpSocket, ConnectUdpSocketConfig,
    ConnectUdpStats, Shared, TunnelAccounting, session_config,
};
use crate::connect_udp::{DatagramRate, PrincipalBudget, TunnelBudget};

type Io = ServiceInput<DuplexStream>;

const LOCAL: SocketAddress = SocketAddress::local_ipv4(4433);
const PEER: SocketAddress = SocketAddress::local_ipv4(443);

/// Larger than everything one case can write, so a peer write never waits for room.
const DUPLEX: usize = 1024 * 1024;
const MAX_OPS: usize = 64;
const MAX_DATAGRAM: usize = 1500;
const MAX_OVERSIZED: usize = 2;
const OVERSIZED: usize = 70 * 1024;
/// How long one peer operation may take on the paused clock.
const STEP: Duration = Duration::from_millis(1);

thread_local! {
    static RUNTIME: Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap_or_else(|error| panic!("fuzz runtime: {error}"));
}

/// Run one case: never panics unless an invariant breaks.
#[cfg_attr(
    not(fuzzing),
    expect(
        unreachable_pub,
        reason = "also compiled for the harness regression tests"
    )
)]
pub fn tunnel_state(input: &[u8]) {
    _ = run(input);
}

/// What one case reached, so fixed regressions can prove their path ran.
#[derive(Debug, Default, Clone, Copy)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the regression tests read what a case reached")
)]
pub(crate) struct Coverage {
    pub(crate) stats: ConnectUdpStats,
    /// UDP payloads the peer received back, over either carrier.
    pub(crate) peer_received: u64,
    /// Socket sends that were accepted.
    pub(crate) accepted: u64,
    /// Socket sends left pending and dropped.
    pub(crate) abandoned: u64,
    pub(crate) closed: Option<ConnectUdpClose>,
}

pub(crate) fn run(input: &[u8]) -> Coverage {
    RUNTIME.with(|runtime| runtime.block_on(case(input)))
}

/// A native carrier whose limit and readiness the input decides.
#[derive(Clone, Default)]
struct FuzzNative(Arc<NativeState>);

#[derive(Default)]
struct NativeState {
    max: AtomicUsize,
    /// 0: takes what fits, 1: always full and never ready, 2: refuses everything as too large.
    mode: AtomicU8,
    delivered: AtomicU64,
    /// Notified when the mode changes, so a send waiting for room looks again.
    room: Arc<Notify>,
    incoming: Mutex<VecDeque<Bytes>>,
    waker: Mutex<Option<Waker>>,
    ended: AtomicBool,
}

impl FuzzNative {
    fn push(&self, datagram: Bytes) {
        self.0.incoming.lock().push_back(datagram);
        self.wake();
    }

    fn end(&self) {
        self.0.ended.store(true, Ordering::Release);
        self.wake();
    }

    fn wake(&self) {
        if let Some(waker) = self.0.waker.lock().take() {
            waker.wake();
        }
    }
}

impl NativeDatagramChannel for FuzzNative {
    fn max_payload_size(&self) -> Option<usize> {
        Some(self.0.max.load(Ordering::Relaxed))
    }

    fn send(&self, payload: Bytes, _policy: NativeSendPolicy) -> Result<(), NativeSendError> {
        let max = self.0.max.load(Ordering::Relaxed);
        match self.0.mode.load(Ordering::Relaxed) {
            1 => Err(NativeSendError::Full),
            2 => Err(NativeSendError::TooLarge { max: 0 }),
            _ if payload.len() > max => Err(NativeSendError::TooLarge { max }),
            _ => {
                self.0.delivered.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
    }

    fn send_ready(&self) -> NativeSendReady {
        let state = self.0.clone();
        NativeSendReady::new(async move {
            loop {
                let mut notified = std::pin::pin!(state.room.clone().notified_owned());
                notified.as_mut().enable();
                if state.mode.load(Ordering::Relaxed) != 1 {
                    return;
                }
                notified.await;
            }
        })
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        if let Some(datagram) = self.0.incoming.lock().pop_front() {
            return Poll::Ready(Ok(Some(datagram)));
        }
        if self.0.ended.load(Ordering::Acquire) {
            return Poll::Ready(Ok(None));
        }
        *self.0.waker.lock() = Some(cx.waker().clone());
        Poll::Pending
    }

    fn dropped(&self) -> u64 {
        0
    }
}

/// Reads the input front to back; past its end every read is zero.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn byte(&mut self) -> u8 {
        let Some((&byte, rest)) = self.0.split_first() else {
            return 0;
        };
        self.0 = rest;
        byte
    }
}

struct Case {
    socket: Option<ConnectUdpSocket<Io>>,
    senders: [Option<ConnectUdpSender>; 2],
    peer: Option<HttpDatagramSession<Io>>,
    native: Option<FuzzNative>,
    /// The tunnel's state, held so its stats stay readable; nothing in it acts on drop.
    shared: Arc<Shared>,
    idle: Duration,
    accepted: u64,
    accepted_bytes: u64,
    abandoned: u64,
    peer_capsule_received: u64,
    oversized: usize,
    closed: Option<ConnectUdpClose>,
}

impl Case {
    fn stats(&self) -> ConnectUdpStats {
        self.shared.stats.snapshot()
    }
}

fn setup(reader: &mut Reader<'_>) -> Case {
    let flags = reader.byte();
    let shape = reader.byte();
    let (proxy_end, peer_end) = tokio::io::duplex(DUPLEX);
    let proxy_end = ServiceInput::new(proxy_end);
    let native = (flags & 1 != 0).then(|| {
        let native = FuzzNative::default();
        native
            .0
            .max
            .store(100 + usize::from(shape) * 8, Ordering::Relaxed);
        proxy_end
            .extensions()
            .insert(NativeDatagrams::new(native.clone()));
        native
    });
    let mut budget = (flags & 2 != 0).then(TunnelBudget::new);
    if let Some(tunnel) = &mut budget {
        if flags & 4 != 0 {
            tunnel.set_to_target(DatagramRate::new(Rate::per_sec(2), Rate::per_sec(4096)));
            tunnel.set_to_client(DatagramRate::new(Rate::per_sec(2), Rate::per_sec(4096)));
        }
        if flags & 8 != 0 {
            tunnel.set_quota(4096);
        }
        tunnel.set_unanswered(4, 2048);
    }
    let principal = (flags & 16 != 0).then(|| {
        Arc::new(
            PrincipalBudget::new()
                .with_quota(8192, Duration::from_secs(60))
                .spend(),
        )
    });
    let idle = Duration::from_secs(1 + u64::from(shape >> 6));
    let mut config = ConnectUdpSocketConfig::default()
        .with_queue(std::num::NonZeroUsize::MIN.saturating_add(usize::from(shape & 7)))
        .with_idle_timeout(idle);
    if flags & 32 != 0 {
        config.set_min_payload(1200);
    }
    let socket = ConnectUdpSocket::with_accounting(
        &Executor::default(),
        HttpDatagramSession::with_config(proxy_end, session_config()),
        LOCAL,
        PEER,
        config,
        TunnelAccounting { budget, principal },
    );
    let shared = socket.shared.clone();
    let peer = HttpDatagramSession::with_config(ServiceInput::new(peer_end), session_config());
    Case {
        socket: Some(socket),
        senders: [None, None],
        peer: Some(peer),
        native,
        shared,
        idle,
        accepted: 0,
        accepted_bytes: 0,
        abandoned: 0,
        peer_capsule_received: 0,
        oversized: 0,
        closed: None,
    }
}

/// A datagram with the context encoding `kind` chooses and `len` payload bytes.
fn encoded(kind: u8, len: usize, fill: u8) -> Bytes {
    let mut datagram = match kind % 4 {
        0 => vec![0x00],
        1 => vec![0x40, 0x00],
        2 => vec![0x02],
        // A Context ID that ends inside itself carries nothing more.
        _ => return Bytes::from_static(b"\x40"),
    };
    datagram.resize(datagram.len() + len, fill);
    Bytes::from(datagram)
}

/// Let the pump, the carrier and the peer make the progress they can, without moving time.
async fn settle() {
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
}

async fn case(input: &[u8]) -> Coverage {
    let mut reader = Reader(input);
    let mut case = setup(&mut reader);
    let mut last_stats = case.stats();
    for operation in input
        .get(2..)
        .unwrap_or_default()
        .as_chunks::<4>()
        .0
        .iter()
        .take(MAX_OPS)
    {
        let [op, a, b, c] = *operation;
        let len = usize::from(u16::from_le_bytes([b, c])) % MAX_DATAGRAM;
        step(&mut case, op, a, b, len).await;
        settle().await;
        let stats = case.stats();
        check(&case, &stats, &last_stats);
        last_stats = stats;
    }
    teardown(case).await
}

async fn step(case: &mut Case, op: u8, a: u8, b: u8, len: usize) {
    match op % 14 {
        0 => {
            if let Some(peer) = &mut case.peer
                && timeout(STEP, peer.send_datagram(encoded(a, len, b)))
                    .await
                    .is_err()
            {
                // A write that cannot finish leaves its capsule half sent: that peer is done.
                case.peer = None;
            }
        }
        1 => {
            if let Some(native) = &case.native {
                native.push(encoded(a, len, b));
            }
        }
        2 => {
            if case.oversized < MAX_OVERSIZED
                && let Some(peer) = &mut case.peer
            {
                case.oversized += 1;
                // Context 0 above the UDP limit aborts the tunnel; another context is skipped.
                let mut value = vec![if a & 1 == 0 { 0x00 } else { 0x02 }];
                value.resize(OVERSIZED, b);
                if timeout(
                    STEP,
                    peer.send_capsule(CapsuleType::DATAGRAM, Bytes::from(value)),
                )
                .await
                .is_err()
                {
                    case.peer = None;
                }
            }
        }
        3 => {
            if let Some(peer) = &mut case.peer {
                let ty = CapsuleType::new(0x1000 + u64::from(a)).unwrap_or(CapsuleType::DATAGRAM);
                if timeout(STEP, peer.send_capsule(ty, Bytes::from(vec![b; len % 64])))
                    .await
                    .is_err()
                {
                    case.peer = None;
                }
            }
        }
        4 => send(case, a, b, len),
        5 => receive(case),
        6 => {
            let advance = if b & 1 == 0 {
                Duration::from_millis(u64::from(a) * 10)
            } else {
                case.idle + Duration::from_secs(1)
            };
            tokio::time::sleep(advance).await;
        }
        7 => {
            if let Some(peer) = &mut case.peer
                && timeout(STEP, peer.close()).await.is_err()
            {
                case.peer = None;
            }
        }
        8 => {
            case.peer = None;
            if let Some(native) = &case.native {
                native.end();
            }
        }
        9 => case.socket = None,
        10 => case.senders[usize::from(a & 1)] = None,
        11 => drain_peer(case),
        // A send right after a receive, before the pump runs: a receive that closed the
        // tunnel must refuse it.
        13 => {
            receive(case);
            note_close(case);
            send(case, a, b, len);
        }
        _ => {
            if let Some(native) = &case.native {
                native
                    .0
                    .max
                    .store(100 + usize::from(a) * 8, Ordering::Relaxed);
                native.0.mode.store(b % 3, Ordering::Relaxed);
                native.0.room.notify_waiters();
                native.wake();
            }
        }
    }
    note_close(case);
}

/// Remember the close reason, which never changes once set.
fn note_close(case: &mut Case) {
    if let Some(socket) = &case.socket {
        let reason = socket.close_reason();
        if case.closed.is_some() && reason != case.closed {
            panic!("the close reason changed: {:?} -> {reason:?}", case.closed);
        }
        case.closed = reason;
    }
}

/// One poll of a send: accepted, refused, or left pending and dropped, which must hold nothing.
fn send(case: &mut Case, a: u8, b: u8, len: usize) {
    let index = usize::from(a & 1);
    if case.senders[index].is_none() {
        let Some(socket) = &case.socket else {
            return;
        };
        case.senders[index] = Some(socket.create_sender());
    }
    let Some(sender) = &mut case.senders[index] else {
        return;
    };
    let len = len.min(MAX_DATAGRAM);
    // Now and then one above any limit.
    let len = if a & 0x80 != 0 { 70 * 1024 } else { len };
    let payload = vec![b; len];
    let mut cx = Context::from_waker(Waker::noop());
    let closed = case.closed.is_some();
    match sender.poll_send(&mut cx, &SendDatagram::new(PEER, &payload)) {
        Poll::Ready(Ok(())) => {
            if closed {
                panic!(
                    "a send was accepted after the tunnel closed ({:?})",
                    case.closed
                );
            }
            case.accepted += 1;
            case.accepted_bytes += len as u64;
        }
        Poll::Ready(Err(_)) => {}
        // A send that would wait is cancelled; its sender stays for the next one, as a dropped
        // send future leaves it. Dropping a sender is an operation of its own.
        Poll::Pending => case.abandoned += 1,
    }
}

/// One poll of a receive.
fn receive(case: &mut Case) {
    let Some(socket) = &mut case.socket else {
        return;
    };
    let mut buffer = [0u8; MAX_DATAGRAM];
    let mut buffers = [IoSliceMut::new(&mut buffer)];
    let mut metadata = [DatagramMetadata::empty()];
    let mut cx = Context::from_waker(Waker::noop());
    if let Poll::Ready(Ok(count)) = socket.poll_recv(&mut cx, &mut buffers, &mut metadata)
        && count != 1
    {
        panic!("a receive filed {count} datagrams into one buffer");
    }
}

/// Count what the peer received back on the capsule carrier, without waiting.
fn drain_peer(case: &mut Case) {
    let Some(peer) = &mut case.peer else {
        return;
    };
    for _ in 0..MAX_OPS {
        match now_or_never(peer.recv()) {
            Some(Ok(Some(SessionEvent::Datagram { payload, .. }))) => {
                if payload.first() == Some(&0x00) {
                    case.peer_capsule_received += 1;
                }
            }
            Some(Ok(Some(_))) => {}
            Some(Ok(None) | Err(_)) => {
                case.peer = None;
                return;
            }
            None => return,
        }
    }
}

fn delivered(case: &Case) -> u64 {
    case.peer_capsule_received
        + case
            .native
            .as_ref()
            .map_or(0, |native| native.0.delivered.load(Ordering::Relaxed))
}

fn check(case: &Case, stats: &ConnectUdpStats, last: &ConnectUdpStats) {
    let dropped = stats.dropped_unknown_context
        + stats.dropped_oversize
        + stats.dropped_rate_limited
        + stats.dropped_over_quota
        + stats.dropped_unanswered;
    if stats.received != stats.forwarded + dropped {
        panic!("received does not partition: {stats:?}");
    }
    if stats.native + stats.capsule != stats.received {
        panic!("carriers do not add up to received: {stats:?}");
    }
    if stats.forwarded_bytes > stats.received_bytes {
        panic!("forwarded more bytes than received: {stats:?}");
    }
    let taken = to_client(stats);
    if taken > case.accepted
        || stats.returned_bytes + stats.returned_dropped_bytes > case.accepted_bytes
    {
        panic!(
            "more counted toward the client than accepted ({} payloads, {} bytes): {stats:?}",
            case.accepted, case.accepted_bytes
        );
    }
    if delivered(case) > stats.returned {
        panic!(
            "the peer got {} back, {} returned",
            delivered(case),
            stats.returned
        );
    }
    // Cumulative counters only grow.
    if stats.received < last.received
        || stats.received_bytes < last.received_bytes
        || taken < to_client(last)
        || stats.returned_dropped_bytes < last.returned_dropped_bytes
    {
        panic!("a counter fell: {last:?} -> {stats:?}");
    }
}

fn to_client(stats: &ConnectUdpStats) -> u64 {
    stats.returned
        + stats.returned_dropped_rate_limited
        + stats.returned_dropped_over_quota
        + stats.returned_dropped_too_large
        + stats.returned_dropped_unsent
}

/// Drop every handle and prove the tunnel is released and every accepted payload counted once.
async fn teardown(mut case: Case) -> Coverage {
    case.senders = [None, None];
    case.socket = None;
    // The peer stays only as long as the tunnel may still write to it; dropping it ends that.
    case.peer = None;
    if let Some(native) = &case.native {
        native.end();
    }
    // Held here alone once every handle and the pump are gone: its stats are final then.
    let alone = timeout(case.idle + 4 * CLOSE_GRACE, async {
        while Arc::strong_count(&case.shared) > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let last = case.stats();
    if alone.is_err() {
        panic!("the tunnel outlives every handle: {last:?}");
    }
    let peer_received = delivered(&case);
    let released = Arc::downgrade(&case.shared);
    drop(case.shared);
    if released.strong_count() != 0 {
        panic!("the tunnel's state is still referenced");
    }
    if to_client(&last) != case.accepted
        || last.returned_bytes + last.returned_dropped_bytes != case.accepted_bytes
    {
        panic!(
            "accepted {} payloads ({} bytes), counted {}: {last:?}",
            case.accepted,
            case.accepted_bytes,
            to_client(&last)
        );
    }
    let metrics = tokio::runtime::Handle::current().metrics();
    for _ in 0..64 {
        if metrics.num_alive_tasks() == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    if metrics.num_alive_tasks() != 0 {
        panic!("{} tasks outlive the case", metrics.num_alive_tasks());
    }
    Coverage {
        stats: last,
        peer_received,
        accepted: case.accepted,
        abandoned: case.abandoned,
        closed: case.closed,
    }
}

#[cfg(test)]
mod tests;
