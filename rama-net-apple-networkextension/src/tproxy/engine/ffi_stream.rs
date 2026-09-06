//! Per-flow stream bridging a Swift FFI peer to the in-Rust service.
//!
//! Read side drains the per-flow `mpsc` channel (FFI peer → service),
//! firing the read-demand callback when a slot frees. Write side calls the
//! FFI status sink (service → FFI peer), parking on `Paused` until
//! `signal_*_drain` wakes the registered waker, with a backstop deadline.
//!
//! Idle-timeout and cancellation are owned by the forwarder, so this stream
//! does not watch the flow guard.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};

use parking_lot::Mutex;
use rama_core::bytes::{Buf, Bytes};
use rama_net::proxy::BridgeCloseReason;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
    time::Sleep,
};

use super::{
    BridgeDirection, BytesStatusSink, ClosedSink, DemandSink, TcpDeliverStatus, TcpPerFlowSignals,
};

/// First terminal close reason observed by a stream. Per-direction cells label
/// structured close events; one cell shared by both streams labels the Dial9
/// flow row with the first normalized bridge reason.
pub(crate) type CloseReasonCell = Arc<Mutex<Option<BridgeCloseReason>>>;

/// Per-flow byte tallies, indexed by [`BridgeDirection`]; read by the
/// service task to emit the flow's close event.
/// * Ingress: `received` = client→service, `sent` = service→client
/// * Egress:  `received` = upstream→service, `sent` = service→upstream
#[derive(Debug, Default)]
pub(crate) struct TcpFlowByteCounters {
    ingress_received: AtomicU64,
    ingress_sent: AtomicU64,
    egress_received: AtomicU64,
    egress_sent: AtomicU64,
}

impl TcpFlowByteCounters {
    fn received(&self, dir: BridgeDirection) -> &AtomicU64 {
        match dir {
            BridgeDirection::Ingress => &self.ingress_received,
            BridgeDirection::Egress => &self.egress_received,
        }
    }

    fn sent(&self, dir: BridgeDirection) -> &AtomicU64 {
        match dir {
            BridgeDirection::Ingress => &self.ingress_sent,
            BridgeDirection::Egress => &self.egress_sent,
        }
    }

    /// `(received, sent)` for the given direction.
    pub(crate) fn snapshot(&self, dir: BridgeDirection) -> (u64, u64) {
        (
            self.received(dir).load(Ordering::Relaxed),
            self.sent(dir).load(Ordering::Relaxed),
        )
    }

    /// Total bytes both directions; progress signal for the idle backstop.
    pub(crate) fn total(&self) -> u64 {
        self.ingress_received.load(Ordering::Relaxed)
            + self.ingress_sent.load(Ordering::Relaxed)
            + self.egress_received.load(Ordering::Relaxed)
            + self.egress_sent.load(Ordering::Relaxed)
    }
}

pub(crate) struct FfiBridgeStream {
    // ── read side (FFI peer → service) ──
    rx: mpsc::Receiver<Bytes>,
    /// Current chunk; advanced as consumed, cleared when empty.
    read_cursor: Option<Bytes>,
    on_read_demand: DemandSink,
    read_failed: Option<Arc<std::sync::atomic::AtomicBool>>,

    // ── write side (service → FFI peer) ──
    sink: BytesStatusSink,
    /// Maximum slice handed to one Rust→Swift sink callback. The Swift
    /// callback copies this borrowed slice before returning, so bounding it
    /// here prevents one large `AsyncWrite` buffer from bypassing the pump's
    /// configured byte budget.
    write_chunk_limit: usize,
    on_closed: ClosedSink,
    closed_fired: bool,
    paused_drain_max_wait: Duration,
    /// Reaps a write parked on `Paused` whose drain never arrives. Armed fresh
    /// at the start of each pause episode, cleared on every `Poll::Ready`.
    paused_backstop: Option<Pin<Box<Sleep>>>,
    /// Drain generation when `paused_backstop` was armed; if it has since
    /// advanced (Swift drained), the next pause is a new episode and re-arms
    /// fresh, so a stale deadline can't fire against it.
    paused_backstop_gen: u64,

    // ── shared per-flow state ──
    signals: Arc<TcpPerFlowSignals>,
    counters: Arc<TcpFlowByteCounters>,
    close_reason: CloseReasonCell,
    flow_close_reason: CloseReasonCell,
    direction: BridgeDirection,
}

impl FfiBridgeStream {
    #[expect(clippy::too_many_arguments, reason = "per-flow wiring; one call site")]
    pub(crate) fn new(
        rx: mpsc::Receiver<Bytes>,
        sink: BytesStatusSink,
        on_read_demand: DemandSink,
        on_closed: ClosedSink,
        signals: Arc<TcpPerFlowSignals>,
        counters: Arc<TcpFlowByteCounters>,
        close_reason: CloseReasonCell,
        flow_close_reason: CloseReasonCell,
        direction: BridgeDirection,
        paused_drain_max_wait: Duration,
        write_chunk_limit: usize,
    ) -> Self {
        debug_assert!(write_chunk_limit > 0, "write chunk limit must be non-zero");
        let write_chunk_limit = write_chunk_limit.max(1);
        Self {
            rx,
            read_cursor: None,
            on_read_demand,
            read_failed: None,
            sink,
            write_chunk_limit,
            on_closed,
            closed_fired: false,
            paused_drain_max_wait,
            paused_backstop: None,
            paused_backstop_gen: 0,
            signals,
            counters,
            close_reason,
            flow_close_reason,
            direction,
        }
    }

    /// Record this direction's and the whole bridge's first terminal reason.
    fn record_reason(&self, reason: BridgeCloseReason) {
        self.flow_close_reason.lock().get_or_insert(reason);
        self.close_reason.lock().get_or_insert(reason);
    }

    fn read_eof_reason(&self) -> BridgeCloseReason {
        match self.direction {
            BridgeDirection::Ingress => BridgeCloseReason::PeerEofLeft,
            BridgeDirection::Egress => BridgeCloseReason::PeerEofRight,
        }
    }

    fn read_error_reason(&self) -> BridgeCloseReason {
        match self.direction {
            BridgeDirection::Ingress => BridgeCloseReason::ReadErrorLeft,
            BridgeDirection::Egress => BridgeCloseReason::ReadErrorRight,
        }
    }

    fn write_error_reason(&self) -> BridgeCloseReason {
        match self.direction {
            BridgeDirection::Ingress => BridgeCloseReason::WriteErrorLeft,
            BridgeDirection::Egress => BridgeCloseReason::WriteErrorRight,
        }
    }

    pub(crate) fn with_read_error_flag(mut self, flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.read_failed = Some(flag);
        self
    }
}

impl AsyncRead for FfiBridgeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // All fields are `Unpin`, so `get_mut` is sound.
        let this = self.get_mut();
        loop {
            if let Some(chunk) = this.read_cursor.as_mut() {
                let n = chunk.len().min(buf.remaining());
                if n > 0 {
                    buf.put_slice(&chunk[..n]);
                    chunk.advance(n);
                    this.counters
                        .received(this.direction)
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                if chunk.is_empty() {
                    this.read_cursor = None;
                }
                return Poll::Ready(Ok(()));
            }

            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(bytes)) => {
                    // Slot freed: complete the drain-and-clear half of the
                    // pause handshake under the same gate used by the
                    // producer's publish-and-recheck half. Invoke the callback
                    // after releasing the gate so a synchronous callback may
                    // safely retry the enqueue path.
                    let should_signal_demand = {
                        let _pause_gate = this.signals.pause_gate(this.direction).lock();
                        this.signals
                            .paused(this.direction)
                            .swap(false, Ordering::AcqRel)
                    };
                    if should_signal_demand {
                        (this.on_read_demand)();
                    }
                    // Skip empty chunks (a 0-byte read would look like EOF).
                    if bytes.is_empty() {
                        continue;
                    }
                    this.read_cursor = Some(bytes);
                }
                // Sender dropped → EOF.
                Poll::Ready(None) => {
                    if this
                        .read_failed
                        .as_ref()
                        .is_some_and(|flag| flag.load(Ordering::Acquire))
                    {
                        this.record_reason(this.read_error_reason());
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "transparent proxy: ffi peer read failed",
                        )));
                    }
                    this.record_reason(this.read_eof_reason());
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for FfiBridgeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Register before calling the sink: `signal_*_drain` can only fire
        // after the sink returns `Paused`, so registering first can't lose
        // it. A spurious wake on `Accepted` just costs one poll.
        this.signals.drain(this.direction).register(cx.waker());

        let chunk = &buf[..buf.len().min(this.write_chunk_limit)];
        match (this.sink)(chunk) {
            TcpDeliverStatus::Accepted => {
                this.counters
                    .sent(this.direction)
                    .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                // Progress: end the pause episode so the next one arms fresh.
                this.paused_backstop = None;
                Poll::Ready(Ok(chunk.len()))
            }
            // Peer gone → broken pipe; the forwarder tears the flow down.
            TcpDeliverStatus::Closed => {
                this.paused_backstop = None;
                this.record_reason(this.write_error_reason());
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "transparent proxy: ffi peer closed the write side",
                )))
            }
            TcpDeliverStatus::Paused => {
                // Park for a drain wake or the backstop deadline. Arm a fresh
                // deadline each pause episode (first pause, or first after a
                // drain) so a stale timer from an earlier episode can't fire.
                let max_wait = this.paused_drain_max_wait;
                let cur_gen = this.signals.drain_generation(this.direction);
                if this.paused_backstop.is_none() || cur_gen != this.paused_backstop_gen {
                    this.paused_backstop_gen = cur_gen;
                    this.paused_backstop = Some(Box::pin(tokio::time::sleep(max_wait)));
                }
                let backstop = this
                    .paused_backstop
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(max_wait)));
                match backstop.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.paused_backstop = None;
                        this.record_reason(BridgeCloseReason::PausedTimeout);
                        // Drain never came: fire close (the service may
                        // ignore the error) and fail the write.
                        if !this.closed_fired {
                            this.closed_fired = true;
                            (this.on_closed)();
                        }
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "transparent proxy: paused-drain backstop",
                        )))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // nothing buffered; bytes go straight to the sink
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Fire the "write done" callback once (gated against teardown).
        if !this.closed_fired {
            this.closed_fired = true;
            (this.on_closed)();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for FfiBridgeStream {
    fn drop(&mut self) {
        // Force-close (dropped before a clean `poll_shutdown`) still fires
        // the gated "write done" callback, once.
        if !self.closed_fired {
            self.closed_fired = true;
            (self.on_closed)();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize};
    use std::task::{Context, Wake, Waker};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const TEST_WRITE_CHUNK_LIMIT: usize = rama_utils::octets::kib(16);

    /// Waker that counts how many times it was woken.
    struct CountWaker(AtomicUsize);
    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn count_waker() -> (Arc<CountWaker>, Waker) {
        let w = Arc::new(CountWaker(AtomicUsize::new(0)));
        let waker: Waker = w.clone().into();
        (w, waker)
    }

    fn accept_sink() -> BytesStatusSink {
        Arc::new(|_: &[u8]| TcpDeliverStatus::Accepted)
    }
    fn const_sink(status: TcpDeliverStatus) -> BytesStatusSink {
        Arc::new(move |_: &[u8]| status)
    }
    /// Sink whose status is read from a shared `AtomicU8` the test flips.
    fn dynamic_sink(code: Arc<AtomicU8>) -> BytesStatusSink {
        Arc::new(move |_: &[u8]| TcpDeliverStatus::from_ffi_u8(code.load(Ordering::SeqCst)))
    }
    fn noop() -> DemandSink {
        Arc::new(|| {})
    }
    fn counter_cb(c: Arc<AtomicUsize>) -> Arc<dyn Fn() + Send + Sync + 'static> {
        Arc::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        })
    }

    #[expect(clippy::too_many_arguments)]
    fn stream(
        rx: mpsc::Receiver<Bytes>,
        sink: BytesStatusSink,
        demand: DemandSink,
        closed: ClosedSink,
        dir: BridgeDirection,
        max_wait: Duration,
        signals: Arc<TcpPerFlowSignals>,
        counters: Arc<TcpFlowByteCounters>,
    ) -> FfiBridgeStream {
        FfiBridgeStream::new(
            rx,
            sink,
            demand,
            closed,
            signals,
            counters,
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None)),
            dir,
            max_wait,
            TEST_WRITE_CHUNK_LIMIT,
        )
    }

    /// Stream with sane defaults + inspectable directional and flow cells.
    fn stream_with_reasons(
        rx: mpsc::Receiver<Bytes>,
        sink: BytesStatusSink,
        dir: BridgeDirection,
        max_wait: Duration,
    ) -> (FfiBridgeStream, CloseReasonCell, CloseReasonCell) {
        let direction_cell: CloseReasonCell = Arc::new(Mutex::new(None));
        let flow_cell: CloseReasonCell = Arc::new(Mutex::new(None));
        let s = FfiBridgeStream::new(
            rx,
            sink,
            noop(),
            noop(),
            Arc::new(TcpPerFlowSignals::new()),
            Arc::new(TcpFlowByteCounters::default()),
            direction_cell.clone(),
            flow_cell.clone(),
            dir,
            max_wait,
            TEST_WRITE_CHUNK_LIMIT,
        );
        (s, direction_cell, flow_cell)
    }

    #[tokio::test]
    async fn read_reports_eof_when_sender_dropped() {
        let (tx, rx) = mpsc::channel::<Bytes>(4);
        let mut s = stream(
            rx,
            accept_sink(),
            noop(),
            noop(),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
            Arc::new(TcpPerFlowSignals::new()),
            Arc::new(TcpFlowByteCounters::default()),
        );
        drop(tx);
        let mut buf = [0u8; 8];
        // `read` resolves immediately to 0 (EOF) once the channel closes.
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn read_delivers_chunk_and_counts_received() {
        let (tx, rx) = mpsc::channel::<Bytes>(4);
        tx.try_send(Bytes::from_static(b"hello")).unwrap();
        drop(tx);
        let counters = Arc::new(TcpFlowByteCounters::default());
        let mut s = stream(
            rx,
            accept_sink(),
            noop(),
            noop(),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
            Arc::new(TcpPerFlowSignals::new()),
            counters.clone(),
        );
        let mut buf = [0u8; 8];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(counters.snapshot(BridgeDirection::Ingress).0, 5);
    }

    #[tokio::test]
    async fn read_fires_demand_once_when_peer_paused() {
        let (tx, rx) = mpsc::channel::<Bytes>(4);
        tx.try_send(Bytes::from_static(b"x")).unwrap();
        let demand_calls = Arc::new(AtomicUsize::new(0));
        let signals = Arc::new(TcpPerFlowSignals::new());
        let mut s = stream(
            rx,
            accept_sink(),
            counter_cb(demand_calls.clone()),
            noop(),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
            signals.clone(),
            Arc::new(TcpFlowByteCounters::default()),
        );
        signals
            .paused(BridgeDirection::Ingress)
            .store(true, Ordering::Release);
        let mut buf = [0u8; 8];
        let _ = s.read(&mut buf).await.unwrap();
        assert_eq!(demand_calls.load(Ordering::SeqCst), 1, "demand fired once");
        assert!(
            !signals
                .paused(BridgeDirection::Ingress)
                .load(Ordering::Acquire),
            "paused flag cleared"
        );
    }

    #[tokio::test]
    async fn write_accepted_counts_sent() {
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let counters = Arc::new(TcpFlowByteCounters::default());
        let mut s = stream(
            rx,
            accept_sink(),
            noop(),
            noop(),
            BridgeDirection::Egress,
            Duration::from_secs(60),
            Arc::new(TcpPerFlowSignals::new()),
            counters.clone(),
        );
        s.write_all(b"abcd").await.unwrap();
        assert_eq!(counters.snapshot(BridgeDirection::Egress).1, 4);
    }

    #[tokio::test]
    async fn write_splits_multi_limit_buffer_before_each_sink_callback() {
        const LIMIT: usize = 7;
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let sink_observed = observed.clone();
        let sink: BytesStatusSink = Arc::new(move |chunk: &[u8]| {
            sink_observed.lock().push(chunk.len());
            TcpDeliverStatus::Accepted
        });
        let counters = Arc::new(TcpFlowByteCounters::default());
        let mut s = FfiBridgeStream::new(
            rx,
            sink,
            noop(),
            noop(),
            Arc::new(TcpPerFlowSignals::new()),
            counters.clone(),
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None)),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
            LIMIT,
        );

        let payload = [0xA5; LIMIT * 3 + 2];
        s.write_all(&payload).await.unwrap();

        assert_eq!(&*observed.lock(), &[LIMIT, LIMIT, LIMIT, 2]);
        assert_eq!(
            counters.snapshot(BridgeDirection::Ingress).1,
            payload.len() as u64
        );
    }

    #[tokio::test]
    async fn paused_oversized_write_retries_the_same_bounded_prefix_after_drain() {
        const LIMIT: usize = 3;
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let code = Arc::new(AtomicU8::new(TcpDeliverStatus::Paused as u8));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let sink_code = code.clone();
        let sink_observed = observed.clone();
        let sink: BytesStatusSink = Arc::new(move |chunk: &[u8]| {
            sink_observed.lock().push(chunk.to_vec());
            TcpDeliverStatus::from_ffi_u8(sink_code.load(Ordering::SeqCst))
        });
        let signals = Arc::new(TcpPerFlowSignals::new());
        let mut s = FfiBridgeStream::new(
            rx,
            sink,
            noop(),
            noop(),
            signals.clone(),
            Arc::new(TcpFlowByteCounters::default()),
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None)),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
            LIMIT,
        );
        let (_w, waker) = count_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Pin::new(&mut s).poll_write(&mut cx, b"abcdef").is_pending());
        signals.drain(BridgeDirection::Ingress).wake();
        code.store(TcpDeliverStatus::Accepted as u8, Ordering::SeqCst);
        assert!(matches!(
            Pin::new(&mut s).poll_write(&mut cx, b"abcdef"),
            Poll::Ready(Ok(LIMIT))
        ));

        assert_eq!(&*observed.lock(), &[b"abc".to_vec(), b"abc".to_vec()]);
    }

    #[tokio::test]
    async fn write_closed_is_broken_pipe() {
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let mut s = stream(
            rx,
            const_sink(TcpDeliverStatus::Closed),
            noop(),
            noop(),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
            Arc::new(TcpPerFlowSignals::new()),
            Arc::new(TcpFlowByteCounters::default()),
        );
        let err = s.write_all(b"abc").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn write_paused_parks_then_drain_signal_wakes_and_retry_succeeds() {
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let code = Arc::new(AtomicU8::new(TcpDeliverStatus::Paused as u8));
        let signals = Arc::new(TcpPerFlowSignals::new());
        let mut s = stream(
            rx,
            dynamic_sink(code.clone()),
            noop(),
            noop(),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
            signals.clone(),
            Arc::new(TcpFlowByteCounters::default()),
        );
        let (w, waker) = count_waker();
        let mut cx = Context::from_waker(&waker);

        // First poll: sink Paused → Pending, our waker registered, not yet woken.
        let p = Pin::new(&mut s).poll_write(&mut cx, b"abc");
        assert!(p.is_pending());
        assert_eq!(w.0.load(Ordering::SeqCst), 0);

        // `signal_*_drain` wakes the registered waker.
        signals.drain(BridgeDirection::Ingress).wake();
        assert_eq!(w.0.load(Ordering::SeqCst), 1, "drain woke our waker");

        // Capacity freed → retry is accepted.
        code.store(TcpDeliverStatus::Accepted as u8, Ordering::SeqCst);
        let p = Pin::new(&mut s).poll_write(&mut cx, b"abc");
        assert!(matches!(p, Poll::Ready(Ok(3))));
    }

    #[tokio::test(start_paused = true)]
    async fn write_paused_backstop_times_out() {
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let mut s = stream(
            rx,
            const_sink(TcpDeliverStatus::Paused),
            noop(),
            noop(),
            BridgeDirection::Ingress,
            Duration::from_millis(50),
            Arc::new(TcpPerFlowSignals::new()),
            Arc::new(TcpFlowByteCounters::default()),
        );
        let (_w, waker) = count_waker();
        let mut cx = Context::from_waker(&waker);
        // Arms the backstop.
        assert!(Pin::new(&mut s).poll_write(&mut cx, b"abc").is_pending());
        tokio::time::advance(Duration::from_millis(60)).await;
        // Backstop elapsed → write errors out so the forwarder reaps the flow.
        match Pin::new(&mut s).poll_write(&mut cx, b"abc") {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected TimedOut, got {other:?}"),
        }
    }

    /// A near-elapsed backstop from an earlier pause episode must not fire
    /// against a fresh pause: after a drain, the next pause re-arms a fresh
    /// deadline rather than inheriting the stale one.
    #[tokio::test(start_paused = true)]
    async fn write_paused_backstop_rearms_after_drain() {
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let signals = Arc::new(TcpPerFlowSignals::new());
        let mut s = stream(
            rx,
            const_sink(TcpDeliverStatus::Paused),
            noop(),
            noop(),
            BridgeDirection::Ingress,
            Duration::from_millis(100),
            signals.clone(),
            Arc::new(TcpFlowByteCounters::default()),
        );
        let (_w, waker) = count_waker();
        let mut cx = Context::from_waker(&waker);

        // Episode 1: pause, arm the backstop; advance most of the way to its
        // deadline without firing.
        assert!(Pin::new(&mut s).poll_write(&mut cx, b"a").is_pending());
        tokio::time::advance(Duration::from_millis(80)).await;

        // Swift drained this direction (progress). A write abandoned mid-pause
        // would never observe this as an `Accepted`; a fresh write re-pauses.
        signals.note_drain(BridgeDirection::Ingress);

        // Episode 2: still Paused. The backstop must re-arm fresh (100ms from
        // now), not reuse episode 1's 80ms-elapsed deadline.
        assert!(Pin::new(&mut s).poll_write(&mut cx, b"b").is_pending());
        tokio::time::advance(Duration::from_millis(80)).await;
        assert!(
            Pin::new(&mut s).poll_write(&mut cx, b"b").is_pending(),
            "fresh pause episode must not inherit the earlier episode's near-elapsed deadline",
        );

        // The fresh deadline still fires once genuinely exceeded.
        tokio::time::advance(Duration::from_millis(40)).await;
        match Pin::new(&mut s).poll_write(&mut cx, b"b") {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected TimedOut on the fresh deadline, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn shutdown_fires_closed_once_and_drop_does_not_double() {
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let closed_calls = Arc::new(AtomicUsize::new(0));
        let mut s = stream(
            rx,
            accept_sink(),
            noop(),
            counter_cb(closed_calls.clone()),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
            Arc::new(TcpPerFlowSignals::new()),
            Arc::new(TcpFlowByteCounters::default()),
        );
        s.shutdown().await.unwrap();
        assert_eq!(closed_calls.load(Ordering::SeqCst), 1);
        drop(s);
        assert_eq!(
            closed_calls.load(Ordering::SeqCst),
            1,
            "drop must not re-fire"
        );
    }

    #[tokio::test]
    async fn drop_without_shutdown_fires_closed() {
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let closed_calls = Arc::new(AtomicUsize::new(0));
        let s = stream(
            rx,
            accept_sink(),
            noop(),
            counter_cb(closed_calls.clone()),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
            Arc::new(TcpPerFlowSignals::new()),
            Arc::new(TcpFlowByteCounters::default()),
        );
        drop(s);
        assert_eq!(closed_calls.load(Ordering::SeqCst), 1);
    }

    // ── close-reason recording (so a write failure isn't logged as clean EOF) ──

    #[tokio::test]
    async fn read_eof_records_peer_eof_left() {
        let (tx, rx) = mpsc::channel::<Bytes>(4);
        drop(tx);
        let (mut s, cell, flow_cell) = stream_with_reasons(
            rx,
            accept_sink(),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
        );
        let mut buf = [0u8; 8];
        let _ = s.read(&mut buf).await.unwrap();
        assert_eq!(*cell.lock(), Some(BridgeCloseReason::PeerEofLeft));
        assert_eq!(*flow_cell.lock(), Some(BridgeCloseReason::PeerEofLeft));
    }

    #[tokio::test]
    async fn egress_read_eof_records_peer_eof_right() {
        let (tx, rx) = mpsc::channel::<Bytes>(4);
        drop(tx);
        let (mut s, cell, flow_cell) = stream_with_reasons(
            rx,
            accept_sink(),
            BridgeDirection::Egress,
            Duration::from_secs(60),
        );
        let mut buf = [0u8; 8];
        let _ = s.read(&mut buf).await.unwrap();
        assert_eq!(*cell.lock(), Some(BridgeCloseReason::PeerEofRight));
        assert_eq!(*flow_cell.lock(), Some(BridgeCloseReason::PeerEofRight));
    }

    #[tokio::test]
    async fn read_error_is_reported_after_buffered_bytes() {
        let (tx, rx) = mpsc::channel::<Bytes>(4);
        tx.try_send(Bytes::from_static(b"tail")).unwrap();
        let failed = Arc::new(AtomicBool::new(true));
        drop(tx);
        let (s, cell, flow_cell) = stream_with_reasons(
            rx,
            accept_sink(),
            BridgeDirection::Egress,
            Duration::from_secs(60),
        );
        let mut s = s.with_read_error_flag(failed);
        let mut tail = [0_u8; 4];
        s.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"tail");

        let mut next = [0_u8; 1];
        let error = s.read(&mut next).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(*cell.lock(), Some(BridgeCloseReason::ReadErrorRight));
        assert_eq!(*flow_cell.lock(), Some(BridgeCloseReason::ReadErrorRight));
    }

    #[tokio::test]
    async fn ingress_write_closed_records_write_error_left() {
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let (mut s, cell, flow_cell) = stream_with_reasons(
            rx,
            const_sink(TcpDeliverStatus::Closed),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
        );
        assert!(s.write_all(b"abc").await.is_err());
        assert_eq!(*cell.lock(), Some(BridgeCloseReason::WriteErrorLeft));
        assert_eq!(*flow_cell.lock(), Some(BridgeCloseReason::WriteErrorLeft));
    }

    #[tokio::test]
    async fn egress_write_closed_records_write_error_right() {
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let (mut s, cell, flow_cell) = stream_with_reasons(
            rx,
            const_sink(TcpDeliverStatus::Closed),
            BridgeDirection::Egress,
            Duration::from_secs(60),
        );
        assert!(s.write_all(b"abc").await.is_err());
        assert_eq!(*cell.lock(), Some(BridgeCloseReason::WriteErrorRight));
        assert_eq!(*flow_cell.lock(), Some(BridgeCloseReason::WriteErrorRight));
    }

    #[tokio::test(start_paused = true)]
    async fn backstop_records_paused_timeout() {
        let (_tx, rx) = mpsc::channel::<Bytes>(4);
        let (mut s, cell, flow_cell) = stream_with_reasons(
            rx,
            const_sink(TcpDeliverStatus::Paused),
            BridgeDirection::Ingress,
            Duration::from_millis(50),
        );
        let (_w, waker) = count_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut s).poll_write(&mut cx, b"abc").is_pending());
        tokio::time::advance(Duration::from_millis(60)).await;
        assert!(matches!(
            Pin::new(&mut s).poll_write(&mut cx, b"abc"),
            Poll::Ready(Err(_))
        ));
        assert_eq!(*cell.lock(), Some(BridgeCloseReason::PausedTimeout));
        assert_eq!(*flow_cell.lock(), Some(BridgeCloseReason::PausedTimeout));
    }

    #[tokio::test]
    async fn shared_flow_reason_keeps_first_terminal_event_across_directions() {
        let (ingress_tx, ingress_rx) = mpsc::channel::<Bytes>(1);
        let (egress_tx, egress_rx) = mpsc::channel::<Bytes>(1);
        let flow_cell: CloseReasonCell = Arc::new(Mutex::new(None));
        let ingress_cell: CloseReasonCell = Arc::new(Mutex::new(None));
        let egress_cell: CloseReasonCell = Arc::new(Mutex::new(None));
        let mut ingress = FfiBridgeStream::new(
            ingress_rx,
            accept_sink(),
            noop(),
            noop(),
            Arc::new(TcpPerFlowSignals::new()),
            Arc::new(TcpFlowByteCounters::default()),
            ingress_cell.clone(),
            flow_cell.clone(),
            BridgeDirection::Ingress,
            Duration::from_secs(60),
            TEST_WRITE_CHUNK_LIMIT,
        );
        let mut egress = FfiBridgeStream::new(
            egress_rx,
            accept_sink(),
            noop(),
            noop(),
            Arc::new(TcpPerFlowSignals::new()),
            Arc::new(TcpFlowByteCounters::default()),
            egress_cell.clone(),
            flow_cell.clone(),
            BridgeDirection::Egress,
            Duration::from_secs(60),
            TEST_WRITE_CHUNK_LIMIT,
        )
        .with_read_error_flag(Arc::new(AtomicBool::new(true)));

        drop(egress_tx);
        let mut byte = [0_u8; 1];
        assert_eq!(
            egress.read(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        drop(ingress_tx);
        assert_eq!(ingress.read(&mut byte).await.unwrap(), 0);

        assert_eq!(*egress_cell.lock(), Some(BridgeCloseReason::ReadErrorRight));
        assert_eq!(*ingress_cell.lock(), Some(BridgeCloseReason::PeerEofLeft));
        assert_eq!(
            *flow_cell.lock(),
            Some(BridgeCloseReason::ReadErrorRight),
            "the first normalized terminal reason must win for the whole bridge"
        );
    }
}
