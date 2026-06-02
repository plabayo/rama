//! Channel/callback-backed per-flow stream that replaces the
//! `tokio::io::duplex` + `run_tcp_bridge` task pair.
//!
//! Each TCP flow has two of these (one per direction-pair):
//!
//! * the **read** side drains the per-flow `mpsc` channel that the FFI
//!   peer (Swift) feeds via `on_*_bytes[_owned]` — i.e. FFI peer →
//!   service — firing the read-demand callback when a channel slot frees;
//! * the **write** side hands bytes straight to the FFI status sink
//!   (`on_server_bytes` / `on_write_to_egress`) — i.e. service → FFI peer
//!   — parking on `Paused` until the matching `signal_*_drain` wakes the
//!   registered waker (or a backstop timer fires).
//!
//! Removing the duplex deletes a whole `BytesMut` per direction plus two
//! copies per chunk; removing the bridge task deletes a per-flow read
//! buffer and two task hops per chunk. Idle-timeout and shutdown-on-cancel
//! are owned one level up by the forwarder's select loop, so this stream
//! deliberately does NOT watch the flow guard itself.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};

use rama_core::bytes::{Buf, Bytes};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
    time::Sleep,
};

use super::{
    BridgeDirection, BytesStatusSink, ClosedSink, DemandSink, TcpDeliverStatus, TcpPerFlowSignals,
};

/// Per-flow byte tallies, indexed by [`BridgeDirection`]. Shared (via
/// `Arc`) between the two streams that increment them and the service
/// task that reads them when emitting the flow's close event.
///
/// Orientation matches the legacy per-bridge counters:
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

    /// Total bytes across both directions — used as a monotonic
    /// progress signal by the flow-level idle backstop.
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
    /// The chunk currently being drained into reader buffers; `Bytes` is
    /// advanced as it is consumed and cleared when empty.
    read_cursor: Option<Bytes>,
    on_read_demand: DemandSink,

    // ── write side (service → FFI peer) ──
    sink: BytesStatusSink,
    on_closed: ClosedSink,
    closed_fired: bool,
    paused_drain_max_wait: Duration,
    /// Armed on first `Paused`, disarmed on progress; backstops a peer
    /// whose drain signal never arrives so a wedged write can't park
    /// forever (mirrors the bridge's `paused_drain_max_wait`).
    paused_backstop: Option<Pin<Box<Sleep>>>,

    // ── shared per-flow state ──
    signals: Arc<TcpPerFlowSignals>,
    counters: Arc<TcpFlowByteCounters>,
    direction: BridgeDirection,
}

impl FfiBridgeStream {
    #[expect(
        clippy::too_many_arguments,
        reason = "per-flow stream wiring; a builder/struct would add noise without simplifying the single call site in `activate`"
    )]
    pub(crate) fn new(
        rx: mpsc::Receiver<Bytes>,
        sink: BytesStatusSink,
        on_read_demand: DemandSink,
        on_closed: ClosedSink,
        signals: Arc<TcpPerFlowSignals>,
        counters: Arc<TcpFlowByteCounters>,
        direction: BridgeDirection,
        paused_drain_max_wait: Duration,
    ) -> Self {
        Self {
            rx,
            read_cursor: None,
            on_read_demand,
            sink,
            on_closed,
            closed_fired: false,
            paused_drain_max_wait,
            paused_backstop: None,
            signals,
            counters,
            direction,
        }
    }
}

impl AsyncRead for FfiBridgeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // `FfiBridgeStream` is `Unpin` (every field is), so unrestricted
        // `&mut` access through the pin is sound.
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
                    // A channel slot just freed — wake the FFI reader if it
                    // paused waiting for capacity. Edge-triggered: only the
                    // true→false swap fires the callback, so we never spam
                    // the peer with redundant demand while the channel drains.
                    if this
                        .signals
                        .paused(this.direction)
                        .swap(false, Ordering::AcqRel)
                    {
                        (this.on_read_demand)();
                    }
                    // A zero-length chunk carries no data (e.g. a coalesced
                    // empty write); skip it rather than report a spurious EOF.
                    if bytes.is_empty() {
                        continue;
                    }
                    this.read_cursor = Some(bytes);
                    // loop to serve from the new cursor
                }
                // Sender dropped (`on_*_eof`, promote cutover, or cancel) —
                // natural end-of-stream, surfaced as a 0-byte read.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
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

        // Register the drain waker BEFORE invoking the sink. The peer can
        // only fire `signal_*_drain` at-or-after the sink observes the
        // `Paused` condition, so registering first guarantees such a wake
        // can never be lost in the window between the sink returning
        // `Paused` and us parking. A spurious wake on the `Accepted` path
        // just costs one extra poll.
        this.signals.drain(this.direction).register(cx.waker());

        match (this.sink)(buf) {
            TcpDeliverStatus::Accepted => {
                this.counters
                    .sent(this.direction)
                    .fetch_add(buf.len() as u64, Ordering::Relaxed);
                // Progress — disarm any backstop so the next stall starts
                // a fresh deadline.
                this.paused_backstop = None;
                Poll::Ready(Ok(buf.len()))
            }
            // Peer is gone; surface as a broken pipe so the forwarder tears
            // the flow down. (`copy_one_way` treats this as a write error.)
            TcpDeliverStatus::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transparent proxy: ffi peer closed the write side",
            ))),
            TcpDeliverStatus::Paused => {
                // Park until the drain waker fires (re-poll → retry the
                // sink with the same buffer — `write_all` re-presents it)
                // or the backstop deadline elapses.
                let max_wait = this.paused_drain_max_wait;
                let backstop = this
                    .paused_backstop
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(max_wait)));
                match backstop.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.paused_backstop = None;
                        // Backstop expired: this write direction is dead.
                        // Fire the close callback now (mirrors the old
                        // bridge's `PausedTimeout → on_server_closed`) so
                        // the FFI peer is notified even if the service
                        // ignores the write error we return.
                        if !this.closed_fired {
                            this.closed_fired = true;
                            (this.on_closed)();
                        }
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "transparent proxy: paused-drain backstop — peer drain signal lost?",
                        )))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // No intermediate buffer on our side — bytes go straight to the
        // sink in `poll_write`, so there is nothing to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Fire the FFI "write side done" callback exactly once. The sink is
        // already wrapped by the `callback_active` gate, so a shutdown that
        // races teardown is a no-op rather than a use-after-free.
        if !this.closed_fired {
            this.closed_fired = true;
            (this.on_closed)();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for FfiBridgeStream {
    fn drop(&mut self) {
        // A force-close (idle backstop / shutdown drops the stream before a
        // clean `poll_shutdown`) still owes the FFI peer its "write side
        // done" signal. Exactly-once via `closed_fired`; the guarded sink
        // no-ops if teardown already disarmed callbacks.
        if !self.closed_fired {
            self.closed_fired = true;
            (self.on_closed)();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU8, AtomicUsize};
    use std::task::{Context, Wake, Waker};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
        FfiBridgeStream::new(rx, sink, demand, closed, signals, counters, dir, max_wait)
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
}
