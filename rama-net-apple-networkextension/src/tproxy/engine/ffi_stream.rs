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

use rama_core::bytes::{Buf, Bytes};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
    time::Sleep,
};

use super::{
    BridgeDirection, BytesStatusSink, ClosedSink, DemandSink, TcpDeliverStatus, TcpPerFlowSignals,
};

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

    // ── write side (service → FFI peer) ──
    sink: BytesStatusSink,
    on_closed: ClosedSink,
    closed_fired: bool,
    paused_drain_max_wait: Duration,
    /// Reaps a write parked on `Paused` whose drain never arrives. Armed on
    /// `Paused`, cleared on progress.
    paused_backstop: Option<Pin<Box<Sleep>>>,

    // ── shared per-flow state ──
    signals: Arc<TcpPerFlowSignals>,
    counters: Arc<TcpFlowByteCounters>,
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
                    // Slot freed: wake the FFI reader if it paused for
                    // capacity. Edge-triggered so we don't re-spam demand.
                    if this
                        .signals
                        .paused(this.direction)
                        .swap(false, Ordering::AcqRel)
                    {
                        (this.on_read_demand)();
                    }
                    // Skip empty chunks (a 0-byte read would look like EOF).
                    if bytes.is_empty() {
                        continue;
                    }
                    this.read_cursor = Some(bytes);
                }
                // Sender dropped → EOF.
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

        // Register before calling the sink: `signal_*_drain` can only fire
        // after the sink returns `Paused`, so registering first can't lose
        // it. A spurious wake on `Accepted` just costs one poll.
        this.signals.drain(this.direction).register(cx.waker());

        match (this.sink)(buf) {
            TcpDeliverStatus::Accepted => {
                this.counters
                    .sent(this.direction)
                    .fetch_add(buf.len() as u64, Ordering::Relaxed);
                this.paused_backstop = None; // progress: re-arm fresh next time
                Poll::Ready(Ok(buf.len()))
            }
            // Peer gone → broken pipe; the forwarder tears the flow down.
            TcpDeliverStatus::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transparent proxy: ffi peer closed the write side",
            ))),
            TcpDeliverStatus::Paused => {
                // Park for a drain wake (re-poll retries the same buffer) or
                // the backstop deadline.
                let max_wait = this.paused_drain_max_wait;
                let backstop = this
                    .paused_backstop
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(max_wait)));
                match backstop.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.paused_backstop = None;
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
