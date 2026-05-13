//! Bridge two duplex [`Stream`] + [`Sink`] endpoints by pumping items between them.
//!
//! Where [`crate::io::BridgeIo`] copies *bytes* between two byte-oriented
//! halves, [`StreamForwardService`] copies *frames* (or any other typed
//! items) between two `Stream + Sink` halves.
//!
//! Both halves must agree on the item type `T`. If they do not — for example
//! one side carries `(Bytes, SocketAddr)` while the other carries plain
//! `Bytes` — that mismatch is the *transport's* problem to solve, by using
//! a connected variant of the underlying socket, or by mapping with
//! [`StreamExt::map`] / [`SinkExt::with`] from [`futures`]. The forwarder
//! itself stays dumb on purpose: it pumps, it does not translate.
//!
//! See [`crate::Service`] for the service abstraction this plugs into.

use std::pin::Pin;
use std::time::Duration;

use futures::{Sink, SinkExt, Stream, StreamExt};
use rama_error::{BoxError, ErrorExt};
use rama_utils::macros::generate_set_and_with;

use crate::Service;
use crate::graceful::ShutdownGuard;
use crate::telemetry::tracing;

/// Reason why a rama bridge — byte-oriented (see `IoForwardService` in
/// `rama-net`) or frame-oriented (see [`StreamForwardService`]) — terminated.
///
/// Shared vocabulary used in close-log events emitted by rama bridges.
/// Consumers are free to emit any subset; each variant carries no metadata
/// of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BridgeCloseReason {
    /// Graceful shutdown was requested via the configured shutdown signal.
    Shutdown,
    /// The bridge observed no progress in either direction within the
    /// configured idle window.
    IdleTimeout,
    /// The "left" / `a` side reached EOF.
    PeerEofLeft,
    /// The "right" / `b` side reached EOF.
    PeerEofRight,
    /// Read from the left half failed.
    ReadErrorLeft,
    /// Read from the right half failed.
    ReadErrorRight,
    /// Write to the left half failed.
    WriteErrorLeft,
    /// Write to the right half failed.
    WriteErrorRight,
    /// A protocol-peek read deadline elapsed before the peek completed.
    /// Used by tproxy bridges that peek the first bytes for protocol detection.
    PeekTimeout,
    /// The flow handler did not produce a decision within the configured
    /// deadline. The flow was rejected (or passed through, depending on
    /// configuration) without bridging.
    HandlerDeadline,
    /// A backpressure-paused write side was never re-armed by its peer
    /// drain signal within the configured maximum-pause window. Surfaces
    /// stuck downstream writers (e.g. a Swift `flow.write` completion
    /// handler that never invokes `signalServerDrain`) instead of
    /// wedging the bridge indefinitely.
    PausedTimeout,
}

impl std::fmt::Display for BridgeCloseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Shutdown => "shutdown",
            Self::IdleTimeout => "idle_timeout",
            Self::PeerEofLeft => "peer_eof_left",
            Self::PeerEofRight => "peer_eof_right",
            Self::ReadErrorLeft => "read_error_left",
            Self::ReadErrorRight => "read_error_right",
            Self::WriteErrorLeft => "write_error_left",
            Self::WriteErrorRight => "write_error_right",
            Self::PeekTimeout => "peek_timeout",
            Self::HandlerDeadline => "handler_deadline",
            Self::PausedTimeout => "paused_timeout",
        })
    }
}

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
impl dial9_trace_format::TraceField for BridgeCloseReason {
    type Ref<'a> = Self;

    fn field_type() -> dial9_trace_format::types::FieldType {
        dial9_trace_format::types::FieldType::U8
    }

    fn encode<W: std::io::Write>(
        &self,
        enc: &mut dial9_trace_format::EventEncoder<'_, W>,
    ) -> std::io::Result<()> {
        let code = match self {
            Self::Shutdown => 1,
            Self::IdleTimeout => 2,
            Self::PeerEofLeft => 3,
            Self::PeerEofRight => 4,
            Self::ReadErrorLeft => 5,
            Self::ReadErrorRight => 6,
            Self::WriteErrorLeft => 7,
            Self::WriteErrorRight => 8,
            Self::PeekTimeout => 9,
            Self::HandlerDeadline => 10,
            Self::PausedTimeout => 11,
        };
        enc.write_u8(code)
    }

    fn decode_ref<'a>(val: &dial9_trace_format::types::FieldValueRef<'a>) -> Option<Self::Ref<'a>> {
        use dial9_trace_format::types::FieldValueRef;
        match val {
            FieldValueRef::Varint(1) => Some(Self::Shutdown),
            FieldValueRef::Varint(2) => Some(Self::IdleTimeout),
            FieldValueRef::Varint(3) => Some(Self::PeerEofLeft),
            FieldValueRef::Varint(4) => Some(Self::PeerEofRight),
            FieldValueRef::Varint(5) => Some(Self::ReadErrorLeft),
            FieldValueRef::Varint(6) => Some(Self::ReadErrorRight),
            FieldValueRef::Varint(7) => Some(Self::WriteErrorLeft),
            FieldValueRef::Varint(8) => Some(Self::WriteErrorRight),
            FieldValueRef::Varint(9) => Some(Self::PeekTimeout),
            FieldValueRef::Varint(10) => Some(Self::HandlerDeadline),
            FieldValueRef::Varint(11) => Some(Self::PausedTimeout),
            _ => None,
        }
    }
}

/// Input to [`StreamForwardService`]: the two duplex endpoints to bridge.
///
/// Both `a` and `b` must be [`Stream`] + [`Sink`] over the *same* item type
/// `T`. To bridge endpoints whose native item types differ, adapt one or
/// both with [`StreamExt::map`] / [`SinkExt::with`] (or use a duplex wrapper
/// such as `rama_udp::ConnectedUdpFramed` that exposes the desired type
/// natively) before constructing the bridge.
#[derive(Debug)]
pub struct StreamBridge<A, B> {
    /// The "left" / `a` endpoint.
    pub a: A,
    /// The "right" / `b` endpoint.
    pub b: B,
}

impl<A, B> StreamBridge<A, B> {
    /// Create a new [`StreamBridge`] from two duplex endpoints.
    pub fn new(a: A, b: B) -> Self {
        Self { a, b }
    }
}

/// A [`Service`] which takes a [`StreamBridge`] and pumps frames between
/// the two endpoints bidirectionally.
///
/// The service optionally observes a [`ShutdownGuard`] (for graceful
/// termination) and an idle timeout that closes the bridge when no frame
/// has been forwarded in either direction within the configured window.
///
/// Returns a [`BridgeCloseReason`] describing why the bridge ended.
#[derive(Debug, Clone, Default)]
pub struct StreamForwardService {
    idle_timeout: Option<Duration>,
    shutdown_guard: Option<ShutdownGuard>,
}

impl StreamForwardService {
    /// Create a new [`StreamForwardService`] with no idle timeout and no
    /// shutdown guard. Equivalent to [`StreamForwardService::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Idle timeout. When set, the bridge closes with reason
        /// [`BridgeCloseReason::IdleTimeout`] if no frame has been
        /// forwarded in either direction within `timeout`.
        ///
        /// `None` (the default) disables idle detection.
        pub fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.idle_timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// [`ShutdownGuard`] used to observe graceful-shutdown signals.
        /// When the guard fires, the bridge closes with reason
        /// [`BridgeCloseReason::Shutdown`].
        ///
        /// `None` (the default) means no shutdown observation.
        pub fn shutdown_guard(mut self, guard: Option<ShutdownGuard>) -> Self {
            self.shutdown_guard = guard;
            self
        }
    }
}

impl<A, B, T, EA, EB> Service<StreamBridge<A, B>> for StreamForwardService
where
    A: Stream<Item = Result<T, EA>> + Sink<T, Error = EA> + Send + Unpin + 'static,
    B: Stream<Item = Result<T, EB>> + Sink<T, Error = EB> + Send + Unpin + 'static,
    T: Send + 'static,
    EA: Into<BoxError> + Send + 'static,
    EB: Into<BoxError> + Send + 'static,
{
    type Output = BridgeCloseReason;
    type Error = BoxError;

    async fn serve(&self, bridge: StreamBridge<A, B>) -> Result<Self::Output, Self::Error> {
        let StreamBridge { a, b } = bridge;
        run_bridge(a, b, self.idle_timeout, self.shutdown_guard.clone()).await
    }
}

async fn run_bridge<A, B, T, EA, EB>(
    a: A,
    b: B,
    idle_timeout: Option<Duration>,
    guard: Option<ShutdownGuard>,
) -> Result<BridgeCloseReason, BoxError>
where
    A: Stream<Item = Result<T, EA>> + Sink<T, Error = EA> + Send + Unpin,
    B: Stream<Item = Result<T, EB>> + Sink<T, Error = EB> + Send + Unpin,
    T: Send,
    EA: Into<BoxError> + Send,
    EB: Into<BoxError> + Send,
{
    let (mut a_sink, mut a_stream) = a.split();
    let (mut b_sink, mut b_stream) = b.split();

    let mut a_done = false;
    let mut b_done = false;
    // The reason of whichever side ended first — that's the one that
    // initiated the close. The other side just drained whatever the
    // initiator had buffered before its half-close. Default value is
    // never observed without being overwritten because the loop only
    // exits via `a_done && b_done`, which requires at least one EOF
    // arm to have run.
    let mut first_eof = BridgeCloseReason::PeerEofLeft;

    let mut idle: Option<Pin<Box<tokio::time::Sleep>>> =
        idle_timeout.map(|d| Box::pin(tokio::time::sleep(d)));
    // Progress counter: bumped on every successful forward. The idle arm
    // re-checks this against `last_progress` before declaring a timeout,
    // to absorb the race where idle fires in the same select tick that a
    // forward also became ready.
    let mut progress: u64 = 0;
    let mut last_progress: u64 = 0;

    let result = loop {
        if a_done && b_done {
            break Ok(first_eof);
        }

        let cancelled = async {
            match guard.as_ref() {
                Some(g) => g.cancelled().await,
                None => std::future::pending::<()>().await,
            }
        };

        let idle_tick = async {
            match idle.as_mut() {
                Some(s) => s.as_mut().await,
                None => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            biased;
            () = cancelled => break Ok(BridgeCloseReason::Shutdown),
            () = idle_tick => {
                // Re-check the progress counter: a forward may have
                // completed in the same poll cycle that idle fired.
                if progress != last_progress {
                    last_progress = progress;
                    if let (Some(d), Some(s)) = (idle_timeout, idle.as_mut()) {
                        s.as_mut().reset(tokio::time::Instant::now() + d);
                    }
                    continue;
                }
                break Ok(BridgeCloseReason::IdleTimeout);
            }

            item = a_stream.next(), if !a_done => match item {
                Some(Ok(t)) => {
                    if let Err(e) = b_sink.send(t).await {
                        break Err((BridgeCloseReason::WriteErrorRight, e.into_box_error()));
                    }
                    progress = progress.wrapping_add(1);
                    if let (Some(d), Some(s)) = (idle_timeout, idle.as_mut()) {
                        s.as_mut().reset(tokio::time::Instant::now() + d);
                    }
                }
                Some(Err(e)) => break Err((BridgeCloseReason::ReadErrorLeft, e.into_box_error())),
                None => {
                    if !b_done {
                        first_eof = BridgeCloseReason::PeerEofLeft;
                    }
                    a_done = true;
                    if let Err(err) = b_sink.close().await {
                        tracing::debug!(
                            target: "rama_core::stream::forward",
                            error = %err.into_box_error(),
                            "stream forward bridge: error while half-closing `b` after `a` EOF",
                        );
                    }
                }
            },

            item = b_stream.next(), if !b_done => match item {
                Some(Ok(t)) => {
                    if let Err(e) = a_sink.send(t).await {
                        break Err((BridgeCloseReason::WriteErrorLeft, e.into_box_error()));
                    }
                    progress = progress.wrapping_add(1);
                    if let (Some(d), Some(s)) = (idle_timeout, idle.as_mut()) {
                        s.as_mut().reset(tokio::time::Instant::now() + d);
                    }
                }
                Some(Err(e)) => break Err((BridgeCloseReason::ReadErrorRight, e.into_box_error())),
                None => {
                    if !a_done {
                        first_eof = BridgeCloseReason::PeerEofRight;
                    }
                    b_done = true;
                    if let Err(err) = a_sink.close().await {
                        tracing::debug!(
                            target: "rama_core::stream::forward",
                            error = %err.into_box_error(),
                            "stream forward bridge: error while half-closing `a` after `b` EOF",
                        );
                    }
                }
            },
        }
    };

    match result {
        Ok(reason) => {
            tracing::trace!(
                target: "rama_core::stream::forward",
                reason = %reason,
                "stream forward bridge closed",
            );
            Ok(reason)
        }
        Err((reason, err)) => {
            tracing::debug!(
                target: "rama_core::stream::forward",
                reason = %reason,
                error = %err,
                "stream forward bridge closed with error",
            );
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::channel::mpsc;
    use std::time::Instant;

    /// Build a pair of duplex endpoints over `mpsc` channels for testing.
    /// `(a, b)` are wired such that items sent on `a` arrive on `b.next()`
    /// and vice versa.
    fn duplex_pair<T: Send + 'static>() -> (DuplexEndpoint<T>, DuplexEndpoint<T>) {
        let (a_tx, b_rx) = mpsc::unbounded::<T>();
        let (b_tx, a_rx) = mpsc::unbounded::<T>();
        (
            DuplexEndpoint::new(a_tx, a_rx),
            DuplexEndpoint::new(b_tx, b_rx),
        )
    }

    struct DuplexEndpoint<T> {
        tx: mpsc::UnboundedSender<T>,
        rx: mpsc::UnboundedReceiver<T>,
    }

    impl<T> DuplexEndpoint<T> {
        fn new(tx: mpsc::UnboundedSender<T>, rx: mpsc::UnboundedReceiver<T>) -> Self {
            Self { tx, rx }
        }
    }

    impl<T> Stream for DuplexEndpoint<T> {
        type Item = Result<T, std::io::Error>;
        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            Pin::new(&mut self.rx).poll_next(cx).map(|opt| opt.map(Ok))
        }
    }

    impl<T> Sink<T> for DuplexEndpoint<T> {
        type Error = std::io::Error;
        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
            self.get_mut()
                .tx
                .unbounded_send(item)
                .map_err(|_err| std::io::Error::other("send on closed channel"))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            self.tx.close_channel();
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl<T> Unpin for DuplexEndpoint<T> {}

    #[tokio::test]
    async fn forwards_in_both_directions() {
        let (mut a_user, a_proxy) = duplex_pair::<u32>();
        let (mut b_user, b_proxy) = duplex_pair::<u32>();

        let svc = StreamForwardService::new();
        let task = tokio::spawn(async move {
            svc.serve(StreamBridge::new(a_proxy, b_proxy))
                .await
                .unwrap()
        });

        a_user.send(1).await.unwrap();
        a_user.send(2).await.unwrap();
        let r1 = b_user.next().await.unwrap().unwrap();
        let r2 = b_user.next().await.unwrap().unwrap();
        assert_eq!((r1, r2), (1, 2));

        b_user.send(10).await.unwrap();
        let r = a_user.next().await.unwrap().unwrap();
        assert_eq!(r, 10);

        drop(a_user);
        drop(b_user);
        let reason = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("bridge did not unwind within 2s")
            .unwrap();
        assert!(matches!(
            reason,
            BridgeCloseReason::PeerEofLeft | BridgeCloseReason::PeerEofRight
        ));
    }

    #[tokio::test]
    async fn idle_timeout_fires_on_no_progress() {
        let (a_user, a_proxy) = duplex_pair::<u32>();
        let (b_user, b_proxy) = duplex_pair::<u32>();

        let svc = StreamForwardService::new().with_idle_timeout(Duration::from_millis(100));
        let started = Instant::now();
        let reason = tokio::time::timeout(
            Duration::from_secs(2),
            svc.serve(StreamBridge::new(a_proxy, b_proxy)),
        )
        .await
        .expect("idle bridge did not unwind within 2s")
        .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(reason, BridgeCloseReason::IdleTimeout);
        assert!(
            elapsed >= Duration::from_millis(80),
            "idle bridge unwound too early: {elapsed:?}",
        );
        // Keep peers alive past the assertion so they don't EOF early.
        drop(a_user);
        drop(b_user);
    }

    #[tokio::test]
    async fn idle_timer_resets_on_activity() {
        let (mut a_user, a_proxy) = duplex_pair::<u32>();
        let (mut b_user, b_proxy) = duplex_pair::<u32>();

        let svc = StreamForwardService::new().with_idle_timeout(Duration::from_millis(150));
        let task = tokio::spawn(async move {
            svc.serve(StreamBridge::new(a_proxy, b_proxy))
                .await
                .unwrap()
        });

        // Push one item every 50ms for ~400ms — total elapsed > idle
        // window, but each individual gap is well below it. The bridge
        // must not declare IdleTimeout.
        for i in 0..8u32 {
            a_user.send(i).await.unwrap();
            let r = b_user.next().await.unwrap().unwrap();
            assert_eq!(r, i);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        drop(a_user);
        drop(b_user);
        let reason = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("bridge did not unwind on EOF within 2s")
            .unwrap();
        assert!(
            matches!(
                reason,
                BridgeCloseReason::PeerEofLeft | BridgeCloseReason::PeerEofRight
            ),
            "expected EOF reason, got {reason}",
        );
    }

    #[tokio::test]
    async fn shutdown_guard_terminates_bridge() {
        use crate::graceful::Shutdown;

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown = Shutdown::new(async move {
            _ = rx.await;
        });
        let guard = shutdown.guard();

        let (_a_user, a_proxy) = duplex_pair::<u32>();
        let (_b_user, b_proxy) = duplex_pair::<u32>();

        let svc = StreamForwardService::new().with_shutdown_guard(guard);
        let task = tokio::spawn(async move {
            svc.serve(StreamBridge::new(a_proxy, b_proxy))
                .await
                .unwrap()
        });

        // Bridge is idle but should not return on its own.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!task.is_finished());

        tx.send(()).unwrap();
        let reason = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("bridge did not unwind on shutdown within 2s")
            .unwrap();
        assert_eq!(reason, BridgeCloseReason::Shutdown);
        drop(shutdown);
    }

    #[tokio::test]
    async fn half_close_keeps_other_direction_alive() {
        // After `a_user` drops, `a_proxy`'s stream EOFs (PeerEofLeft is
        // pinned as first_eof) but the bridge must NOT unwind yet — it
        // should keep pumping `b -> a` direction until `b_user` also
        // drops. We assert this by:
        //   1. Drop `a_user` early.
        //   2. After a short pause, verify the service task hasn't
        //      finished.
        //   3. Drop `b_user`.
        //   4. The bridge unwinds and `first_eof` wins → PeerEofLeft.
        let (a_user, a_proxy) = duplex_pair::<u32>();
        let (b_user, b_proxy) = duplex_pair::<u32>();

        let svc = StreamForwardService::new();
        let task = tokio::spawn(async move {
            svc.serve(StreamBridge::new(a_proxy, b_proxy))
                .await
                .unwrap()
        });

        drop(a_user);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !task.is_finished(),
            "bridge unwound before second side closed (a half-close should not be enough)",
        );

        drop(b_user);
        let reason = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("bridge did not unwind within 2s")
            .unwrap();
        // a_user dropped first → first_eof = PeerEofLeft.
        assert_eq!(reason, BridgeCloseReason::PeerEofLeft);
    }

}
