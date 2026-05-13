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
    // initiator had buffered before its half-close.
    let mut first_eof: Option<BridgeCloseReason> = None;

    let mut idle: Option<Pin<Box<tokio::time::Sleep>>> =
        idle_timeout.map(|d| Box::pin(tokio::time::sleep(d)));

    loop {
        if a_done && b_done {
            let reason = first_eof.unwrap_or(BridgeCloseReason::PeerEofLeft);
            tracing::trace!(
                target: "rama_core::stream::forward",
                reason = %reason,
                "stream forward bridge closed",
            );
            return Ok(reason);
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
            () = cancelled => {
                tracing::trace!(
                    target: "rama_core::stream::forward",
                    reason = %BridgeCloseReason::Shutdown,
                    "stream forward bridge closed",
                );
                return Ok(BridgeCloseReason::Shutdown);
            }
            () = idle_tick => {
                tracing::trace!(
                    target: "rama_core::stream::forward",
                    reason = %BridgeCloseReason::IdleTimeout,
                    "stream forward bridge closed",
                );
                return Ok(BridgeCloseReason::IdleTimeout);
            }

            item = a_stream.next(), if !a_done => match item {
                Some(Ok(t)) => {
                    if let (Some(d), Some(s)) = (idle_timeout, idle.as_mut()) {
                        s.as_mut().reset(tokio::time::Instant::now() + d);
                    }
                    if let Err(e) = b_sink.send(t).await {
                        return Err(e.into());
                    }
                }
                Some(Err(e)) => return Err(e.into()),
                None => {
                    a_done = true;
                    if first_eof.is_none() {
                        first_eof = Some(BridgeCloseReason::PeerEofLeft);
                    }
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
                    if let (Some(d), Some(s)) = (idle_timeout, idle.as_mut()) {
                        s.as_mut().reset(tokio::time::Instant::now() + d);
                    }
                    if let Err(e) = a_sink.send(t).await {
                        return Err(e.into());
                    }
                }
                Some(Err(e)) => return Err(e.into()),
                None => {
                    b_done = true;
                    if first_eof.is_none() {
                        first_eof = Some(BridgeCloseReason::PeerEofRight);
                    }
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
}
