use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rama_core::graceful::ShutdownGuard;
use rama_core::rt::Executor;
use rama_core::telemetry::tracing;
use rama_core::{
    Service,
    error::{BoxError, ErrorExt},
    io::{BridgeIo, Io},
};
use rama_utils::macros::generate_set_and_with;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::IdleGuard;

/// Reason why an [`IoForwardService`] bridge — or any equivalent bidirectional
/// byte relay — terminated.
///
/// Shared vocabulary used in close-log events emitted by rama bridges.
/// Consumers are free to emit any subset; each variant carries no metadata
/// of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BridgeCloseReason {
    /// Graceful shutdown was requested via the configured shutdown signal.
    Shutdown,
    /// The bridge observed no byte progress in either direction within the
    /// configured idle window.
    IdleTimeout,
    /// The "left" / ingress / client side reached EOF.
    PeerEofLeft,
    /// The "right" / egress / target side reached EOF.
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
        })
    }
}

/// Direction tag used internally by [`run_bridge`] to disambiguate
/// per-direction errors when classifying I/O failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopyDirection {
    LeftToRight,
    RightToLeft,
}

const DEFAULT_BUF_SIZE: usize = 8 * 1024;
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_millis(50);

/// A proxy [`Service`] which takes a [`BridgeIo`]
/// and copies the bytes of both the source and target [`Io`]s
/// bidirectionally.
///
/// The service observes shutdown via the [`ShutdownGuard`] of the
/// [`Executor`] passed at construction (if any), enforces an optional
/// idle timeout that closes the bridge when neither direction has made
/// byte progress within the configured window, and emits a single
/// structured close event when the bridge ends.
#[derive(Debug, Clone)]
pub struct IoForwardService {
    executor: Executor,
    idle_timeout: Option<Duration>,
    shutdown_grace: Duration,
    buf_size: usize,
}

impl Default for IoForwardService {
    fn default() -> Self {
        Self::new(Executor::default())
    }
}

impl IoForwardService {
    /// Create a new [`IoForwardService`] using the given [`Executor`].
    #[must_use]
    pub fn new(executor: Executor) -> Self {
        Self {
            executor,
            idle_timeout: None,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
            buf_size: DEFAULT_BUF_SIZE,
        }
    }

    generate_set_and_with! {
        /// Per-direction idle timeout. When set, the bridge closes with reason
        /// [`BridgeCloseReason::IdleTimeout`] if no byte progress is observed
        /// in either direction within `timeout`.
        ///
        /// `None` (the default) disables idle detection.
        pub fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.idle_timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Per-half cap on graceful shutdown. When the bridge unwinds it calls
        /// `shutdown()` on each write half bounded by this duration; if the
        /// inner type blocks (e.g. a TLS layer waiting for `close_notify`),
        /// the shutdown is abandoned and the half is dropped.
        ///
        /// Default: 50ms.
        pub fn shutdown_grace(mut self, grace: Duration) -> Self {
            self.shutdown_grace = grace;
            self
        }
    }

    generate_set_and_with! {
        /// Per-direction copy buffer size (in bytes).
        ///
        /// Default: 8 KiB.
        pub fn buf_size(mut self, size: usize) -> Self {
            self.buf_size = size.max(1);
            self
        }
    }

    /// The shutdown guard wired through the [`Executor`], if any.
    fn shutdown_guard(&self) -> Option<ShutdownGuard> {
        self.executor.guard().cloned()
    }
}

impl<S, T> Service<BridgeIo<S, T>> for IoForwardService
where
    S: Io + Unpin,
    T: Io + Unpin,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        BridgeIo(left, right): BridgeIo<S, T>,
    ) -> Result<Self::Output, Self::Error> {
        #[cfg(feature = "dial9")]
        super::dial9::record_bridge_opened(
            self.idle_timeout
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0),
            self.executor.guard().is_some(),
        );

        let outcome = run_bridge(
            left,
            right,
            self.shutdown_guard(),
            self.idle_timeout,
            self.shutdown_grace,
            self.buf_size,
        )
        .await;

        emit_close_event(&outcome);

        #[cfg(feature = "dial9")]
        {
            let age_ms = u64::try_from(outcome.age.as_millis()).unwrap_or(u64::MAX);
            super::dial9::record_bridge_closed(
                outcome.reason,
                age_ms,
                outcome.bytes_l_to_r,
                outcome.bytes_r_to_l,
                outcome.fatal_error.as_ref(),
            );
        }

        match outcome.fatal_error {
            None => Ok(()),
            Some(err) => {
                if crate::conn::is_connection_error(&err) {
                    Ok(())
                } else {
                    Err(err.context("(proxy) I/O forwarder"))
                }
            }
        }
    }
}

#[derive(Debug)]
struct BridgeOutcome {
    reason: BridgeCloseReason,
    bytes_l_to_r: u64,
    bytes_r_to_l: u64,
    age: Duration,
    fatal_error: Option<std::io::Error>,
}

async fn run_bridge<S, T>(
    left: S,
    right: T,
    guard: Option<ShutdownGuard>,
    idle_timeout: Option<Duration>,
    shutdown_grace: Duration,
    buf_size: usize,
) -> BridgeOutcome
where
    S: Io + Unpin,
    T: Io + Unpin,
{
    let opened_at = Instant::now();
    let bytes_l_to_r = Arc::new(AtomicU64::new(0));
    let bytes_r_to_l = Arc::new(AtomicU64::new(0));
    let progress = Arc::new(AtomicU64::new(0));

    let (mut left_r, mut left_w) = tokio::io::split(left);
    let (mut right_r, mut right_w) = tokio::io::split(right);

    let (reason, fatal_error) = {
        let l_to_r = std::pin::pin!(copy_one_way(
            &mut left_r,
            &mut right_w,
            bytes_l_to_r.clone(),
            progress.clone(),
            buf_size,
        ));
        let r_to_l = std::pin::pin!(copy_one_way(
            &mut right_r,
            &mut left_w,
            bytes_r_to_l.clone(),
            progress.clone(),
            buf_size,
        ));

        run_select_loop(l_to_r, r_to_l, guard.as_ref(), idle_timeout, &progress).await
        // l_to_r and r_to_l drop here, releasing borrows on the halves.
    };

    // Close both write halves concurrently rather than sequentially — TLS
    // close_notify can take the full grace window per side, and serializing
    // the two doubles the worst-case bridge unwind time.
    _ = tokio::join!(
        tokio::time::timeout(shutdown_grace, left_w.shutdown()),
        tokio::time::timeout(shutdown_grace, right_w.shutdown()),
    );

    BridgeOutcome {
        reason,
        bytes_l_to_r: bytes_l_to_r.load(Ordering::Relaxed),
        bytes_r_to_l: bytes_r_to_l.load(Ordering::Relaxed),
        age: opened_at.elapsed(),
        fatal_error,
    }
}

async fn run_select_loop<F1, F2>(
    mut l_to_r: std::pin::Pin<&mut F1>,
    mut r_to_l: std::pin::Pin<&mut F2>,
    guard: Option<&ShutdownGuard>,
    idle_timeout: Option<Duration>,
    progress: &AtomicU64,
) -> (BridgeCloseReason, Option<std::io::Error>)
where
    F1: Future<Output = Result<(), std::io::Error>>,
    F2: Future<Output = Result<(), std::io::Error>>,
{
    let mut idle = idle_timeout.map(IdleGuard::new);
    let mut last_progress: u64 = 0;
    let mut l_to_r_done = false;
    let mut r_to_l_done = false;

    loop {
        if l_to_r_done && r_to_l_done {
            return (BridgeCloseReason::PeerEofLeft, None);
        }

        let cancelled = async {
            match guard {
                Some(g) => g.cancelled().await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            biased;
            () = cancelled => return (BridgeCloseReason::Shutdown, None),
            _ = async {
                match idle.as_mut() {
                    Some(g) => g.tick().await,
                    None => std::future::pending().await,
                }
            } => {
                let cur = progress.load(Ordering::Relaxed);
                if cur != last_progress {
                    last_progress = cur;
                    if let Some(g) = idle.as_mut() {
                        g.reset();
                    }
                    continue;
                }
                return (BridgeCloseReason::IdleTimeout, None);
            }
            res = l_to_r.as_mut(), if !l_to_r_done => match res {
                Ok(()) => {
                    l_to_r_done = true;
                    if !r_to_l_done {
                        continue;
                    }
                    return (BridgeCloseReason::PeerEofLeft, None);
                }
                Err(e) => {
                    let reason = classify_copy_error(&e, CopyDirection::LeftToRight);
                    return (reason, Some(e));
                }
            },
            res = r_to_l.as_mut(), if !r_to_l_done => match res {
                Ok(()) => {
                    r_to_l_done = true;
                    if !l_to_r_done {
                        continue;
                    }
                    return (BridgeCloseReason::PeerEofRight, None);
                }
                Err(e) => {
                    let reason = classify_copy_error(&e, CopyDirection::RightToLeft);
                    return (reason, Some(e));
                }
            },
        }
    }
}

async fn copy_one_way<R, W>(
    reader: &mut R,
    writer: &mut W,
    bytes: Arc<AtomicU64>,
    progress: Arc<AtomicU64>,
    buf_size: usize,
) -> Result<(), std::io::Error>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buf_size];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            // Half-close the write side so the peer sees EOF.
            // Bounded externally by the surrounding `tokio::select!` /
            // shutdown grace; here we just attempt cleanly.
            _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
        bytes.fetch_add(n as u64, Ordering::Relaxed);
        progress.fetch_add(1, Ordering::Relaxed);
    }
}

fn classify_copy_error(err: &std::io::Error, direction: CopyDirection) -> BridgeCloseReason {
    use std::io::ErrorKind;
    // Rough split: connection / EOF errors on the read side; other kinds on the
    // write side. We can't always tell which side surfaced an error from the
    // io::Error alone, so this is best-effort.
    let read_side = matches!(
        err.kind(),
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::BrokenPipe
    );
    match (direction, read_side) {
        (CopyDirection::LeftToRight, true) => BridgeCloseReason::ReadErrorLeft,
        (CopyDirection::LeftToRight, false) => BridgeCloseReason::WriteErrorRight,
        (CopyDirection::RightToLeft, true) => BridgeCloseReason::ReadErrorRight,
        (CopyDirection::RightToLeft, false) => BridgeCloseReason::WriteErrorLeft,
    }
}

fn emit_close_event(outcome: &BridgeOutcome) {
    let age_ms = u64::try_from(outcome.age.as_millis()).unwrap_or(u64::MAX);
    if outcome.fatal_error.is_some() {
        tracing::debug!(
            target: "rama_net::proxy::forward",
            reason = %outcome.reason,
            bytes_l_to_r = outcome.bytes_l_to_r,
            bytes_r_to_l = outcome.bytes_r_to_l,
            age_ms,
            error = ?outcome.fatal_error,
            "io forward bridge closed",
        );
    } else {
        tracing::trace!(
            target: "rama_net::proxy::forward",
            reason = %outcome.reason,
            bytes_l_to_r = outcome.bytes_l_to_r,
            bytes_r_to_l = outcome.bytes_r_to_l,
            age_ms,
            "io forward bridge closed",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::graceful::Shutdown;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    async fn run_default<S, T>(left: S, right: T)
    where
        S: Io + Unpin,
        T: Io + Unpin,
    {
        let svc = IoForwardService::default();
        svc.serve(BridgeIo(left, right)).await.unwrap()
    }

    #[tokio::test]
    async fn forward_basic_bidirectional_traffic() {
        let (a_user, a_proxy) = duplex(64);
        let (b_user, b_proxy) = duplex(64);

        let svc_task = tokio::spawn(async move {
            run_default(a_proxy, b_proxy).await;
        });

        let mut a = a_user;
        let mut b = b_user;

        a.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        b.write_all(b"world!").await.unwrap();
        let mut buf = [0u8; 6];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world!");

        // Closing one side should let the bridge wind down.
        drop(a);
        drop(b);
        svc_task.await.unwrap();
    }

    async fn shutdown_pair() -> (Shutdown, tokio::sync::oneshot::Sender<()>) {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown = Shutdown::new(async move {
            _ = rx.await;
        });
        (shutdown, tx)
    }

    #[tokio::test]
    async fn forward_shutdown_drops_idle_bridge() {
        let (shutdown, trigger) = shutdown_pair().await;
        let guard = shutdown.guard();
        let svc = IoForwardService::new(Executor::graceful(guard));

        let (_a_user, a_proxy) = duplex(64);
        let (_b_user, b_proxy) = duplex(64);

        let task = tokio::spawn(async move {
            svc.serve(BridgeIo(a_proxy, b_proxy)).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let started = Instant::now();
        trigger.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("bridge did not unwind within 2s")
            .unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "bridge took {elapsed:?} to unwind on shutdown",
        );
        drop(shutdown);
    }

    #[tokio::test]
    async fn forward_shutdown_drops_active_bridge() {
        let (shutdown, trigger) = shutdown_pair().await;
        let guard = shutdown.guard();
        let svc = IoForwardService::new(Executor::graceful(guard));

        let (mut a_user, a_proxy) = duplex(64);
        let (mut b_user, b_proxy) = duplex(64);

        let task = tokio::spawn(async move {
            svc.serve(BridgeIo(a_proxy, b_proxy)).await.unwrap();
        });

        a_user.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b_user.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        let started = Instant::now();
        trigger.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("bridge did not unwind within 2s")
            .unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "bridge took {elapsed:?} to unwind on shutdown",
        );
        drop(shutdown);
    }

    #[tokio::test]
    async fn forward_idle_timeout_fires_when_no_progress() {
        let svc = IoForwardService::default().with_idle_timeout(Duration::from_millis(100));

        let (_a_user, a_proxy) = duplex(64);
        let (_b_user, b_proxy) = duplex(64);

        let started = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(2),
            svc.serve(BridgeIo(a_proxy, b_proxy)),
        )
        .await
        .expect("idle bridge did not unwind within 2s")
        .unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(80),
            "idle bridge unwound too early: {elapsed:?}",
        );
        assert!(
            elapsed < Duration::from_millis(800),
            "idle bridge unwound too late: {elapsed:?}",
        );
    }

    #[tokio::test]
    async fn forward_idle_timeout_resets_on_progress() {
        let svc = IoForwardService::default().with_idle_timeout(Duration::from_millis(150));

        let (mut a_user, a_proxy) = duplex(64);
        let (mut b_user, b_proxy) = duplex(64);

        let task = tokio::spawn(async move {
            svc.serve(BridgeIo(a_proxy, b_proxy)).await.unwrap();
        });

        // Push a byte every 50ms for ~400ms; idle is 150ms so it should never
        // fire even though cumulative time exceeds the idle window.
        for _ in 0..8 {
            a_user.write_all(b"x").await.unwrap();
            let mut buf = [0u8; 1];
            b_user.read_exact(&mut buf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        drop(a_user);
        drop(b_user);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("bridge did not unwind on EOF within 2s")
            .unwrap();
    }

    #[tokio::test]
    async fn forward_byte_counters_visible_via_close_log() {
        let (mut a_user, a_proxy) = duplex(64);
        let (mut b_user, b_proxy) = duplex(64);

        let task = tokio::spawn(async move {
            run_default(a_proxy, b_proxy).await;
        });

        a_user.write_all(b"abc").await.unwrap();
        let mut buf = [0u8; 3];
        b_user.read_exact(&mut buf).await.unwrap();
        b_user.write_all(b"defgh").await.unwrap();
        let mut buf = [0u8; 5];
        a_user.read_exact(&mut buf).await.unwrap();

        drop(a_user);
        drop(b_user);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn forward_default_executor_means_no_shutdown_observation() {
        // Without a graceful executor, the bridge does not observe an
        // external shutdown signal and only ends on EOF/error/idle.
        let svc = IoForwardService::default();

        let (a_user, a_proxy) = duplex(64);
        let (b_user, b_proxy) = duplex(64);

        let task = tokio::spawn(async move {
            svc.serve(BridgeIo(a_proxy, b_proxy)).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!task.is_finished(), "bridge ended without an EOF signal");

        drop(a_user);
        drop(b_user);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("bridge did not unwind on EOF within 2s")
            .unwrap();
    }
}
