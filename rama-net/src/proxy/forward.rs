use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::std::sync::Arc;

use super::IdleGuard;

use rama_core::graceful::ShutdownGuard;
use rama_core::rt::Executor;
use rama_core::telemetry::tracing;
use rama_core::{
    Service,
    error::{BoxError, ErrorExt},
    io::{BridgeIo, Io},
};
use rama_utils::macros::generate_set_and_with;
use rama_utils::octets::kib;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

// `BridgeCloseReason` is shared with the frame-oriented bridge in
// `rama-core::stream::forward`. Re-exported here for convience.
#[doc(inline)]
pub use rama_core::stream::BridgeCloseReason;

/// Direction tag used internally by [`run_bridge`] to disambiguate
/// per-direction errors when classifying I/O failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopyDirection {
    LeftToRight,
    RightToLeft,
}

/// Anchor from which the response first-byte window
/// (see [`IoForwardService::with_first_byte_timeout`]) is measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FirstByteTimeoutStart {
    /// Count from the moment the bridge opens.
    ///
    /// Best for server-speaks-first protocols (SMTP/FTP/SSH) where the origin
    /// is expected to greet unprompted. On client-speaks-first protocols
    /// (HTTP/TLS) it can cut a slow-to-speak client, since the origin has no
    /// reason to respond until the client's request arrives.
    BridgeOpen,
    /// Count from the client's first sent byte, true time-to-first-response-byte.
    ///
    /// Isolates a genuinely silent origin (asked, but not answering) without
    /// penalising a client that is merely slow to send. A silent origin on a
    /// server-speaks-first protocol is not caught by this anchor, total mutual
    /// silence stays [`idle_timeout`](IoForwardService::with_idle_timeout)'s job.
    ///
    /// This is the default.
    #[default]
    ClientFirstByte,
}

// 16 KiB is a middle ground: large enough to roughly halve the per-chunk
// copy/syscall count vs the classic 8 KiB on bulk transfers, while keeping the
// per-direction reused buffer small enough that holding two of them per live
// flow stays cheap under high connection concurrency. Override per service via
// [`IoForwardService::with_buf_size`] when a workload wants a different point on
// that throughput-vs-resident-memory curve.
const DEFAULT_BUF_SIZE: usize = kib(16);
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
    first_byte_timeout: Option<Duration>,
    first_byte_timeout_start: FirstByteTimeoutStart,
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
            first_byte_timeout: None,
            first_byte_timeout_start: FirstByteTimeoutStart::default(),
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
        /// Response first-byte timeout. When set, the bridge closes with reason
        /// [`BridgeCloseReason::FirstByteTimeout`] if the upstream (right /
        /// egress) half writes no byte within `timeout` of the window's start
        /// (see [`first_byte_timeout_start`](Self::with_first_byte_timeout_start)).
        ///
        /// This targets a silent origin that accepts the connection but never
        /// responds: the client's bytes still flow toward the upstream, so the
        /// flow never looks idle. It keys off the upstream -> client direction
        /// only, once the first upstream byte arrives the timer disarms
        /// permanently and [`idle_timeout`](Self::with_idle_timeout) takes over.
        ///
        /// Where the window is anchored (bridge open vs the client's first sent
        /// byte) is controlled by
        /// [`first_byte_timeout_start`](Self::with_first_byte_timeout_start).
        ///
        /// `None` (the default) disables first-byte detection.
        pub fn first_byte_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.first_byte_timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Anchor for the response first-byte window: see
        /// [`FirstByteTimeoutStart`]. Only meaningful when
        /// [`first_byte_timeout`](Self::with_first_byte_timeout) is set.
        ///
        /// Default: [`FirstByteTimeoutStart::ClientFirstByte`].
        pub fn first_byte_timeout_start(mut self, start: FirstByteTimeoutStart) -> Self {
            self.first_byte_timeout_start = start;
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
            self.first_byte_timeout,
            self.first_byte_timeout_start,
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

#[expect(clippy::too_many_arguments)]
async fn run_bridge<S, T>(
    left: S,
    right: T,
    guard: Option<ShutdownGuard>,
    idle_timeout: Option<Duration>,
    first_byte_timeout: Option<Duration>,
    first_byte_timeout_start: FirstByteTimeoutStart,
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

    let first_byte_seen = Arc::new(AtomicBool::new(false));
    let upstream_eof_seen = Arc::new(AtomicBool::new(false));

    let client_first_byte_seen = Arc::new(AtomicBool::new(false));
    let client_spoke = Arc::new(Notify::new());

    let (mut left_r, mut left_w) = tokio::io::split(left);
    let (mut right_r, mut right_w) = tokio::io::split(right);

    // Tracks whether `copy_one_way` has already half-closed the write
    // side it owns. The inline half-close fires immediately on EOF so
    // the peer sees FIN promptly; we then skip the outer post-loop
    // shutdown for that side. Calling `shutdown` twice on a TLS writer
    // (boring/rustls) is implementation-defined and can panic — the
    // flag stops that here.
    let left_w_shut = Arc::new(AtomicBool::new(false));
    let right_w_shut = Arc::new(AtomicBool::new(false));

    let (reason, fatal_error) = {
        let l_to_r = std::pin::pin!(copy_one_way(
            &mut left_r,
            &mut right_w,
            bytes_l_to_r.clone(),
            progress.clone(),
            buf_size,
            shutdown_grace,
            right_w_shut.clone(),
            Some(client_first_byte_seen.clone()),
            Some(client_spoke.clone()),
            None,
        ));
        let r_to_l = std::pin::pin!(copy_one_way(
            &mut right_r,
            &mut left_w,
            bytes_r_to_l.clone(),
            progress.clone(),
            buf_size,
            shutdown_grace,
            left_w_shut.clone(),
            Some(first_byte_seen.clone()),
            None,
            Some(upstream_eof_seen.clone()),
        ));

        run_select_loop(
            l_to_r,
            r_to_l,
            guard.as_ref(),
            idle_timeout,
            first_byte_timeout,
            first_byte_timeout_start,
            &progress,
            &first_byte_seen,
            &upstream_eof_seen,
            &client_spoke,
        )
        .await
        // l_to_r and r_to_l drop here, releasing borrows on the halves.
    };

    // Close both write halves concurrently rather than sequentially — TLS
    // close_notify can take the full grace window per side, and serializing
    // the two doubles the worst-case bridge unwind time. Skip a side that
    // `copy_one_way` already shut down inline so we don't double-shutdown
    // a TLS writer.
    let left_pending_shutdown = !left_w_shut.load(Ordering::Acquire);
    let right_pending_shutdown = !right_w_shut.load(Ordering::Acquire);
    match (left_pending_shutdown, right_pending_shutdown) {
        (true, true) => {
            _ = tokio::join!(
                tokio::time::timeout(shutdown_grace, left_w.shutdown()),
                tokio::time::timeout(shutdown_grace, right_w.shutdown()),
            );
        }
        (true, false) => {
            _ = tokio::time::timeout(shutdown_grace, left_w.shutdown()).await;
        }
        (false, true) => {
            _ = tokio::time::timeout(shutdown_grace, right_w.shutdown()).await;
        }
        (false, false) => {}
    }

    BridgeOutcome {
        reason,
        bytes_l_to_r: bytes_l_to_r.load(Ordering::Relaxed),
        bytes_r_to_l: bytes_r_to_l.load(Ordering::Relaxed),
        age: opened_at.elapsed(),
        fatal_error,
    }
}

enum FirstByteWindow {
    /// Nothing configured or this timeout has been disarmed
    Inert,
    /// Waiting for client to send bytes first
    PendingClient(Duration),
    /// Actively counting down to the deadline
    Armed(std::pin::Pin<Box<tokio::time::Sleep>>),
}

#[expect(clippy::too_many_arguments)]
async fn run_select_loop<F1, F2>(
    mut l_to_r: std::pin::Pin<&mut F1>,
    mut r_to_l: std::pin::Pin<&mut F2>,
    guard: Option<&ShutdownGuard>,
    idle_timeout: Option<Duration>,
    first_byte_timeout: Option<Duration>,
    first_byte_timeout_start: FirstByteTimeoutStart,
    progress: &AtomicU64,
    first_byte_seen: &AtomicBool,
    upstream_eof_seen: &AtomicBool,
    client_spoke: &Notify,
) -> (BridgeCloseReason, Option<std::io::Error>)
where
    F1: Future<Output = Result<(), std::io::Error>>,
    F2: Future<Output = Result<(), std::io::Error>>,
{
    let mut idle = idle_timeout.map(IdleGuard::new);
    let mut first_byte = match (first_byte_timeout, first_byte_timeout_start) {
        (None, _) => FirstByteWindow::Inert,
        (Some(d), FirstByteTimeoutStart::BridgeOpen) => {
            FirstByteWindow::Armed(Box::pin(tokio::time::sleep(d)))
        }
        (Some(d), FirstByteTimeoutStart::ClientFirstByte) => FirstByteWindow::PendingClient(d),
    };
    let mut last_progress: u64 = 0;
    let mut l_to_r_done = false;
    let mut r_to_l_done = false;
    // The reason of whichever arm finished first — that's the one
    // that initiated the close. The second arm is just draining what
    // the peer had already buffered before its half-close. Without
    // this, a flow whose left side EOFed first followed by the right
    // side draining its buffer would be reported as `PeerEofRight`
    // (last to finish), which is misleading on the analysis side.
    let mut first_eof: Option<BridgeCloseReason> = None;

    loop {
        if l_to_r_done && r_to_l_done {
            return (first_eof.unwrap_or(BridgeCloseReason::PeerEofLeft), None);
        }

        // Settle the first-byte window for good once the upstream direction is
        // resolved: either the upstream wrote its first byte (`first_byte_seen`),
        // or it reached a clean EOF without ever writing (`upstream_eof_seen`).
        // The explicit EOF signal is set before graceful writer shutdown, because
        // `r_to_l_done` is not observable until that shutdown has completed.
        if !matches!(first_byte, FirstByteWindow::Inert)
            && (first_byte_seen.load(Ordering::Relaxed)
                || upstream_eof_seen.load(Ordering::Relaxed))
        {
            first_byte = FirstByteWindow::Inert;
        }

        let pending_client_window = match &first_byte {
            FirstByteWindow::PendingClient(d) => Some(*d),
            _ => None,
        };

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
            _ = async {
                match &mut first_byte {
                    FirstByteWindow::Armed(s) => s.as_mut().await,
                    _ => std::future::pending().await,
                }
            } => {
                // re-check here is needed in case it changed during the await
                if first_byte_seen.load(Ordering::Relaxed)
                    || upstream_eof_seen.load(Ordering::Relaxed)
                {
                    first_byte = FirstByteWindow::Inert;
                    continue;
                }
                return (BridgeCloseReason::FirstByteTimeout, None);
            }
            _ = async {
                match pending_client_window {
                    Some(_) => client_spoke.notified().await,
                    None => std::future::pending().await,
                }
            } => {
                // Client just sent its first byte: start the window from here
                if let Some(d) = pending_client_window {
                    first_byte = FirstByteWindow::Armed(Box::pin(tokio::time::sleep(d)));
                }
            }
            res = l_to_r.as_mut(), if !l_to_r_done => match res {
                Ok(()) => {
                    l_to_r_done = true;
                    if first_eof.is_none() {
                        first_eof = Some(BridgeCloseReason::PeerEofLeft);
                    }
                    if !r_to_l_done {
                        continue;
                    }
                    return (
                        first_eof.unwrap_or(BridgeCloseReason::PeerEofLeft),
                        None,
                    );
                }
                Err(e) => {
                    let reason = classify_copy_error(&e, CopyDirection::LeftToRight);
                    return (reason, Some(e));
                }
            },
            res = r_to_l.as_mut(), if !r_to_l_done => match res {
                Ok(()) => {
                    r_to_l_done = true;
                    if first_eof.is_none() {
                        first_eof = Some(BridgeCloseReason::PeerEofRight);
                    }
                    if !l_to_r_done {
                        continue;
                    }
                    return (
                        first_eof.unwrap_or(BridgeCloseReason::PeerEofRight),
                        None,
                    );
                }
                Err(e) => {
                    let reason = classify_copy_error(&e, CopyDirection::RightToLeft);
                    return (reason, Some(e));
                }
            },
        }
    }
}

#[expect(clippy::too_many_arguments)]
async fn copy_one_way<R, W>(
    reader: &mut R,
    writer: &mut W,
    bytes: Arc<AtomicU64>,
    progress: Arc<AtomicU64>,
    buf_size: usize,
    shutdown_grace: Duration,
    write_side_shut: Arc<AtomicBool>,
    first_byte_seen: Option<Arc<AtomicBool>>,
    first_byte_notify: Option<Arc<Notify>>,
    eof_seen: Option<Arc<AtomicBool>>,
) -> Result<(), std::io::Error>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buf_size];
    let mut copy_err: Option<std::io::Error> = None;
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                if let Some(seen) = &eof_seen {
                    seen.store(true, Ordering::Relaxed);
                }
                break;
            }
            Ok(n) => {
                // Record the first byte for this direction before write_all, so
                // backpressure on the far side never counts against the window.
                // `swap` detects the first transition so we notify exactly once
                if let Some(seen) = &first_byte_seen
                    && !seen.swap(true, Ordering::Relaxed)
                    && let Some(notify) = &first_byte_notify
                {
                    notify.notify_one();
                }
                if let Err(err) = writer.write_all(&buf[..n]).await {
                    copy_err = Some(err);
                    break;
                }
                bytes.fetch_add(n as u64, Ordering::Relaxed);
                progress.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => {
                copy_err = Some(err);
                break;
            }
        }
    }

    // Single shutdown path for clean EOF, read errors, and write
    // errors alike: one bounded shutdown attempt, mark the side shut
    // so the outer `run_bridge` post-loop shutdown skips us, swallow
    // any shutdown error (the writer may already be poisoned by a
    // prior write error — that's expected). Bounded by
    // `shutdown_grace` so a TLS writer waiting on the peer's
    // close_notify can't wedge this future indefinitely.
    _ = tokio::time::timeout(shutdown_grace, writer.shutdown()).await;
    write_side_shut.store(true, Ordering::Release);

    match copy_err {
        Some(err) => Err(err),
        None => Ok(()),
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
    use std::time::Duration;

    use super::*;

    use rama_core::graceful::Shutdown;

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

    #[tokio::test(start_paused = true)]
    async fn forward_first_byte_timeout_fires_when_upstream_silent() {
        let svc = IoForwardService::default().with_first_byte_timeout(Duration::from_millis(100));

        let (mut a_user, a_proxy) = duplex(64);
        let (_b_user, b_proxy) = duplex(64);

        a_user.write_all(b"hello").await.unwrap();

        let started = tokio::time::Instant::now();
        tokio::time::timeout(
            Duration::from_secs(5),
            svc.serve(BridgeIo(a_proxy, b_proxy)),
        )
        .await
        .expect("silent-upstream bridge did not unwind")
        .unwrap();

        assert_eq!(
            started.elapsed(),
            Duration::from_millis(100),
            "first-byte timeout should fire exactly at its deadline",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn forward_first_byte_survives_when_upstream_speaks() {
        let svc = IoForwardService::default()
            .with_first_byte_timeout(Duration::from_millis(100))
            .with_first_byte_timeout_start(FirstByteTimeoutStart::BridgeOpen)
            .with_idle_timeout(Duration::from_millis(200));

        let (mut a_user, a_proxy) = duplex(64);
        let (mut b_user, b_proxy) = duplex(64);

        let task = tokio::spawn(async move {
            svc.serve(BridgeIo(a_proxy, b_proxy)).await.unwrap();
        });

        let started = tokio::time::Instant::now();

        b_user.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 1];
        a_user.read_exact(&mut buf).await.unwrap();

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("bridge did not unwind")
            .unwrap();
        assert!(
            started.elapsed() > Duration::from_millis(100),
            "bridge closed inside the first-byte window ({:?}); the upstream byte should have disarmed it",
            started.elapsed(),
        );
    }

    #[tokio::test(start_paused = true)]
    async fn forward_first_byte_disarmed_on_upstream_eof_before_byte() {
        // A clean upstream EOF (no byte ever written) is a `PeerEofRight`, not a
        // silent origin: the first-byte timer must disarm so it neither cuts the
        // client-half drain short nor misreports `FirstByteTimeout`. Anchored
        // from bridge open so the window is armed despite the silent client.
        let svc = IoForwardService::default()
            .with_first_byte_timeout(Duration::from_millis(10))
            .with_first_byte_timeout_start(FirstByteTimeoutStart::BridgeOpen)
            .with_shutdown_grace(Duration::from_millis(100));

        struct PendingShutdownIo {
            inner: tokio::io::DuplexStream,
        }

        impl tokio::io::AsyncRead for PendingShutdownIo {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.inner), cx, buf)
            }
        }

        impl tokio::io::AsyncWrite for PendingShutdownIo {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.inner), cx, buf)
            }

            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.inner), cx)
            }

            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Pending
            }
        }

        let (a_user, a_proxy) = duplex(64);
        let a_proxy = PendingShutdownIo { inner: a_proxy };
        let (b_user, b_proxy) = duplex(64);

        let task = tokio::spawn(async move {
            svc.serve(BridgeIo(a_proxy, b_proxy)).await.unwrap();
        });

        // Upstream accepts, then EOFs immediately without ever writing.
        drop(b_user);

        // The upstream EOF is observed immediately, but half-closing the client
        // writer remains pending until shutdown_grace. Advance past the
        // first-byte deadline but not the shutdown grace: the bridge must still
        // be alive rather than misreporting FirstByteTimeout.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !task.is_finished(),
            "first-byte timer fired while graceful shutdown followed a clean upstream EOF",
        );

        // Client EOFs too -> bridge winds down cleanly.
        drop(a_user);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("bridge did not unwind after client EOF")
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn forward_first_byte_survives_client_backpressure() {
        let svc = IoForwardService::default()
            .with_first_byte_timeout(Duration::from_millis(100))
            .with_first_byte_timeout_start(FirstByteTimeoutStart::BridgeOpen)
            .with_idle_timeout(Duration::from_millis(200));

        // The upstream response is larger than the client-side buffer, so the
        // right-to-left write cannot complete. Reading the response from the
        // upstream must still disarm the first byte timer.
        let (_a_user, a_proxy) = duplex(1);
        let (mut b_user, b_proxy) = duplex(64);

        let task = tokio::spawn(async move {
            svc.serve(BridgeIo(a_proxy, b_proxy)).await.unwrap();
        });

        let started = tokio::time::Instant::now();
        b_user.write_all(b"response").await.unwrap();

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("bridge did not unwind")
            .unwrap();
        assert_eq!(
            started.elapsed(),
            Duration::from_millis(200),
            "upstream response should disarm first-byte timeout even when the client is backpressured",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn forward_first_byte_client_start_anchors_on_client_byte() {
        // Default `ClientFirstByte` anchor: the window must not start until the
        // client has sent, then it counts from that byte. A client that is slow
        // to speak is never cut while the origin waits to be asked.
        let svc = IoForwardService::default().with_first_byte_timeout(Duration::from_millis(100));

        let (mut a_user, a_proxy) = duplex(64);
        let (_b_user, b_proxy) = duplex(64);

        let task = tokio::spawn(async move {
            svc.serve(BridgeIo(a_proxy, b_proxy)).await.unwrap();
        });

        // Client stays silent well past the window; the upstream is silent too.
        // With the anchor at the client's first byte the window has not started,
        // so the bridge must survive.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !task.is_finished(),
            "first-byte window started before the client sent anything",
        );

        // Now the client speaks, the window starts from here. The upstream
        // stays silent, so it must fire exactly one window later.
        let spoke_at = tokio::time::Instant::now();
        a_user.write_all(b"hello").await.unwrap();

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("silent-upstream bridge did not unwind")
            .unwrap();
        assert_eq!(
            spoke_at.elapsed(),
            Duration::from_millis(100),
            "first-byte window should be measured from the client's first byte",
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

    /// `copy_one_way` must call `writer.shutdown()` exactly once
    /// regardless of whether the loop exited via clean EOF, a read
    /// error, or a write error. Without this the outer `run_bridge`
    /// post-loop shutdown would re-enter `shutdown` on a writer that
    /// already errored — fine for current TLS impls, fragile against
    /// future ones. Pin the contract.
    #[tokio::test]
    async fn copy_one_way_calls_shutdown_once_on_write_error() {
        use std::sync::atomic::AtomicUsize;
        use std::task::{Context, Poll};

        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        struct ReadOnce {
            done: bool,
        }
        impl AsyncRead for ReadOnce {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                if self.done {
                    return Poll::Ready(Ok(()));
                }
                self.done = true;
                buf.put_slice(b"hi");
                Poll::Ready(Ok(()))
            }
        }

        struct CountingWriter {
            shutdown_calls: Arc<AtomicUsize>,
            fail_write: bool,
        }
        impl AsyncWrite for CountingWriter {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                if self.fail_write {
                    Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "test",
                    )))
                } else {
                    Poll::Ready(Ok(buf.len()))
                }
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.shutdown_calls.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(()))
            }
        }

        let shutdown_calls = Arc::new(AtomicUsize::new(0));
        let mut reader = ReadOnce { done: false };
        let mut writer = CountingWriter {
            shutdown_calls: shutdown_calls.clone(),
            fail_write: true,
        };
        let bytes = Arc::new(AtomicU64::new(0));
        let progress = Arc::new(AtomicU64::new(0));
        let write_side_shut = Arc::new(AtomicBool::new(false));
        let res = copy_one_way(
            &mut reader,
            &mut writer,
            bytes,
            progress,
            64,
            Duration::from_millis(50),
            write_side_shut.clone(),
            None,
            None,
            None,
        )
        .await;
        assert!(res.is_err(), "expected write error to propagate");
        assert_eq!(
            shutdown_calls.load(Ordering::Relaxed),
            1,
            "shutdown must be called exactly once even on the write-error path",
        );
        assert!(
            write_side_shut.load(Ordering::Acquire),
            "write_side_shut flag must be set so run_bridge skips a duplicate shutdown",
        );
    }
}
