use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::std::sync::Arc;

use super::IdleGuard;

use rama_core::graceful::ShutdownGuard;
use rama_core::rt::Executor;
use rama_core::telemetry::tracing;
use rama_core::{
    Service,
    extensions::ExtensionsRef,
    io::{AbortIo, BridgeIo, Io},
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
    S: Io + Unpin + ExtensionsRef,
    T: Io + Unpin + ExtensionsRef,
{
    type Output = IoForwardOutcome;
    type Error = IoForwardError;

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

        // The outcome is returned either way; the `Result` variant signals a
        // clean vs errored close (an errored close wraps the outcome in
        // [`IoForwardError`], which still exposes it).
        let errored = outcome
            .fatal_error
            .as_ref()
            .is_some_and(|err| !crate::conn::is_connection_error(err));
        if errored {
            Err(IoForwardError(outcome))
        } else {
            Ok(outcome)
        }
    }
}

/// The result of an [`IoForwardService`] bridge, describing why and how the
/// forward ended.
///
/// Returned as the service [`Output`](IoForwardService) on a clean or benign
/// close. A genuine (non-connection) error close instead yields an
/// [`IoForwardError`], which carries this same outcome. Either way callers get
/// the full picture: benign peer disconnects (connection resets/aborts) are
/// reported as `Ok`, still carrying the classified [`reason`](Self::reason) and
/// [`fatal_error`](Self::fatal_error).
#[derive(Debug)]
pub struct IoForwardOutcome {
    reason: BridgeCloseReason,
    bytes_l_to_r: u64,
    bytes_r_to_l: u64,
    age: Duration,
    fatal_error: Option<std::io::Error>,
}

impl IoForwardOutcome {
    /// Why the bridge closed.
    #[must_use]
    pub fn reason(&self) -> BridgeCloseReason {
        self.reason
    }

    /// Bytes copied from the left (ingress) half to the right (egress) half.
    #[must_use]
    pub fn bytes_l_to_r(&self) -> u64 {
        self.bytes_l_to_r
    }

    /// Bytes copied from the right (egress) half to the left (ingress) half.
    #[must_use]
    pub fn bytes_r_to_l(&self) -> u64 {
        self.bytes_r_to_l
    }

    /// Total bytes copied in both directions.
    #[must_use]
    pub fn bytes_total(&self) -> u64 {
        self.bytes_l_to_r.saturating_add(self.bytes_r_to_l)
    }

    /// How long the bridge was open.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.age
    }

    /// The fatal I/O error that ended the bridge, if any.
    #[must_use]
    pub fn fatal_error(&self) -> Option<&std::io::Error> {
        self.fatal_error.as_ref()
    }
}

impl std::fmt::Display for IoForwardOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(proxy) I/O forwarder closed: reason={}, bytes_l_to_r={}, bytes_r_to_l={}, age_ms={}",
            self.reason,
            self.bytes_l_to_r,
            self.bytes_r_to_l,
            u64::try_from(self.age.as_millis()).unwrap_or(u64::MAX),
        )?;
        if let Some(err) = &self.fatal_error {
            write!(f, ", error={err}")?;
        }
        Ok(())
    }
}

/// The [`Error`](IoForwardService) returned by [`IoForwardService`] when the
/// bridge ended on a genuine (non-connection) I/O error.
///
/// Wraps the full [`IoForwardOutcome`] of the closed bridge: [`Deref`] or
/// [`outcome`](Self::outcome) to inspect the reason, byte counts, age, and the
/// underlying error.
///
/// [`Deref`]: std::ops::Deref
#[derive(Debug)]
pub struct IoForwardError(IoForwardOutcome);

impl IoForwardError {
    /// The outcome of the bridge that errored.
    #[must_use]
    pub fn outcome(&self) -> &IoForwardOutcome {
        &self.0
    }

    /// Consume this error, returning the underlying [`IoForwardOutcome`].
    #[must_use]
    pub fn into_outcome(self) -> IoForwardOutcome {
        self.0
    }
}

impl std::ops::Deref for IoForwardError {
    type Target = IoForwardOutcome;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for IoForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for IoForwardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0
            .fatal_error()
            .map(|err| err as &(dyn std::error::Error + 'static))
    }
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
) -> IoForwardOutcome
where
    S: Io + Unpin + ExtensionsRef,
    T: Io + Unpin + ExtensionsRef,
{
    let opened_at = Instant::now();
    let aborts = Arc::new(Aborts::new(&left, &right));
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

    let (mut reason, mut fatal_error) = {
        let l_to_r = std::pin::pin!(copy_one_way(
            &mut left_r,
            &mut right_w,
            bytes_l_to_r.clone(),
            progress.clone(),
            buf_size,
            shutdown_grace,
            right_w_shut.clone(),
            (aborts.clone(), Side::Right),
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
            (aborts.clone(), Side::Left),
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
    // An aborted side resets as it drops here, with nothing left to close.
    let left_pending_shutdown = !aborts.aborted(Side::Left) && !left_w_shut.load(Ordering::Acquire);
    let right_pending_shutdown =
        !aborts.aborted(Side::Right) && !right_w_shut.load(Ordering::Acquire);
    let (left_err, right_err) = tokio::join!(
        close_within(left_pending_shutdown, &mut left_w, shutdown_grace),
        close_within(right_pending_shutdown, &mut right_w, shutdown_grace),
    );
    // A reset found by this last close is reflected too, unless an earlier one already was;
    // an expired grace window is not a reset.
    for (err, side_reason) in [
        (left_err, BridgeCloseReason::WriteErrorLeft),
        (right_err, BridgeCloseReason::WriteErrorRight),
    ] {
        if let Some(err) = err.filter(reflects_as_abort) {
            aborts.trigger();
            if !fatal_error.as_ref().is_some_and(reflects_as_abort) {
                reason = side_reason;
                fatal_error = Some(err);
            }
        }
    }

    IoForwardOutcome {
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
    (aborts, writer_side): (Arc<Aborts>, Side),
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
        // Only tokio's own IO resources charge the coop budget; an in-memory or
        // TLS-buffered reader can stay ready indefinitely. Charge it here so a
        // busy tunnel still yields to the other direction and to shutdown.
        tokio::task::consume_budget().await;
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
                // TLS or HTTP/3 writers may hold data until flushed, as tokio's copy knows.
                if let Err(err) = writer.write_all(&buf[..n]).await {
                    copy_err = Some(err);
                    break;
                }
                if let Err(err) = writer.flush().await {
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

    // A failure resets both sides (RFC 9113 §8.5, RFC 9114 §4.4); else one bounded orderly
    // shutdown, so a TLS writer waiting on close_notify cannot wedge this future.
    if copy_err.as_ref().is_some_and(reflects_as_abort) {
        aborts.trigger();
    }
    if !aborts.aborted(writer_side)
        && let Ok(Err(err)) = tokio::time::timeout(shutdown_grace, writer.shutdown()).await
        && !copy_err.as_ref().is_some_and(reflects_as_abort)
        && reflects_as_abort(&err)
    {
        // The half-close itself found the peer reset, also after an orderly-looking end: fail
        // as a write would, ending the relay.
        aborts.trigger();
        copy_err = Some(err);
    }
    write_side_shut.store(true, Ordering::Release);

    match copy_err {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Close `writer` in order within `grace`, if `pending`: the error it returns, if any. An
/// expired grace window is no error.
async fn close_within<W>(pending: bool, writer: &mut W, grace: Duration) -> Option<std::io::Error>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if !pending {
        return None;
    }
    tokio::time::timeout(grace, writer.shutdown())
        .await
        .ok()
        .and_then(Result::err)
}

/// The [`AbortIo`] each side publishes in its own extensions, if any.
struct Aborts {
    left: Option<Arc<AbortIo>>,
    right: Option<Arc<AbortIo>>,
    triggered: AtomicBool,
}

impl Aborts {
    fn new(left: &impl ExtensionsRef, right: &impl ExtensionsRef) -> Self {
        Self {
            left: left.extensions().self_get_arc(),
            right: right.extensions().self_get_arc(),
            triggered: AtomicBool::new(false),
        }
    }

    /// Reset both sides; one without an [`AbortIo`] is still closed in order.
    fn trigger(&self) {
        if self.triggered.swap(true, Ordering::AcqRel) {
            return;
        }
        for abort in [&self.left, &self.right].into_iter().flatten() {
            abort.abort();
        }
    }

    /// Whether this side was reset, so it must not be closed in order as well.
    fn aborted(&self, side: Side) -> bool {
        let abort = match side {
            Side::Left => &self.left,
            Side::Right => &self.right,
        };
        abort.is_some() && self.triggered.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy)]
enum Side {
    Left,
    Right,
}

/// A side that failed is reflected as a reset. A peer that stopped reading (`BrokenPipe`)
/// or closed without TLS close_notify (`UnexpectedEof`, common in the wild) ended in order.
fn reflects_as_abort(err: &std::io::Error) -> bool {
    !matches!(
        err.kind(),
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof
    )
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

fn emit_close_event(outcome: &IoForwardOutcome) {
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
    use std::assert_matches;
    use std::time::Duration;

    use super::*;

    use rama_core::{ServiceInput, graceful::Shutdown};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// A bridge of plain test I/O, given the extensions a bridge requires.
    fn bridge<S, T>(left: S, right: T) -> BridgeIo<ServiceInput<S>, ServiceInput<T>> {
        BridgeIo(ServiceInput::new(left), ServiceInput::new(right))
    }

    async fn run_default<S, T>(left: S, right: T) -> IoForwardOutcome
    where
        S: Io + Unpin,
        T: Io + Unpin,
    {
        let svc = IoForwardService::default();
        svc.serve(bridge(left, right)).await.unwrap()
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

    /// Reads EOF right away and records every write it gets.
    #[derive(Clone, Default)]
    struct WriteRecorder(Arc<parking_lot::Mutex<Vec<Vec<u8>>>>);

    impl tokio::io::AsyncRead for WriteRecorder {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for WriteRecorder {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0.lock().push(buf.to_vec());
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn forward_sends_peeked_prefix_with_buffered_rest() {
        use rama_core::bytes::Bytes;
        use rama_core::io::{PrefixedIo, ReplayReader};

        // A 2 byte peek splits a length-prefixed request;
        // some servers reset on a first segment that short.
        let (mut client, proxy) = duplex(64);
        client.write_all(b"\x00\x05hello").await.unwrap();
        drop(client);

        let left = PrefixedIo::new(ReplayReader::new(Bytes::from_static(b"\x00\x00")), proxy);
        let right = WriteRecorder::default();
        let writes = right.0.clone();

        run_default(left, right).await;

        assert_eq!(*writes.lock(), [b"\x00\x00\x00\x05hello".to_vec()]);
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
            svc.serve(bridge(a_proxy, b_proxy)).await.unwrap();
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
            svc.serve(bridge(a_proxy, b_proxy)).await.unwrap();
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
        let outcome =
            tokio::time::timeout(Duration::from_secs(2), svc.serve(bridge(a_proxy, b_proxy)))
                .await
                .expect("idle bridge did not unwind within 2s")
                .unwrap();
        assert_eq!(outcome.reason(), BridgeCloseReason::IdleTimeout);
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
        tokio::time::timeout(Duration::from_secs(5), svc.serve(bridge(a_proxy, b_proxy)))
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
            svc.serve(bridge(a_proxy, b_proxy)).await.unwrap();
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
            svc.serve(bridge(a_proxy, b_proxy)).await.unwrap();
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
            svc.serve(bridge(a_proxy, b_proxy)).await.unwrap();
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
            svc.serve(bridge(a_proxy, b_proxy)).await.unwrap();
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
            svc.serve(bridge(a_proxy, b_proxy)).await.unwrap();
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
    async fn forward_outcome_reports_reason_and_byte_counts() {
        let (mut a_user, a_proxy) = duplex(64);
        let (mut b_user, b_proxy) = duplex(64);

        let task = tokio::spawn(async move { run_default(a_proxy, b_proxy).await });

        a_user.write_all(b"abc").await.unwrap();
        let mut buf = [0u8; 3];
        b_user.read_exact(&mut buf).await.unwrap();
        b_user.write_all(b"defgh").await.unwrap();
        let mut buf = [0u8; 5];
        a_user.read_exact(&mut buf).await.unwrap();

        drop(a_user);
        drop(b_user);
        let outcome = task.await.unwrap();

        assert_matches!(
            outcome.reason(),
            BridgeCloseReason::PeerEofLeft | BridgeCloseReason::PeerEofRight,
            "unexpected reason: {:?}",
            outcome.reason(),
        );
        assert_eq!(outcome.bytes_l_to_r(), 3);
        assert_eq!(outcome.bytes_r_to_l(), 5);
        assert_eq!(outcome.bytes_total(), 8);
        assert!(outcome.fatal_error().is_none());
    }

    #[tokio::test]
    async fn forward_default_executor_means_no_shutdown_observation() {
        // Without a graceful executor, the bridge does not observe an
        // external shutdown signal and only ends on EOF/error/idle.
        let svc = IoForwardService::default();

        let (a_user, a_proxy) = duplex(64);
        let (b_user, b_proxy) = duplex(64);

        let task = tokio::spawn(async move {
            svc.serve(bridge(a_proxy, b_proxy)).await.unwrap();
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
            (
                Arc::new(Aborts {
                    left: None,
                    right: None,
                    triggered: AtomicBool::new(false),
                }),
                Side::Right,
            ),
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

    /// An [`Io`] whose reader either errors once with a configured kind, or
    /// pends forever; its writer always accepts. Used to drive the bridge into
    /// a specific terminal error reason.
    struct ScriptedIo {
        read_err: Option<std::io::ErrorKind>,
        errored: bool,
    }

    impl ScriptedIo {
        fn erroring(kind: std::io::ErrorKind) -> Self {
            Self {
                read_err: Some(kind),
                errored: false,
            }
        }

        fn pending() -> Self {
            Self {
                read_err: None,
                errored: false,
            }
        }
    }

    impl tokio::io::AsyncRead for ScriptedIo {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.read_err {
                Some(kind) if !self.errored => {
                    self.errored = true;
                    std::task::Poll::Ready(Err(std::io::Error::new(kind, "scripted")))
                }
                // Never yields data or EOF: keeps this direction open so the
                // bridge closes on the other direction's error.
                _ => std::task::Poll::Pending,
            }
        }
    }

    impl tokio::io::AsyncWrite for ScriptedIo {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// How a test side's read ends.
    #[derive(Clone, Copy)]
    enum ReadEnd {
        Eof,
        Fail(std::io::ErrorKind),
        Pend,
    }

    /// One bridge side: its read ends once as `end`, then pends; it counts its shutdowns,
    /// failing them with `shutdown_error` if set, and when it publishes one, its [`AbortIo`]
    /// calls.
    struct TestSide {
        end: ReadEnd,
        shutdowns: Arc<AtomicU64>,
        shutdown_error: Option<std::io::ErrorKind>,
    }

    impl tokio::io::AsyncRead for TestSide {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match std::mem::replace(&mut self.end, ReadEnd::Pend) {
                ReadEnd::Eof => std::task::Poll::Ready(Ok(())),
                ReadEnd::Fail(kind) => std::task::Poll::Ready(Err(kind.into())),
                ReadEnd::Pend => std::task::Poll::Pending,
            }
        }
    }

    impl tokio::io::AsyncWrite for TestSide {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(self.shutdown_error.map_or(Ok(()), |kind| Err(kind.into())))
        }
    }

    struct Counts {
        shutdowns: Arc<AtomicU64>,
        aborts: Arc<AtomicU64>,
    }

    impl Counts {
        fn get(&self) -> (u64, u64) {
            (
                self.shutdowns.load(Ordering::SeqCst),
                self.aborts.load(Ordering::SeqCst),
            )
        }
    }

    fn side(end: ReadEnd, abortable: bool) -> (ServiceInput<TestSide>, Counts) {
        side_failing_shutdown(end, abortable, None)
    }

    fn side_failing_shutdown(
        end: ReadEnd,
        abortable: bool,
        shutdown_error: Option<std::io::ErrorKind>,
    ) -> (ServiceInput<TestSide>, Counts) {
        let counts = Counts {
            shutdowns: Arc::new(AtomicU64::new(0)),
            aborts: Arc::new(AtomicU64::new(0)),
        };
        let io = ServiceInput::new(TestSide {
            end,
            shutdowns: counts.shutdowns.clone(),
            shutdown_error,
        });
        if abortable {
            let aborts = counts.aborts.clone();
            io.extensions().insert(AbortIo::new(move || {
                aborts.fetch_add(1, Ordering::SeqCst);
            }));
        }
        (io, counts)
    }

    /// A writer that holds what it is given until flushed, as TLS or HTTP/3 may.
    struct HeldUntilFlushed {
        held: Vec<u8>,
        flushed: Arc<parking_lot::Mutex<Vec<u8>>>,
    }

    impl tokio::io::AsyncRead for HeldUntilFlushed {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl tokio::io::AsyncWrite for HeldUntilFlushed {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.held.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let held = std::mem::take(&mut self.held);
            self.flushed.lock().extend(held);
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Relayed data reaches the peer while the source stays open, also through a writer
    /// that only sends on flush.
    #[tokio::test]
    async fn relayed_data_is_flushed_while_the_source_stays_open() {
        let (mut source, left) = duplex(64);
        let flushed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let right = HeldUntilFlushed {
            held: Vec::new(),
            flushed: flushed.clone(),
        };
        let bridge = tokio::spawn(async move {
            _ = IoForwardService::default().serve(bridge(left, right)).await;
        });
        source.write_all(b"data").await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while flushed.lock().as_slice() != b"data" {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the relayed data was never flushed");
        bridge.abort();
    }

    /// RFC 9113 §8.5, RFC 9114 §4.4: a failed side is reflected as a reset of both sides,
    /// while an orderly end, a stopped reader or a close without close_notify is not.
    #[tokio::test]
    async fn failures_are_reflected_as_resets_and_orderly_ends_are_not() {
        use std::io::ErrorKind::{
            BrokenPipe, ConnectionAborted, ConnectionReset, InvalidData, TimedOut, UnexpectedEof,
        };
        for kind in [ConnectionReset, ConnectionAborted, InvalidData, TimedOut] {
            let (left, left_counts) = side(ReadEnd::Fail(kind), true);
            let (right, right_counts) = side(ReadEnd::Pend, true);
            _ = IoForwardService::default()
                .serve(BridgeIo(left, right))
                .await;
            // Reset, never also closed in order.
            assert_eq!(left_counts.get(), (0, 1), "{kind:?}");
            assert_eq!(right_counts.get(), (0, 1), "{kind:?}");
        }
        for kind in [BrokenPipe, UnexpectedEof] {
            let (left, left_counts) = side(ReadEnd::Fail(kind), true);
            let (right, right_counts) = side(ReadEnd::Pend, true);
            _ = IoForwardService::default()
                .serve(BridgeIo(left, right))
                .await;
            assert_eq!(left_counts.get(), (1, 0), "{kind:?}");
            assert_eq!(right_counts.get(), (1, 0), "{kind:?}");
        }
        let (left, left_counts) = side(ReadEnd::Eof, true);
        let (right, right_counts) = side(ReadEnd::Eof, true);
        IoForwardService::default()
            .serve(BridgeIo(left, right))
            .await
            .unwrap();
        assert_eq!(left_counts.get(), (1, 0));
        assert_eq!(right_counts.get(), (1, 0));
    }

    /// The half-close after one side ends can itself find the other side reset: that resets both
    /// sides and ends the relay. A stopped reader found there stays an orderly half-close, with
    /// the other direction still open.
    #[tokio::test(start_paused = true)]
    async fn a_reset_found_by_the_half_close_ends_the_relay() {
        use std::io::ErrorKind::{BrokenPipe, ConnectionReset};
        async fn ended(bridge: BridgeIo<ServiceInput<TestSide>, ServiceInput<TestSide>>) -> bool {
            tokio::time::timeout(
                Duration::from_secs(1),
                IoForwardService::default().serve(bridge),
            )
            .await
            .is_ok()
        }
        for ending_left in [true, false] {
            for (shutdown, reflected) in [(ConnectionReset, true), (BrokenPipe, false)] {
                for abortable in [true, false] {
                    let case = format!("left={ending_left} {shutdown:?} abortable={abortable}");
                    let (ending, ending_counts) = side(ReadEnd::Eof, abortable);
                    let (failing, failing_counts) =
                        side_failing_shutdown(ReadEnd::Pend, abortable, Some(shutdown));
                    let ended = if ending_left {
                        ended(BridgeIo(ending, failing)).await
                    } else {
                        ended(BridgeIo(failing, ending)).await
                    };
                    assert_eq!(ended, reflected, "{case}");
                    let aborts = u64::from(reflected && abortable);
                    // A reset side is not also closed in order; one without abort still is.
                    let ending_shutdowns = u64::from(reflected && !abortable);
                    assert_eq!(ending_counts.get(), (ending_shutdowns, aborts), "{case}");
                    assert_eq!(failing_counts.get(), (1, aborts), "{case}");
                }
            }
        }
    }

    /// A reset found by any close is reflected, also after an orderly-looking end (a stopped
    /// reader, a close without close_notify): by the half-close that follows it, and by the
    /// relay's last close of the other side. It is what the relay reports, naming that side.
    #[tokio::test]
    async fn a_reset_found_by_any_close_is_reflected() {
        use std::io::ErrorKind::{BrokenPipe, ConnectionReset, UnexpectedEof};
        for ending_left in [true, false] {
            for benign in [BrokenPipe, UnexpectedEof] {
                for abortable in [true, false] {
                    // The half-close after the benign end resets (`inline`), or the last close
                    // of the side that ended does.
                    for inline in [true, false] {
                        let case = format!(
                            "left={ending_left} {benign:?} abortable={abortable} inline={inline}"
                        );
                        let (ending, ending_counts) = side_failing_shutdown(
                            ReadEnd::Fail(benign),
                            abortable,
                            (!inline).then_some(ConnectionReset),
                        );
                        let (other, other_counts) = side_failing_shutdown(
                            ReadEnd::Pend,
                            abortable,
                            inline.then_some(ConnectionReset),
                        );
                        let outcome = tokio::time::timeout(Duration::from_secs(1), async {
                            if ending_left {
                                IoForwardService::default()
                                    .serve(BridgeIo(ending, other))
                                    .await
                            } else {
                                IoForwardService::default()
                                    .serve(BridgeIo(other, ending))
                                    .await
                            }
                        })
                        .await
                        .expect(&case)
                        .expect(&case);
                        let aborts = u64::from(abortable);
                        // The other side is closed by the half-close; the ending side by the
                        // last close unless the inline reset already reset it.
                        let ending_shutdowns = u64::from(!(inline && abortable));
                        assert_eq!(ending_counts.get(), (ending_shutdowns, aborts), "{case}");
                        assert_eq!(other_counts.get(), (1, aborts), "{case}");
                        assert_eq!(
                            outcome.fatal_error().map(std::io::Error::kind),
                            Some(ConnectionReset),
                            "{case}"
                        );
                        if !inline {
                            let expected = if ending_left {
                                BridgeCloseReason::WriteErrorLeft
                            } else {
                                BridgeCloseReason::WriteErrorRight
                            };
                            assert_eq!(outcome.reason(), expected, "{case}");
                        }
                    }
                }
            }
        }
    }

    /// A side that cannot be reset is still closed in order when the other one fails.
    #[tokio::test]
    async fn a_side_without_abort_is_closed_in_order() {
        for failing_left in [true, false] {
            let failure = ReadEnd::Fail(std::io::ErrorKind::ConnectionReset);
            let (left, left_counts) =
                side(if failing_left { failure } else { ReadEnd::Pend }, true);
            let (right, right_counts) =
                side(if failing_left { ReadEnd::Pend } else { failure }, false);
            _ = IoForwardService::default()
                .serve(BridgeIo(left, right))
                .await;
            assert_eq!(left_counts.get(), (0, 1), "failing_left={failing_left}");
            assert_eq!(right_counts.get(), (1, 0), "failing_left={failing_left}");
        }
    }

    #[tokio::test]
    async fn forward_genuine_error_surfaces_as_err_outcome() {
        // `InvalidData` is not a connection error, so it propagates as `Err`.
        let left = ScriptedIo::erroring(std::io::ErrorKind::InvalidData);
        let right = ScriptedIo::pending();

        let svc = IoForwardService::default();
        let err = svc
            .serve(bridge(left, right))
            .await
            .expect_err("genuine (non-connection) error must surface as Err");

        assert!(err.fatal_error().is_some());
        assert_matches!(
            err.outcome().reason(),
            BridgeCloseReason::ReadErrorLeft | BridgeCloseReason::WriteErrorRight,
            "unexpected reason: {:?}",
            err.reason(),
        );
    }

    #[tokio::test]
    async fn forward_connection_error_stays_ok_but_is_exposed() {
        // `ConnectionReset` is a benign peer disconnect: swallowed to `Ok`, but
        // the error and reason are still exposed on the outcome.
        let left = ScriptedIo::erroring(std::io::ErrorKind::ConnectionReset);
        let right = ScriptedIo::pending();

        let svc = IoForwardService::default();
        let outcome = svc
            .serve(bridge(left, right))
            .await
            .expect("connection reset must stay Ok");

        assert_eq!(outcome.reason(), BridgeCloseReason::ReadErrorLeft);
        assert!(outcome.fatal_error().is_some());
    }
}
