use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::std::sync::Arc;

use super::IdleGuard;

use crate::conn::LingeringClose;

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
const LINGER_BUF_SIZE: usize = kib(4);

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
    lingering_close: Option<LingeringClose>,
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
            lingering_close: None,
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

    generate_set_and_with! {
        /// Lingering close: after the bridge closed the left side, by
        /// convention the ingress, in order while its peer had not ended its
        /// stream yet, keep reading from it and discard the bytes before
        /// dropping it, within the given bounds.
        ///
        /// Closing a socket that still has unread input sends a reset instead
        /// of a clean close, and on Windows a reset makes the peer discard
        /// what it has not read yet, such as the tail of a response that was
        /// just forwarded to it. The same happens when the peer sends after
        /// the socket was closed. Lingering keeps the socket open until the
        /// peer is done, as nginx does with `lingering_close`.
        ///
        /// Only a left side that the bridge wrote to lingers: without
        /// forwarded data there is nothing to protect, and lingering on the
        /// upstream would keep downloading what nobody reads. A side that is
        /// reset does not linger either. Sides that publish an
        /// [`AbortIo`] (rama's TCP streams, TLS on them, HTTP/2 and HTTP/3
        /// tunnels) are reset when the other side fails, so lingering covers
        /// the closes in order: timeouts, one side ending its stream, and
        /// sides that cannot be reset.
        ///
        /// The bounds also stretch how long a reply still gets delivered
        /// after the other peer turned out gone: while it moves, up to the
        /// total timeout.
        ///
        /// Skipped when the bridge closes because of a shutdown, and cut
        /// short when a shutdown starts while lingering.
        ///
        /// `None` (the default) disables it.
        pub fn lingering_close(mut self, linger: Option<LingeringClose>) -> Self {
            self.lingering_close = linger;
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
            self.lingering_close,
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
    lingering_close: Option<LingeringClose>,
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

    // Whether each reader reached its end (EOF or an error), which decides
    // the sides that still linger.
    let l_to_r_end = Arc::new(DirectionEnd::default());
    let r_to_l_end = Arc::new(DirectionEnd::default());

    // How long the other direction may keep delivering what a gone peer sent
    // before it went away: a short window, extended while that makes
    // progress, up to the lingering total.
    let linger = lingering_close.filter(LingeringClose::is_enabled);
    let drain_idle = linger.map_or(shutdown_grace, |linger| {
        linger
            .idle_timeout()
            .min(linger.timeout())
            .max(shutdown_grace)
    });
    let drain_window = DrainWindow {
        idle: drain_idle,
        total: linger.map_or(drain_idle, |linger| linger.timeout().max(drain_idle)),
    };

    let (mut reason, mut fatal_error) = {
        let l_to_r = std::pin::pin!(copy_one_way(
            &mut left_r,
            &mut right_w,
            bytes_l_to_r.clone(),
            progress.clone(),
            buf_size,
            shutdown_grace,
            right_w_shut.clone(),
            l_to_r_end.clone(),
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
            r_to_l_end.clone(),
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
            Ends {
                l_to_r: &l_to_r_end,
                r_to_l: &r_to_l_end,
                l_to_r_bytes: &bytes_l_to_r,
                r_to_l_bytes: &bytes_r_to_l,
            },
            drain_window,
        )
        .await
        // l_to_r and r_to_l drop here, releasing borrows on the halves.
    };
    aborts.trigger_deferred();

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
        if let Some(err) = err.filter(AbortIo::reflects) {
            aborts.trigger();
            if !fatal_error.as_ref().is_some_and(AbortIo::reflects) {
                reason = side_reason;
                fatal_error = Some(err);
            }
        }
    }

    // Lingering is not part of the bridge's life.
    let age = opened_at.elapsed();

    // Only the left side, by convention the ingress, lingers: lingering on
    // the upstream would keep downloading what nobody reads. And only once
    // the bridge wrote to it, as there is nothing to protect otherwise.
    if let Some(linger) = linger
        && reason != BridgeCloseReason::Shutdown
        && !l_to_r_end.read_ended()
        && !aborts.aborted(Side::Left)
        && bytes_r_to_l.load(Ordering::Relaxed) > 0
    {
        // The upstream closes now, not once the client is done.
        drop((right_r, right_w));
        linger_drain(&mut left_r, linger, guard.as_ref()).await;
    }

    IoForwardOutcome {
        reason,
        bytes_l_to_r: bytes_l_to_r.load(Ordering::Relaxed),
        bytes_r_to_l: bytes_r_to_l.load(Ordering::Relaxed),
        age,
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

/// How the select loop ended: the reason and the fatal error, if any.
type LoopEnd = (BridgeCloseReason, Option<std::io::Error>);

/// How long a [`Draining`] direction may keep going: `idle` without
/// progress, `total` at most.
#[derive(Debug, Clone, Copy)]
struct DrainWindow {
    idle: Duration,
    total: Duration,
}

/// A direction whose write found its peer gone. What that peer sent before
/// may still be on its way through the other direction, so the bridge keeps
/// that one running for a while. A reset is reflected only after that.
struct Draining<'a> {
    reason: BridgeCloseReason,
    error: std::io::Error,
    deadline: std::pin::Pin<Box<tokio::time::Sleep>>,
    give_up: tokio::time::Instant,
    /// The bytes the draining direction wrote, and how many when last seen.
    written: &'a AtomicU64,
    seen: u64,
}

impl<'a> Draining<'a> {
    fn new(
        reason: BridgeCloseReason,
        error: std::io::Error,
        window: DrainWindow,
        written: &'a AtomicU64,
    ) -> Self {
        let now = tokio::time::Instant::now();
        let give_up = after(now, window.total);
        Self {
            reason,
            error,
            deadline: Box::pin(tokio::time::sleep_until(
                after(now, window.idle).min(give_up),
            )),
            give_up,
            written,
            seen: written.load(Ordering::Relaxed),
        }
    }

    /// The deadline passed: keep draining for another `idle` if bytes went
    /// out since, and the total allows.
    fn extend(&mut self, idle: Duration) -> bool {
        let now = tokio::time::Instant::now();
        let written = self.written.load(Ordering::Relaxed);
        if written == self.seen || now >= self.give_up {
            return false;
        }
        self.seen = written;
        self.deadline
            .as_mut()
            .reset(after(now, idle).min(self.give_up));
        true
    }

    fn finish(self) -> LoopEnd {
        (self.reason, Some(self.error))
    }

    /// End with what the other direction ran into, if that is the reset
    /// that gets reflected while the drain's own error is not.
    fn finish_with(self, reason: BridgeCloseReason, error: std::io::Error) -> LoopEnd {
        if AbortIo::reflects(&error) && !AbortIo::reflects(&self.error) {
            (reason, Some(error))
        } else {
            self.finish()
        }
    }
}

/// `instant + duration`, or a far-off instant if that does not fit.
fn after(instant: tokio::time::Instant, duration: Duration) -> tokio::time::Instant {
    instant
        .checked_add(duration)
        .unwrap_or_else(|| instant + Duration::from_secs(86_400 * 365 * 30))
}

/// A write or half-close error saying the peer is gone, rather than that we
/// failed.
fn is_peer_gone(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        err.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::NotConnected
    )
}

/// How one direction of the bridge ended.
#[derive(Default)]
struct DirectionEnd {
    /// Its reader reached its end: EOF or an error.
    read_ended: AtomicBool,
    /// Its error came from its writer (a write, flush or the half-close)
    /// rather than from its reader.
    write_failed: AtomicBool,
}

impl DirectionEnd {
    fn mark_read_ended(&self) {
        self.read_ended.store(true, Ordering::Release);
    }

    fn mark_write_failed(&self) {
        self.write_failed.store(true, Ordering::Release);
    }

    fn read_ended(&self) -> bool {
        self.read_ended.load(Ordering::Acquire)
    }

    fn write_failed(&self) -> bool {
        self.write_failed.load(Ordering::Acquire)
    }
}

/// How each direction ended, and how many bytes it wrote.
struct Ends<'a> {
    l_to_r: &'a DirectionEnd,
    r_to_l: &'a DirectionEnd,
    l_to_r_bytes: &'a AtomicU64,
    r_to_l_bytes: &'a AtomicU64,
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
    ends: Ends<'_>,
    drain_window: DrainWindow,
) -> LoopEnd
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
    let mut draining: Option<Draining> = None;

    loop {
        if l_to_r_done && r_to_l_done {
            return draining.map_or(
                (first_eof.unwrap_or(BridgeCloseReason::PeerEofLeft), None),
                Draining::finish,
            );
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
            () = cancelled => {
                return (BridgeCloseReason::Shutdown, draining.map(|d| d.error));
            }
            () = async {
                match draining.as_mut() {
                    Some(d) => d.deadline.as_mut().await,
                    None => std::future::pending().await,
                }
            } => {
                if draining
                    .as_mut()
                    .is_some_and(|d| d.extend(drain_window.idle))
                {
                    continue;
                }
                if let Some(d) = draining.take() {
                    return d.finish();
                }
            }
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
                return draining.map_or((BridgeCloseReason::IdleTimeout, None), Draining::finish);
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
                return draining.map_or((BridgeCloseReason::FirstByteTimeout, None), Draining::finish);
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
                }
                Err(e) => {
                    let write_failed = ends.l_to_r.write_failed();
                    let reason = classify_copy_error(CopyDirection::LeftToRight, write_failed);
                    // A write or the half-close found the right peer gone,
                    // but what it sent before may still be on its way to the
                    // left.
                    if draining.is_none() && !r_to_l_done && write_failed && is_peer_gone(&e) {
                        l_to_r_done = true;
                        draining = Some(Draining::new(reason, e, drain_window, ends.r_to_l_bytes));
                        continue;
                    }
                    return match draining {
                        Some(d) => d.finish_with(reason, e),
                        None => (reason, Some(e)),
                    };
                }
            },
            res = r_to_l.as_mut(), if !r_to_l_done => match res {
                Ok(()) => {
                    r_to_l_done = true;
                    if first_eof.is_none() {
                        first_eof = Some(BridgeCloseReason::PeerEofRight);
                    }
                }
                Err(e) => {
                    let write_failed = ends.r_to_l.write_failed();
                    let reason = classify_copy_error(CopyDirection::RightToLeft, write_failed);
                    if draining.is_none() && !l_to_r_done && write_failed && is_peer_gone(&e) {
                        r_to_l_done = true;
                        draining = Some(Draining::new(reason, e, drain_window, ends.l_to_r_bytes));
                        continue;
                    }
                    return match draining {
                        Some(d) => d.finish_with(reason, e),
                        None => (reason, Some(e)),
                    };
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
    end: Arc<DirectionEnd>,
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
                end.mark_read_ended();
                if let Some(seen) = &eof_seen {
                    seen.store(true, Ordering::Relaxed);
                }
                break;
            }
            Ok(n) => {
                // Record the first byte for this direction before writing, so
                // backpressure on the far side never counts against the window.
                // `swap` detects the first transition so we notify exactly once
                if let Some(seen) = &first_byte_seen
                    && !seen.swap(true, Ordering::Relaxed)
                    && let Some(notify) = &first_byte_notify
                {
                    notify.notify_one();
                }
                if let Err(err) = write_counted(writer, &buf[..n], &bytes).await {
                    end.mark_write_failed();
                    copy_err = Some(err);
                    break;
                }
                // TLS or HTTP/3 writers may hold data until flushed, as tokio's copy knows.
                if let Err(err) = writer.flush().await {
                    end.mark_write_failed();
                    copy_err = Some(err);
                    break;
                }
                progress.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => {
                end.mark_read_ended();
                copy_err = Some(err);
                break;
            }
        }
    }

    // A failure resets both sides (RFC 9113 §8.5, RFC 9114 §4.4). One our
    // reader found does so at once; one our writer found only once the other
    // direction delivered what the gone peer sent before (see `Draining`).
    if copy_err.as_ref().is_some_and(AbortIo::reflects) {
        aborts.reflect(!end.write_failed());
    }
    // Else one bounded orderly shutdown, so a TLS writer waiting on
    // close_notify cannot wedge this future. Marked first: this future may be
    // dropped mid-shutdown, and a TLS writer must not be shut down twice.
    if !aborts.aborted(writer_side) {
        write_side_shut.store(true, Ordering::Release);
        if let Ok(Err(err)) = tokio::time::timeout(shutdown_grace, writer.shutdown()).await
            && !copy_err.as_ref().is_some_and(AbortIo::reflects)
            && AbortIo::reflects(&err)
        {
            // The half-close itself found the peer reset, also after an
            // orderly-looking end: fail as a write would, ending the relay.
            end.mark_write_failed();
            aborts.reflect(false);
            copy_err = Some(err);
        }
    }
    write_side_shut.store(true, Ordering::Release);

    match copy_err {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Write all of `buf`, counting the bytes as they go out, so that a drain
/// can tell a peer that reads slowly but steadily from a stuck one.
async fn write_counted<W>(writer: &mut W, mut buf: &[u8], bytes: &AtomicU64) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    while !buf.is_empty() {
        match writer.write(buf).await {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                buf = &buf[n..];
                bytes.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
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
    /// A failure is to be reflected once the relay loop ends.
    deferred: AtomicBool,
}

impl Aborts {
    fn new(left: &impl ExtensionsRef, right: &impl ExtensionsRef) -> Self {
        Self {
            left: left.extensions().self_get_arc(),
            right: right.extensions().self_get_arc(),
            triggered: AtomicBool::new(false),
            deferred: AtomicBool::new(false),
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

    /// Reflect a failure: at once, or once the relay loop ends, see
    /// [`Self::trigger_deferred`].
    fn reflect(&self, now: bool) {
        if now {
            self.trigger();
        } else {
            self.deferred.store(true, Ordering::Release);
        }
    }

    /// Reset both sides if a failure was deferred.
    fn trigger_deferred(&self) {
        if self.deferred.load(Ordering::Acquire) {
            self.trigger();
        }
    }

    /// Whether this side is reset, now or once the relay loop ends, so it
    /// must not be closed in order as well.
    fn aborted(&self, side: Side) -> bool {
        let abort = match side {
            Side::Left => &self.left,
            Side::Right => &self.right,
        };
        abort.is_some()
            && (self.triggered.load(Ordering::Acquire) || self.deferred.load(Ordering::Acquire))
    }
}

#[derive(Clone, Copy)]
enum Side {
    Left,
    Right,
}

/// Read and discard until the peer ends its stream or a bound of `linger` is
/// hit, so that the side is not closed with unread input.
async fn linger_drain<R>(reader: &mut R, linger: LingeringClose, guard: Option<&ShutdownGuard>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::time::Instant;

    if !linger.is_enabled() {
        return;
    }
    let started = Instant::now();
    let give_up = after(started, linger.timeout());
    let deadline = |last_data: Instant| after(last_data, linger.idle_timeout()).min(give_up);
    let mut last_data = started;
    let mut discarded: u64 = 0;
    let mut buf = vec![0u8; LINGER_BUF_SIZE];
    // One timer for both bounds, moved only when it fires: cheaper than
    // resetting it on every read.
    let mut timer = std::pin::pin!(tokio::time::sleep_until(deadline(last_data)));
    let mut cancelled = std::pin::pin!(async {
        match guard {
            Some(guard) => guard.cancelled().await,
            None => std::future::pending().await,
        }
    });
    let end = loop {
        let room = linger.max_bytes().map_or(buf.len(), |max| {
            usize::try_from(max.saturating_sub(discarded)).map_or(buf.len(), |n| n.min(buf.len()))
        });
        if room == 0 {
            break "max_bytes";
        }
        tokio::select! {
            biased;
            () = &mut cancelled => break "shutdown",
            () = &mut timer => {
                let due = deadline(last_data);
                if due <= Instant::now() {
                    break if due == give_up { "timeout" } else { "idle" };
                }
                timer.as_mut().reset(due);
            }
            read = reader.read(&mut buf[..room]) => match read {
                Ok(0) => break "eof",
                Err(_) => break "error",
                Ok(n) => {
                    discarded += n as u64;
                    last_data = Instant::now();
                    if last_data >= give_up {
                        break "timeout";
                    }
                    // A reader that is always ready would otherwise keep the
                    // timer and the shutdown from ever being seen.
                    tokio::task::coop::consume_budget().await;
                }
            },
        }
    };
    tracing::trace!(
        target: "rama_net::proxy::forward",
        discarded,
        end,
        linger_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "io forward bridge lingered before close",
    );
}

/// The side an error of `direction` came from: its writer (a write, flush or
/// the half-close) if `write_failed`, else its reader.
fn classify_copy_error(direction: CopyDirection, write_failed: bool) -> BridgeCloseReason {
    match (direction, write_failed) {
        (CopyDirection::LeftToRight, false) => BridgeCloseReason::ReadErrorLeft,
        (CopyDirection::LeftToRight, true) => BridgeCloseReason::WriteErrorRight,
        (CopyDirection::RightToLeft, false) => BridgeCloseReason::ReadErrorRight,
        (CopyDirection::RightToLeft, true) => BridgeCloseReason::WriteErrorLeft,
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
        let end = Arc::new(DirectionEnd::default());
        let res = copy_one_way(
            &mut reader,
            &mut writer,
            bytes,
            progress,
            64,
            Duration::from_millis(50),
            write_side_shut.clone(),
            end.clone(),
            (
                Arc::new(Aborts {
                    left: None,
                    right: None,
                    triggered: AtomicBool::new(false),
                    deferred: AtomicBool::new(false),
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
        assert!(
            !end.read_ended(),
            "a write error leaves the read side open, so that side still lingers",
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

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let (connected, accepted) = tokio::join!(
            tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept(),
        );
        (connected.unwrap(), accepted.unwrap().0)
    }

    fn reply(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    const REQUEST: &[u8] = b"PING\r\n";
    const REPLY_LEN: usize = 6554;

    /// A client ↔ bridge ↔ origin chain over loopback sockets. The bridge's
    /// legs publish no [`AbortIo`], so it closes them in order, where it
    /// would reset rama's TCP streams.
    struct Chain {
        client: tokio::net::TcpStream,
        origin: tokio::net::TcpStream,
        bridge: tokio::task::JoinHandle<IoForwardOutcome>,
    }

    async fn chain(svc: IoForwardService) -> Chain {
        let (client, ingress) = tcp_pair().await;
        let (egress, origin) = tcp_pair().await;
        let bridge = tokio::spawn(async move {
            match svc.serve(bridge(ingress, egress)).await {
                Ok(outcome) => outcome,
                Err(err) => err.into_outcome(),
            }
        });
        Chain {
            client,
            origin,
            bridge,
        }
    }

    /// Lingers until something other than a timeout ends it.
    fn patient_linger() -> LingeringClose {
        LingeringClose::new().with_idle_timeout(Duration::from_secs(30))
    }

    async fn read_until_end(
        reader: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> (Vec<u8>, std::io::Result<()>) {
        let mut bytes = Vec::new();
        let mut buf = vec![0; kib(16)];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => return (bytes, Ok(())),
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(err) => return (bytes, Err(err)),
            }
        }
    }

    /// The origin replies and resets while the client is still sending, so
    /// the bridge closes the client leg with client bytes in flight. The
    /// client only starts reading later.
    async fn close_while_client_sends(
        linger: Option<LingeringClose>,
    ) -> (Vec<u8>, std::io::Result<()>) {
        let Chain {
            client,
            mut origin,
            bridge,
        } = chain(IoForwardService::default().maybe_with_lingering_close(linger)).await;
        let (reset, reset_now) = tokio::sync::oneshot::channel::<()>();
        let origin = tokio::spawn(async move {
            let mut req = vec![0; REQUEST.len()];
            origin.read_exact(&mut req).await.unwrap();
            origin.write_all(&reply(REPLY_LEN)).await.unwrap();
            // Reset only once the client holds the whole reply, so that it is
            // up to the bridge whether the client gets to read it.
            _ = reset_now.await;
            origin.set_zero_linger().unwrap();
        });
        let (mut client_r, mut client_w) = client.into_split();
        client_w.write_all(REQUEST).await.unwrap();
        let writer = tokio::spawn(async move {
            for _ in 0..20 {
                if client_w.write_all(&[1; 1024]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            client_w
        });
        let mut peeked = vec![0; REPLY_LEN];
        while client_r.peek(&mut peeked).await.unwrap() < REPLY_LEN {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        reset.send(()).unwrap();
        // Give the bridge time to close the client leg before reading.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let received = read_until_end(&mut client_r).await;
        drop((client_r, writer.await.unwrap()));
        origin.await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), bridge)
            .await
            .expect("bridge did not unwind")
            .unwrap();
        received
    }

    /// The bridge idles out and closes the client leg; the client sends once
    /// more afterwards and only then reads.
    async fn send_after_bridge_closed(
        linger: Option<LingeringClose>,
    ) -> (Vec<u8>, std::io::Result<()>) {
        let svc = IoForwardService::default()
            .with_idle_timeout(Duration::from_millis(50))
            .maybe_with_lingering_close(linger);
        let Chain {
            mut client,
            mut origin,
            bridge,
        } = chain(svc).await;
        let origin = tokio::spawn(async move {
            let mut req = vec![0; REQUEST.len()];
            origin.read_exact(&mut req).await.unwrap();
            origin.write_all(&reply(REPLY_LEN)).await.unwrap();
            origin
        });
        client.write_all(REQUEST).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        _ = client.write_all(b"late").await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let received = read_until_end(&mut client).await;
        drop(client);
        drop(origin.await.unwrap());
        tokio::time::timeout(Duration::from_secs(5), bridge)
            .await
            .expect("bridge did not unwind")
            .unwrap();
        received
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_close_keeps_reply_while_client_still_sends() {
        for _ in 0..10 {
            let (bytes, end) = close_while_client_sends(Some(LingeringClose::default())).await;
            assert_eq!(bytes, reply(REPLY_LEN));
            end.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_close_absorbs_send_after_bridge_closed() {
        for _ in 0..20 {
            let (bytes, end) = send_after_bridge_closed(Some(LingeringClose::default())).await;
            assert_eq!(bytes, reply(REPLY_LEN));
            end.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "characterization: prints what happens without lingering"]
    async fn without_lingering_close() {
        let mut kept = [0; 2];
        let mut ends = Vec::new();
        for _ in 0..20 {
            for (i, (bytes, end)) in [
                close_while_client_sends(None).await,
                send_after_bridge_closed(None).await,
            ]
            .into_iter()
            .enumerate()
            {
                if bytes == reply(REPLY_LEN) {
                    kept[i] += 1;
                }
                let end = end.map_err(|err| (err.kind(), err.raw_os_error()));
                if !ends.contains(&(i, end)) {
                    ends.push((i, end));
                }
            }
        }
        eprintln!(
            "without lingering: reply kept while client sends={}/20, after send after close={}/20, ends={ends:?}",
            kept[0], kept[1]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_close_is_bounded_by_its_idle_timeout() {
        let svc = IoForwardService::default()
            .with_idle_timeout(Duration::from_millis(20))
            .with_lingering_close(
                LingeringClose::new().with_idle_timeout(Duration::from_millis(200)),
            );
        let Chain {
            client,
            mut origin,
            bridge,
        } = chain(svc).await;
        let started = Instant::now();
        // Something to protect: lingering is for a client the bridge wrote to.
        origin.write_all(b"hi").await.unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(5), bridge)
            .await
            .expect("lingering was not bounded by its idle timeout")
            .unwrap();
        assert_eq!(outcome.reason(), BridgeCloseReason::IdleTimeout);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(200),
            "lingered only {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(2), "lingered {elapsed:?}");
        assert!(
            elapsed.saturating_sub(outcome.age()) >= Duration::from_millis(190),
            "the bridge age {:?} includes the lingering",
            outcome.age(),
        );
        drop((client, origin));
    }

    /// A peer that keeps sending, just often enough to never idle out, is
    /// cut off by the total timeout.
    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_close_is_bounded_by_its_total_timeout() {
        let svc = IoForwardService::default().with_lingering_close(
            LingeringClose::new()
                .with_idle_timeout(Duration::from_millis(300))
                .with_timeout(Duration::from_millis(600)),
        );
        let Chain {
            mut client,
            mut origin,
            bridge,
        } = chain(svc).await;
        // Nagle would hold each byte back until the last one is acknowledged,
        // which a delayed ACK can stretch past the idle timeout.
        client.set_nodelay(true).unwrap();
        let started = Instant::now();
        // The origin replies and ends cleanly, so the client side lingers.
        origin.write_all(b"hi").await.unwrap();
        drop(origin);
        let trickle = tokio::spawn(async move {
            let until = Instant::now() + Duration::from_secs(5);
            while Instant::now() < until && client.write_all(b"x").await.is_ok() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        let outcome = tokio::time::timeout(Duration::from_secs(5), bridge)
            .await
            .expect("lingering was not bounded by its total timeout")
            .unwrap();
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(3), "lingered {elapsed:?}");
        assert!(
            elapsed.saturating_sub(outcome.age()) >= Duration::from_millis(590),
            "lingered only {:?}",
            elapsed.saturating_sub(outcome.age()),
        );
        trickle.abort();
    }

    /// A reader that always has data never makes the drain wait, which must
    /// not keep its timeout or a shutdown from being seen.
    struct AlwaysReady;

    impl tokio::io::AsyncRead for AlwaysReady {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let n = buf.initialize_unfilled().len();
            buf.advance(n);
            std::task::Poll::Ready(Ok(()))
        }
    }

    // A current-thread runtime only fires timers and runs other tasks when
    // this one yields, and a timeout around the drain would not fire either.
    #[tokio::test]
    async fn linger_drain_ends_an_always_ready_reader_at_its_timeout() {
        let linger = LingeringClose::new().with_timeout(Duration::from_millis(100));
        let started = Instant::now();
        linger_drain(&mut AlwaysReady, linger, None).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100),
            "lingered {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(2), "lingered {elapsed:?}");
    }

    #[tokio::test]
    async fn linger_drain_sees_a_shutdown_while_the_reader_is_always_ready() {
        let (shutdown, trigger) = shutdown_pair().await;
        let guard = shutdown.guard();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            _ = trigger.send(());
        });
        let started = Instant::now();
        linger_drain(&mut AlwaysReady, patient_linger(), Some(&guard)).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "shutdown seen after {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn linger_drain_stops_at_its_byte_limit() {
        struct Counting(u64);
        impl tokio::io::AsyncRead for Counting {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                let before = buf.filled().len();
                let read =
                    tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut AlwaysReady), cx, buf);
                self.0 += (buf.filled().len() - before) as u64;
                read
            }
        }
        for max in [1, 1000, 4096, 10_000] {
            let mut reader = Counting(0);
            let linger = patient_linger().with_max_bytes(max);
            linger_drain(&mut reader, linger, None).await;
            assert_eq!(reader.0, max, "read past its limit");
        }
    }

    #[tokio::test]
    async fn linger_drain_is_skipped_when_disabled() {
        for linger in [
            LingeringClose::new().with_timeout(Duration::ZERO),
            LingeringClose::new().with_idle_timeout(Duration::ZERO),
            LingeringClose::new().with_max_bytes(0),
        ] {
            let mut reader = ScriptedIo::erroring(std::io::ErrorKind::Other);
            linger_drain(&mut reader, linger, None).await;
            assert!(!reader.errored, "{linger:?} still read");
        }
    }

    /// After a first-byte timeout nothing was forwarded to the client, so
    /// there is nothing to protect: no side lingers, even while the client
    /// keeps its end open.
    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_close_skips_a_silent_origin() {
        let svc = IoForwardService::default()
            .with_first_byte_timeout(Duration::from_millis(50))
            .with_lingering_close(patient_linger());
        let Chain {
            mut client,
            origin,
            bridge,
        } = chain(svc).await;
        client.write_all(REQUEST).await.unwrap();
        let (_, end) = read_until_end(&mut client).await;
        end.unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(2), bridge)
            .await
            .expect("a side lingered after a first-byte timeout")
            .unwrap();
        drop(client);
        assert_eq!(outcome.reason(), BridgeCloseReason::FirstByteTimeout);
        drop(origin);
    }

    /// Where the bridge finds out that the origin reset.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ResetFoundBy {
        /// A write of the upload.
        Write,
        /// The half-close after the upload, before the reply is readable.
        HalfClose,
    }

    /// An origin that replies and resets while the client uploads, with the
    /// reply still on its way to a slow client when the bridge finds the
    /// reset. Scripted: the origin yields `reply` then a reset.
    struct ResettingOrigin {
        reply: Vec<u8>,
        sent: usize,
        found_by: ResetFoundBy,
        shut: bool,
        reader: Option<std::task::Waker>,
    }

    impl ResettingOrigin {
        fn new(found_by: ResetFoundBy) -> Self {
            Self {
                reply: reply(REPLY_LEN),
                sent: 0,
                found_by,
                shut: false,
                reader: None,
            }
        }
    }

    impl tokio::io::AsyncRead for ResettingOrigin {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.found_by == ResetFoundBy::HalfClose && !self.shut {
                self.reader = Some(cx.waker().clone());
                return std::task::Poll::Pending;
            }
            if self.sent == self.reply.len() {
                return std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
            }
            let n = buf.remaining().min(self.reply.len() - self.sent);
            let sent = self.sent;
            buf.put_slice(&self.reply[sent..sent + n]);
            self.sent += n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for ResettingOrigin {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(match self.found_by {
                ResetFoundBy::Write => Err(std::io::ErrorKind::ConnectionReset.into()),
                ResetFoundBy::HalfClose => Ok(buf.len()),
            })
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.found_by == ResetFoundBy::Write {
                return std::task::Poll::Ready(Ok(()));
            }
            self.shut = true;
            if let Some(reader) = self.reader.take() {
                reader.wake();
            }
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
        }
    }

    /// A client leg that, like an HTTP/2 or HTTP/3 stream, is reset as soon
    /// as its [`AbortIo`] is called: writes to it fail from then on.
    struct ResetAtOnce {
        io: tokio::io::DuplexStream,
        reset: Arc<AtomicBool>,
    }

    impl tokio::io::AsyncRead for ResetAtOnce {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for ResetAtOnce {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.reset.load(Ordering::SeqCst) {
                return std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
            }
            std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    /// How the client reads the reply.
    #[derive(Debug, Clone, Copy)]
    enum Reading {
        AtOnce,
        Never,
        /// 64 bytes at a time, with this pause in between.
        Slowly(Duration),
    }

    /// Returns what the client read, how often the client side was reset,
    /// and how long the bridge took, by tokio's clock.
    async fn reset_while_uploading(
        found_by: ResetFoundBy,
        svc: IoForwardService,
        reading: Reading,
    ) -> (Vec<u8>, u64, Duration) {
        let (mut client, ingress) = duplex(64);
        let reset = Arc::new(AtomicBool::new(false));
        let ingress = ServiceInput::new(ResetAtOnce {
            io: ingress,
            reset: reset.clone(),
        });
        let aborts = Arc::new(AtomicU64::new(0));
        let counter = aborts.clone();
        ingress.extensions().insert(AbortIo::new(move || {
            reset.store(true, Ordering::SeqCst);
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        let origin = ServiceInput::new(ResettingOrigin::new(found_by));
        let started = tokio::time::Instant::now();
        let bridge = tokio::spawn(async move {
            _ = svc.serve(BridgeIo(ingress, origin)).await;
            started.elapsed()
        });
        client.write_all(b"upload").await.unwrap();
        if found_by == ResetFoundBy::HalfClose {
            client.shutdown().await.unwrap();
        }
        let mut received = Vec::new();
        match reading {
            Reading::AtOnce => received = read_until_end(&mut client).await.0,
            Reading::Never => {}
            Reading::Slowly(pause) => {
                let mut buf = [0; 64];
                while let Ok(n @ 1..) = client.read(&mut buf).await {
                    received.extend_from_slice(&buf[..n]);
                    tokio::time::sleep(pause).await;
                }
            }
        }
        let took = tokio::time::timeout(Duration::from_secs(30), bridge)
            .await
            .expect("bridge did not unwind")
            .unwrap();
        (received, aborts.load(Ordering::SeqCst), took)
    }

    const FOUND_BY: [ResetFoundBy; 2] = [ResetFoundBy::Write, ResetFoundBy::HalfClose];

    /// The reset is reflected to the client, but only once the reply the
    /// origin sent before it got there, also when the half-close found it,
    /// and with a client leg that is reset at once.
    // Simulated I/O must not race host scheduling against the drain deadline.
    #[tokio::test(start_paused = true)]
    async fn a_reset_found_while_uploading_still_delivers_the_reply() {
        for found_by in FOUND_BY {
            let svc = IoForwardService::default();
            let (received, aborts, _) = reset_while_uploading(found_by, svc, Reading::AtOnce).await;
            assert_eq!(received.len(), REPLY_LEN, "{found_by:?}");
            assert_eq!(received, reply(REPLY_LEN), "{found_by:?}");
            assert_eq!(aborts, 1, "{found_by:?}");
        }
    }

    /// A client that never reads is reset once the drain window ends: the
    /// shutdown grace without lingering.
    #[tokio::test(start_paused = true)]
    async fn a_reset_found_while_uploading_ends_after_the_drain_window() {
        let grace = Duration::from_millis(500);
        for found_by in FOUND_BY {
            let svc = IoForwardService::default().with_shutdown_grace(grace);
            let (_, aborts, took) = reset_while_uploading(found_by, svc, Reading::Never).await;
            assert_eq!(aborts, 1, "{found_by:?}");
            assert!(took >= grace, "{found_by:?}: drained only {took:?}");
            assert!(took < grace * 2, "{found_by:?}: drained {took:?}");
        }
    }

    /// The drain window is extended while the reply still moves to a slow
    /// client, up to the lingering total; it is not without lingering.
    #[tokio::test(start_paused = true)]
    async fn the_drain_window_is_extended_while_the_reply_moves() {
        let pause = Duration::from_millis(30);
        // The reply takes about 3 s to read at this pace.
        let linger = LingeringClose::new().with_idle_timeout(Duration::from_millis(100));
        for (linger, total, complete) in [
            (
                Some(linger.with_timeout(Duration::from_secs(10))),
                None,
                true,
            ),
            (
                Some(linger.with_timeout(Duration::from_secs(1))),
                Some(Duration::from_secs(1)),
                false,
            ),
            (None, None, false),
        ] {
            let svc = IoForwardService::default().maybe_with_lingering_close(linger);
            let (received, aborts, took) =
                reset_while_uploading(ResetFoundBy::Write, svc, Reading::Slowly(pause)).await;
            assert_eq!(received.len() == REPLY_LEN, complete, "{linger:?}");
            assert_eq!(received, reply(REPLY_LEN)[..received.len()], "{linger:?}");
            assert_eq!(aborts, 1, "{linger:?}");
            if let Some(total) = total {
                assert!(took >= total && took < total * 2, "{linger:?}: {took:?}");
            }
        }
    }

    /// A timeout too large to add to an instant means no limit, not a panic.
    #[tokio::test]
    async fn linger_drain_takes_unbounded_timeouts() {
        let linger = LingeringClose::new()
            .with_idle_timeout(Duration::MAX)
            .with_timeout(Duration::MAX);
        let mut reader = ScriptedIo::erroring(std::io::ErrorKind::ConnectionReset);
        linger_drain(&mut reader, linger, None).await;
        assert!(reader.errored);
    }

    /// Only the client side lingers, and only when it was closed in order: a
    /// client reset to reflect a failure of the origin does not.
    #[tokio::test]
    async fn only_a_client_closed_in_order_lingers() {
        let idle = Duration::from_millis(200);
        let svc = IoForwardService::default()
            .with_lingering_close(LingeringClose::new().with_idle_timeout(idle));
        for abortable in [true, false] {
            let (client, client_counts) = side(ReadEnd::Pend, abortable);
            // Replies, then resets.
            let origin = ServiceInput::new(ResettingOrigin::new(ResetFoundBy::Write));
            let started = Instant::now();
            _ = tokio::time::timeout(Duration::from_secs(5), svc.serve(BridgeIo(client, origin)))
                .await
                .expect("lingering was not bounded");
            assert_eq!(
                started.elapsed() >= idle,
                !abortable,
                "abortable={abortable}"
            );
            assert_eq!(
                client_counts.get(),
                (u64::from(!abortable), u64::from(abortable)),
                "abortable={abortable}"
            );
        }
    }

    /// The upstream side never lingers: that would keep downloading what
    /// nobody reads.
    #[tokio::test]
    async fn the_upstream_never_lingers() {
        let svc = IoForwardService::default().with_lingering_close(patient_linger());
        let (client, _) = side(ReadEnd::Fail(std::io::ErrorKind::UnexpectedEof), false);
        let (origin, origin_counts) = side(ReadEnd::Pend, false);
        tokio::time::timeout(Duration::from_secs(2), svc.serve(BridgeIo(client, origin)))
            .await
            .expect("the upstream lingered")
            .unwrap();
        assert_eq!(origin_counts.get(), (1, 0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_close_is_bounded_by_bytes() {
        let svc = IoForwardService::default()
            .with_idle_timeout(Duration::from_millis(20))
            .with_lingering_close(patient_linger().with_max_bytes(rama_utils::octets::kib_u64(64)));
        let Chain {
            mut client,
            mut origin,
            bridge,
        } = chain(svc).await;
        // The origin replies and ends cleanly, so the client side lingers.
        origin.write_all(b"hi").await.unwrap();
        drop(origin);
        // Wait for the idle close, then flood the lingering side.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!bridge.is_finished(), "the bridge should be lingering");
        let flood = tokio::spawn(async move {
            let chunk = vec![0; kib(16)];
            while client.write_all(&chunk).await.is_ok() {}
        });
        tokio::time::timeout(Duration::from_secs(5), bridge)
            .await
            .expect("lingering was not bounded by its byte limit")
            .unwrap();
        flood.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_close_is_cut_short_by_shutdown() {
        let (shutdown, trigger) = shutdown_pair().await;
        let svc = IoForwardService::new(Executor::graceful(shutdown.guard()))
            .with_idle_timeout(Duration::from_millis(20))
            .with_lingering_close(patient_linger());
        let Chain {
            client,
            mut origin,
            bridge,
        } = chain(svc).await;
        origin.write_all(b"hi").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!bridge.is_finished(), "the bridge should be lingering");
        let started = Instant::now();
        trigger.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), bridge)
            .await
            .expect("shutdown did not cut lingering short")
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        drop((client, origin, shutdown));
    }
}
