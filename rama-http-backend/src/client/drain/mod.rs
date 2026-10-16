//! Bounded background draining of abandoned HTTP/1 response bodies.
//!
//! An HTTP/1 connection can only serve its next request once the previous
//! response body was read off the wire. A caller dropping a response before
//! its end would otherwise cost the pooled connection (and a new handshake
//! for the next request). [`Http1DrainBody`] instead moves the unread body,
//! together with the pool lease it holds, into a bounded background task
//! that reads and discards the remainder, so the connection returns to the
//! pool once the body completes. Any failure drops the body the ordinary
//! way: the connection is marked broken before its lease is released.

use std::{
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use rama_core::{
    bytes::Bytes,
    error::BoxError,
    extensions::{Extension, Extensions},
    graceful::WeakShutdownGuard,
    rt::Executor,
    telemetry::tracing,
};
use rama_http_types::{
    Body,
    body::{Frame, GuardedBody, SizeHint, StreamingBody},
};
use rama_net::{
    client::pool::ConnectionReuse,
    conn::{ConnectionHealth, ConnectionHealthWatcher},
};
use rama_utils::{macros::generate_set_and_with, octets::mib};
use tokio::time::Instant;

/// Configuration of the bounded background draining of HTTP/1 response
/// bodies that were dropped before their end.
///
/// An HTTP/1 connection can only be reused once the previous response body
/// was read off the wire. When a response from a pooled HTTP/1 connection is
/// dropped with its body unread or partially read, the remainder is read and
/// discarded by a background task, within these bounds, so the connection
/// can return to the pool instead of being closed. While it drains, the
/// connection stays checked out: requests meanwhile are served as the pool's
/// saturation policy decides (another connection, or waiting for one). A
/// successful drain makes the connection available to later requests; it
/// does not reserve it for the next one.
///
/// A drain gives up, closing the connection as without draining, once:
///
/// - more than [`max_bytes`](Self::max_bytes) payload bytes were discarded
///   with more of the body left. The body is read a frame at a time, so the
///   last frame read may cross the limit: this bounds the reads, not exactly
///   the bytes read off the socket. A body ending at exactly `max_bytes`
///   drains, as does one whose final frame crosses it;
/// - [`timeout`](Self::timeout) elapsed since the body was dropped,
///   including the time waiting to be scheduled;
/// - the body fails (truncated or malformed framing), or the executor shuts down.
///
/// Draining only starts if fewer than [`max_concurrent`](Self::max_concurrent)
/// drains run for the same connector (shared by its clones); otherwise the
/// connection is closed right away. A zero `max_bytes` or `timeout` never
/// drains a body that has bytes left.
///
/// This only applies to HTTP/1 responses whose connection could be reused:
/// not after a `Connection: close` (sent or received), for close-delimited
/// bodies, upgrades or successful CONNECT tunnels, nor for connections
/// otherwise known broken or not reusable. HTTP/2 and HTTP/3 cancel the
/// stream of a dropped body instead, keeping the connection.
///
/// Draining needs the tokio runtime of the connection: a body dropped outside
/// of one is not drained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1BodyDrainConfig {
    /// At most this many unread payload bytes (before content decoding) are
    /// discarded to recover a connection: 1 MiB by default.
    pub max_bytes: usize,
    /// A drain gives up this long after the body was dropped: 50 ms by default.
    pub timeout: Duration,
    /// At most this many drains run at once per connector: 256 by default.
    pub max_concurrent: NonZeroUsize,
}

impl Default for Http1BodyDrainConfig {
    fn default() -> Self {
        Self::new()
    }
}

const DEFAULT_MAX_CONCURRENT: NonZeroUsize = NonZeroUsize::new(256).unwrap();

impl Http1BodyDrainConfig {
    /// Create a new [`Http1BodyDrainConfig`] with the default limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_bytes: mib(1),
            timeout: Duration::from_millis(50),
            max_concurrent: DEFAULT_MAX_CONCURRENT,
        }
    }

    generate_set_and_with! {
        /// Discard at most this many unread payload bytes to recover a connection.
        pub fn max_bytes(mut self, max: usize) -> Self {
            self.max_bytes = max;
            self
        }
    }

    generate_set_and_with! {
        /// Give up a drain this long after its body was dropped.
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Run at most this many drains at once per connector.
        pub fn max_concurrent(mut self, max: NonZeroUsize) -> Self {
            self.max_concurrent = max;
            self
        }
    }
}

/// The drain limits of one connector and the drains it runs, shared by its
/// clones and the bodies of its connections.
#[derive(Debug)]
pub(super) struct Http1BodyDrain {
    config: Http1BodyDrainConfig,
    active: AtomicUsize,
}

impl Http1BodyDrainConfig {
    /// Whether these limits allow draining a body with bytes left at all.
    pub(super) fn can_drain(&self) -> bool {
        self.max_bytes > 0 && !self.timeout.is_zero()
    }
}

impl Http1BodyDrain {
    pub(super) fn new(config: &Http1BodyDrainConfig) -> Self {
        Self {
            config: config.clone(),
            active: AtomicUsize::new(0),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<DrainPermit> {
        let max = self.config.max_concurrent.get();
        self.active
            .try_update(Ordering::Acquire, Ordering::Relaxed, |active| {
                (active < max).then_some(active + 1)
            })
            .ok()?;
        Some(DrainPermit(self.clone()))
    }
}

/// One of the connector's `max_concurrent` drains, released on drop.
struct DrainPermit(Arc<Http1BodyDrain>);

impl Drop for DrainPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Release);
    }
}

/// Marks an HTTP/1 client connection, with the executor its abandoned
/// response bodies are drained on.
///
/// Holds the shutdown guard weakly: an idle pooled connection must not delay
/// a graceful shutdown.
#[derive(Debug, Clone, Extension)]
#[extension(tags(http))]
pub(super) struct Http1DrainRuntime {
    guard: Option<WeakShutdownGuard>,
}

impl Http1DrainRuntime {
    pub(super) fn new(exec: &Executor) -> Self {
        Self {
            guard: exec.guard().map(|guard| guard.clone_weak()),
        }
    }

    fn executor(&self) -> Executor {
        match &self.guard {
            Some(guard) => Executor::graceful(guard.clone().upgrade()),
            None => Executor::new(),
        }
    }
}

/// The response body of an HTTP/1 connection, drained in the background
/// when dropped before its end (see [`Http1BodyDrainConfig`]).
///
/// It forwards to the [`GuardedBody`] holding the connection lease, which
/// releases the lease at end-of-stream as it does without draining.
pub(super) struct Http1DrainBody<C: Send + 'static> {
    /// `None` once the body completed or failed.
    inner: Option<GuardedBody<Body, C>>,
    drain: Arc<Http1BodyDrain>,
    /// Of the connection: its health, reuse policy and [`Http1DrainRuntime`].
    conn: Extensions,
}

impl<C: Send + 'static> Http1DrainBody<C> {
    pub(super) fn new(
        inner: GuardedBody<Body, C>,
        drain: Arc<Http1BodyDrain>,
        conn: Extensions,
    ) -> Self {
        Self {
            inner: Some(inner),
            drain,
            conn,
        }
    }

    /// Whether the connection may still serve another request.
    fn reusable(&self) -> bool {
        !self
            .conn
            .get_ref::<ConnectionHealthWatcher>()
            .is_some_and(|health| health.health() == ConnectionHealth::Broken)
            && self
                .conn
                .get_ref::<ConnectionReuse>()
                .is_none_or(ConnectionReuse::is_reusable)
    }
}

impl<C: Send + 'static> StreamingBody for Http1DrainBody<C> {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(None);
        };
        let result = Pin::new(inner).poll_frame(cx);
        // Nothing is left to drain after the final frame or an error.
        if let Poll::Ready(None | Some(Err(_))) = &result {
            self.inner = None;
        } else if let Poll::Ready(Some(Ok(frame))) = &result
            && frame.is_trailers()
        {
            self.inner = None;
        }
        result
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().is_none_or(StreamingBody::is_end_stream)
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), StreamingBody::size_hint)
    }
}

impl<C: Send + 'static> Drop for Http1DrainBody<C> {
    fn drop(&mut self) {
        // Anything that returns early drops `body` the ordinary way: an
        // incomplete one marks its connection broken before releasing it.
        let Some(body) = self.inner.take() else {
            return;
        };
        if body.is_end_stream() || !self.reusable() {
            return;
        }
        let Some(runtime) = self.conn.get_ref::<Http1DrainRuntime>() else {
            return;
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let Some(permit) = self.drain.try_acquire() else {
            tracing::trace!("http1 response body dropped: drain limit reached, closing connection");
            return;
        };
        #[cfg(test)]
        DRAINS_STARTED.with(|started| started.set(started.get() + 1));
        let started = Instant::now();
        let deadline = started.checked_add(self.drain.config.timeout);
        let max_bytes = self.drain.config.max_bytes;
        // The task owns the body, its lease and the permit: whatever ends it,
        // a cancellation or shutdown included, releases them as above.
        runtime
            .executor()
            .spawn_cancellable_task(drain(body, permit, max_bytes, started, deadline));
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
thread_local! {
    /// Drains started by bodies dropped on this thread.
    static DRAINS_STARTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Maximum frames read in one drain poll before yielding to the executor.
const FRAMES_PER_POLL: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainOutcome {
    Complete,
    ByteLimit,
    Deadline,
    StreamError,
    Cancelled,
}

impl DrainOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ByteLimit => "byte_limit",
            Self::Deadline => "deadline",
            Self::StreamError => "stream_error",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Emits the drain's one trace event, also when the task is cancelled.
struct DrainReport {
    started: Instant,
    discarded: usize,
    outcome: DrainOutcome,
}

impl Drop for DrainReport {
    fn drop(&mut self) {
        tracing::debug!(
            outcome = self.outcome.as_str(),
            discarded_bytes = self.discarded,
            elapsed_us = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX),
            "http1 response body drain finished"
        );
    }
}

async fn drain<C: Send + 'static>(
    body: GuardedBody<Body, C>,
    permit: DrainPermit,
    max_bytes: usize,
    started: Instant,
    deadline: Option<Instant>,
) {
    // Locals drop in reverse, also when cancelled: the body (invalidating and
    // releasing its connection unless complete), the permit, then the report.
    let mut report = DrainReport {
        started,
        discarded: 0,
        outcome: DrainOutcome::Cancelled,
    };
    let _permit = permit;
    let mut body = body;
    let progress = std::future::poll_fn(|cx| {
        poll_drain(&mut body, cx, &mut report.discarded, max_bytes, deadline)
    });
    report.outcome = match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, progress)
            .await
            .unwrap_or(DrainOutcome::Deadline),
        None => progress.await,
    };
    drop(body);
}

fn poll_drain<C>(
    body: &mut GuardedBody<Body, C>,
    cx: &mut Context<'_>,
    discarded: &mut usize,
    max_bytes: usize,
    deadline: Option<Instant>,
) -> Poll<DrainOutcome> {
    // Tokio polls the inner future before its timeout. Check before reading,
    // also when a drain first starts or resumes after its deadline.
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Poll::Ready(DrainOutcome::Deadline);
    }
    for _ in 0..FRAMES_PER_POLL {
        let frame = match Pin::new(&mut *body).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => return Poll::Ready(DrainOutcome::Complete),
            Poll::Ready(Some(Err(_))) => return Poll::Ready(DrainOutcome::StreamError),
            Poll::Ready(Some(Ok(frame))) => frame,
        };
        match frame.into_data() {
            Ok(data) => {
                *discarded = discarded.saturating_add(data.len());
                // A frame that completed the body needs no further read,
                // whatever it brought the count to.
                if *discarded > max_bytes && !body.is_end_stream() {
                    return Poll::Ready(DrainOutcome::ByteLimit);
                }
            }
            // trailers are by contract the final frame
            Err(frame) if frame.is_trailers() => return Poll::Ready(DrainOutcome::Complete),
            Err(_) => {}
        }
        // e.g. the last bytes of a content-length body: no need to poll for `None`
        if body.is_end_stream() {
            return Poll::Ready(DrainOutcome::Complete);
        }
    }
    // An always-ready body must not hold the worker indefinitely.
    cx.waker().wake_by_ref();
    Poll::Pending
}
