//! Connection utilities

use std::{
    io,
    pin::Pin,
    sync::Weak,
    task::{Context, Poll, ready},
    time::Duration,
};

use rama_core::extensions::{Extension, Extensions};
use rama_utils::{
    reactive::{ChangeListener, Changed, Reactive, ReactiveRepr},
    time::deadline_after,
};
use tokio::{
    runtime::{Handle, Id},
    time::{Instant, Sleep, sleep, sleep_until},
};

/// Check if the error is a connection error,
/// in which case the error can be ignored.
#[must_use]
pub fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::Interrupted
    )
}

/// Pause policy for a listener whose `accept` fails, such as on `EMFILE`.
///
/// Errors that only concern the connection being accepted retry right away; anything else
/// pauses accepting, doubling from 10ms up to 1s until an accept succeeds again.
#[derive(Debug, Default)]
pub struct AcceptBackoff {
    next: Option<Duration>,
}

impl AcceptBackoff {
    const MIN_DELAY: Duration = Duration::from_millis(10);
    const MAX_DELAY: Duration = Duration::from_secs(1);

    /// Create a backoff in its initial state.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: None }
    }

    /// Record a successful accept.
    pub fn reset(&mut self) {
        self.next = None;
    }

    /// Record a failed accept, returning how long to pause before accepting again.
    ///
    /// `None` means the error was about that one connection and accepting can continue.
    pub fn on_error(&mut self, err: &io::Error) -> Option<Duration> {
        if is_connection_error(err) || is_pending_network_error(err) {
            return None;
        }
        let delay = self.next.unwrap_or(Self::MIN_DELAY);
        self.next = Some((delay * 2).min(Self::MAX_DELAY));
        Some(delay)
    }
}

/// An [`AcceptBackoff`] for an accept polled in a loop, such as a stream of connections:
/// the pause a failed accept asks for passes before the next one is attempted.
#[derive(Debug, Default)]
pub struct PolledAcceptBackoff {
    backoff: AcceptBackoff,
    pause: Option<Pin<Box<Sleep>>>,
    runtime: Option<Id>,
    waiting: bool,
}

impl PolledAcceptBackoff {
    /// Create a backoff in its initial state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            backoff: AcceptBackoff::new(),
            pause: None,
            runtime: None,
            waiting: false,
        }
    }

    /// Accept with `accept` once any pending pause has passed, recording its outcome.
    pub fn poll_accept<T>(
        &mut self,
        cx: &mut Context<'_>,
        accept: impl FnOnce(&mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if self.waiting
            && let Some(pause) = self.pause.as_mut()
        {
            let runtime = Handle::current().id();
            if self.runtime != Some(runtime) {
                *pause = Box::pin(sleep_until(pause.deadline()));
                self.runtime = Some(runtime);
            }
            ready!(pause.as_mut().poll(cx));
            self.waiting = false;
        }
        let result = ready!(accept(cx));
        match &result {
            Ok(_) => self.backoff.reset(),
            Err(err) => {
                if let Some(delay) = self.backoff.on_error(err) {
                    let runtime = Handle::current().id();
                    if self.runtime == Some(runtime)
                        && let Some(pause) = self.pause.as_mut()
                    {
                        pause.as_mut().reset(deadline_after(Instant::now(), delay));
                    } else {
                        self.pause = Some(Box::pin(sleep(delay)));
                        self.runtime = Some(runtime);
                    }
                    self.waiting = true;
                }
            }
        }
        Poll::Ready(result)
    }
}

/// Network errors `accept` reports for the pending connection, not the listener (accept(2)).
fn is_pending_network_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
    )
}

#[derive(Debug, Default, Extension)]
#[extension(tags(net), scope(connection))]
/// Watcher that can update and read the [`ConnectionHealth`]
///
/// Note: this should only be added once to extensions and
/// be used by all connection / health checks.
///
/// # Install vs mark/read convention
///
/// A protocol implementation *installing* the watcher for a new logical
/// connection must use `self_get_ref_or_insert` (this extensions level only):
/// a transport forked off a consumed connection (e.g. a CONNECT tunnel from an
/// upgraded h1 hop) must not adopt that connection's health state through the
/// parent chain. *Marking* and *reading* should use the walking
/// `get_ref`/`get_ref_or_insert`, so they resolve to the watcher governing the
/// connection at hand.
///
/// Whoever observes an event that makes a connection non-reusable (an
/// abandoned mid-stream body, a cancelled in-flight request, a protocol error)
/// must mark it broken *synchronously with that event*, before any guard
/// releases the connection back to a pool: deferring the mark to a background
/// connection task loses the race against the next request checking the
/// connection out.
pub struct ConnectionHealthWatcher(Reactive<ConnectionHealth>);

impl ConnectionHealthWatcher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the watcher for a new logical connection.
    ///
    /// Inserts at this extensions level only (no parent walk), per the
    /// install-vs-mark convention above: use this from protocol handshakes,
    /// and the walking `get_ref`/`get_ref_or_insert` to read or mark.
    pub fn install(extensions: &Extensions) -> &Self {
        extensions.self_get_ref_or_insert(Self::default)
    }

    /// Set the [`ConnectionHealth`] to health
    pub fn mark_healthy(&self) {
        self.update_health(ConnectionHealth::Healthy);
    }

    /// Set the [`ConnectionHealth`] to broken
    pub fn mark_broken(&self) {
        self.update_health(ConnectionHealth::Broken);
    }

    /// Set the [`ConnectionHealth`]
    pub fn update_health(&self, health: ConnectionHealth) {
        self.0.set(health);
    }

    /// Get the [`ConnectionHealth`]
    #[must_use]
    pub fn health(&self) -> ConnectionHealth {
        self.0.get()
    }

    /// Subscribe to health changes: [`Changed::changed`] yields each new value.
    #[must_use]
    pub fn watch(&self) -> Changed<ConnectionHealth> {
        self.0.watch()
    }

    /// Wake `listener` after every later health change, until it is dropped.
    pub fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
        self.0.subscribe(listener);
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Default)]
/// Health of the connection
pub enum ConnectionHealth {
    Broken,
    #[default]
    Healthy,
}

impl ReactiveRepr for ConnectionHealth {
    fn to_usize(self) -> usize {
        match self {
            Self::Healthy => 0,
            Self::Broken => 1,
        }
    }

    fn from_usize(value: usize) -> Self {
        match value {
            0 => Self::Healthy,
            _ => Self::Broken,
        }
    }
}

#[derive(Debug, Extension)]
#[extension(tags(net), scope(connection))]
/// Hint for the maximum number of concurrent requests/streams a connection can
/// serve at once.
///
/// Used by the multiplexing connection pool to size a connection's concurrency.
/// Connectors should set this on the connection's extensions: e.g. an http/2
/// connector from the peer's `SETTINGS_MAX_CONCURRENT_STREAMS`, and an http/1
/// connector to `1` (http/1 cannot multiplex).
pub struct MaxConcurrency(Reactive<usize>);

impl MaxConcurrency {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self(Reactive::new(max))
    }

    /// Set the maximum number of concurrent requests/streams.
    pub fn set(&self, max: usize) {
        self.0.set(max);
    }

    /// Get the maximum number of concurrent requests/streams.
    #[must_use]
    pub fn get(&self) -> usize {
        self.0.get()
    }

    /// Subscribe to changes: [`Changed::changed`] yields each new value.
    #[must_use]
    pub fn watch(&self) -> Changed<usize> {
        self.0.watch()
    }

    /// Wake `listener` after every later change, until it is dropped.
    pub fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
        self.0.subscribe(listener);
    }
}

/// Bounds of a lingering close: after shutting down its own side, a
/// connection keeps reading and discarding what its peer still sends before
/// it is closed.
///
/// Closing a socket that still has unread input sends a reset instead of a
/// clean close, and on Windows a reset makes the peer discard what it has
/// not read yet, such as the tail of a response that was just sent to it.
/// The same happens when the peer sends after the socket was closed.
/// Lingering keeps the socket open until the peer is done, as nginx does
/// with `lingering_close`.
///
/// A connection lingers until its peer ends the stream, nothing arrives for
/// [`idle_timeout`](Self::idle_timeout), [`timeout`](Self::timeout) passes
/// in total, or [`max_bytes`](Self::max_bytes) (if set) were read and
/// discarded, whichever comes first. A peer that is still sending is waited
/// for, so the total timeout is what bounds a slow one. Used by
/// [`IoForwardService`](crate::proxy::IoForwardService) and rama's HTTP/1
/// server, which say when a connection lingers.
///
/// The total of 30 seconds is nginx's `lingering_time`. The idle timeout of
/// 2 seconds is shorter than nginx's `lingering_timeout` of 5, as the peer
/// only has to finish what it was already sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LingeringClose {
    idle_timeout: std::time::Duration,
    timeout: std::time::Duration,
    max_bytes: Option<u64>,
}

impl Default for LingeringClose {
    fn default() -> Self {
        Self::new()
    }
}

impl LingeringClose {
    /// Linger while data keeps arriving within 2 seconds, for at most 30
    /// seconds in total, without a byte limit.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            idle_timeout: std::time::Duration::from_secs(2),
            timeout: std::time::Duration::from_secs(30),
            max_bytes: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Stop lingering once nothing arrived for this long.
        /// If this is at least the total timeout, the total limit wins instead.
        /// HTTP/1 servers can then abort a blocked response even for an idle client.
        pub fn idle_timeout(mut self, timeout: std::time::Duration) -> Self {
            self.idle_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Stop lingering once this long passed in total.
        pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Stop lingering once this many bytes were read and discarded.
        /// `None` (the default) sets no limit.
        pub fn max_bytes(mut self, max: Option<u64>) -> Self {
            self.max_bytes = max;
            self
        }
    }

    /// How long a lingering connection waits for more data.
    #[must_use]
    pub const fn idle_timeout(&self) -> std::time::Duration {
        self.idle_timeout
    }

    /// How long a connection lingers at most.
    #[must_use]
    pub const fn timeout(&self) -> std::time::Duration {
        self.timeout
    }

    /// How many bytes a connection reads and discards at most while
    /// lingering, if limited.
    #[must_use]
    pub const fn max_bytes(&self) -> Option<u64> {
        self.max_bytes
    }

    /// Whether these bounds let a connection linger at all.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        !self.idle_timeout.is_zero()
            && !self.timeout.is_zero()
            && !matches!(self.max_bytes, Some(0))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn lingering_close_defaults() {
        let linger = LingeringClose::default();
        assert_eq!(linger, LingeringClose::new());
        assert_eq!(linger.idle_timeout(), Duration::from_secs(2));
        assert_eq!(linger.timeout(), Duration::from_secs(30));
        assert_eq!(linger.max_bytes(), None);
        assert!(linger.is_enabled());
    }

    #[test]
    fn lingering_close_is_disabled_by_any_zero_bound() {
        let mut linger = LingeringClose::new();
        linger.set_max_bytes(1);
        assert!(linger.is_enabled());
        assert!(!linger.with_max_bytes(0).is_enabled());
        assert!(linger.without_max_bytes().is_enabled());
        assert!(!linger.with_idle_timeout(Duration::ZERO).is_enabled());
        assert!(!linger.with_timeout(Duration::ZERO).is_enabled());
    }
}

#[cfg(test)]
mod accept_backoff_tests {
    use std::{cell::Cell, ptr::from_ref, task::Waker};

    use tokio::{runtime::Builder, time::advance};

    use super::*;

    #[test]
    fn a_polled_accept_can_start_a_pause_on_another_runtime() {
        let mut backoff = PolledAcceptBackoff::new();
        for _ in 0..2 {
            Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .unwrap()
                .block_on(async {
                    let mut cx = Context::from_waker(Waker::noop());
                    let failed = backoff.poll_accept(&mut cx, |_| {
                        Poll::Ready(Err::<(), _>(io::Error::other("too many open files")))
                    });
                    assert!(matches!(failed, Poll::Ready(Err(_))));
                    assert!(
                        backoff
                            .poll_accept(&mut cx, |_| Poll::Ready(Ok(())))
                            .is_pending()
                    );
                    advance(AcceptBackoff::MIN_DELAY).await;
                    assert!(matches!(
                        backoff.poll_accept(&mut cx, |_| Poll::Ready(Ok(()))),
                        Poll::Ready(Ok(()))
                    ));
                });
        }
    }

    #[test]
    fn a_pending_accept_pause_migrates_to_another_runtime() {
        let a = Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let b = Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let mut backoff = PolledAcceptBackoff::new();
        a.block_on(async {
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                backoff.poll_accept(&mut cx, |_| Poll::Ready(Err::<(), _>(io::Error::other(
                    "listener unavailable"
                )))),
                Poll::Ready(Err(_))
            ));
            assert!(
                backoff
                    .poll_accept(&mut cx, |_| Poll::Ready(Ok(())))
                    .is_pending()
            );
        });
        b.block_on(async {
            let mut cx = Context::from_waker(Waker::noop());
            assert!(
                backoff
                    .poll_accept(&mut cx, |_| Poll::Ready(Ok(())))
                    .is_pending()
            );
            advance(AcceptBackoff::MIN_DELAY * 2).await;
            assert!(matches!(
                backoff.poll_accept(&mut cx, |_| Poll::Ready(Ok(()))),
                Poll::Ready(Ok(()))
            ));
        });
    }

    #[test]
    fn connection_errors_do_not_pause() {
        let mut backoff = AcceptBackoff::new();
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
        ] {
            assert_eq!(backoff.on_error(&io::Error::from(kind)), None, "{kind:?}");
        }
    }

    #[test]
    fn listener_errors_pause_with_doubling_and_reset() {
        let mut backoff = AcceptBackoff::new();
        let emfile = io::Error::other("too many open files");
        let delays: Vec<_> = (0..9).filter_map(|_| backoff.on_error(&emfile)).collect();
        assert_eq!(
            delays,
            [10, 20, 40, 80, 160, 320, 640, 1000, 1000].map(Duration::from_millis)
        );

        backoff.reset();
        assert_eq!(backoff.on_error(&emfile), Some(Duration::from_millis(10)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_polled_accept_waits_out_the_pause_of_a_listener_error() {
        let mut backoff = PolledAcceptBackoff::new();
        let mut cx = Context::from_waker(Waker::noop());
        let attempts = Cell::new(0);
        let accept = |fails: bool| {
            let attempts = &attempts;
            move |_: &mut Context<'_>| {
                attempts.set(attempts.get() + 1);
                Poll::Ready(if fails {
                    Err(io::Error::other("too many open files"))
                } else {
                    Ok(())
                })
            }
        };
        assert!(matches!(
            backoff.poll_accept(&mut cx, accept(true)),
            Poll::Ready(Err(_))
        ));
        assert!(backoff.poll_accept(&mut cx, accept(false)).is_pending());
        assert_eq!(attempts.get(), 1);

        advance(Duration::from_millis(10)).await;
        assert!(matches!(
            backoff.poll_accept(&mut cx, accept(false)),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(attempts.get(), 2);

        // A connection error does not pause the next accept.
        let reset =
            |_: &mut Context<'_>| Poll::Ready(Err::<(), _>(io::ErrorKind::ConnectionReset.into()));
        assert!(backoff.poll_accept(&mut cx, reset).is_ready());
        assert!(backoff.poll_accept(&mut cx, accept(false)).is_ready());
    }

    #[tokio::test(start_paused = true)]
    async fn a_polled_accept_reuses_its_timer_between_pauses() {
        let mut backoff = PolledAcceptBackoff::new();
        let mut cx = Context::from_waker(Waker::noop());
        let fails = |_: &mut Context<'_>| {
            Poll::Ready(Err::<(), _>(io::Error::other("too many open files")))
        };
        let succeeds = |_: &mut Context<'_>| Poll::Ready(Ok(()));

        assert!(matches!(
            backoff.poll_accept(&mut cx, fails),
            Poll::Ready(Err(_))
        ));
        let timer = backoff.pause.as_deref().map(from_ref);
        assert!(timer.is_some());
        assert!(backoff.poll_accept(&mut cx, succeeds).is_pending());
        advance(AcceptBackoff::MIN_DELAY).await;
        assert!(matches!(
            backoff.poll_accept(&mut cx, succeeds),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(backoff.pause.as_deref().map(from_ref), timer);
        assert!(matches!(
            backoff.poll_accept(&mut cx, succeeds),
            Poll::Ready(Ok(()))
        ));

        for delay in [AcceptBackoff::MIN_DELAY, AcceptBackoff::MIN_DELAY * 2] {
            assert!(matches!(
                backoff.poll_accept(&mut cx, fails),
                Poll::Ready(Err(_))
            ));
            assert_eq!(backoff.pause.as_deref().map(from_ref), timer);
            assert!(backoff.poll_accept(&mut cx, fails).is_pending());
            advance(delay).await;
        }
        assert!(matches!(
            backoff.poll_accept(&mut cx, succeeds),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(backoff.pause.as_deref().map(from_ref), timer);
    }
}
