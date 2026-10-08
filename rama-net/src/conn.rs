//! Connection utilities

use std::io;

use rama_core::extensions::{Extension, Extensions};
use rama_utils::reactive::{ChangeListener, Changed, Reactive, ReactiveRepr};
use std::sync::Weak;

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

#[derive(Debug, Default, Extension)]
#[extension(tags(net))]
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
#[extension(tags(net))]
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
