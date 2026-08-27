//! Connection utilities

use std::io;

use rama_core::extensions::{Extension, Extensions};
use rama_utils::reactive::{Changed, Reactive, ReactiveRepr};

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
}
