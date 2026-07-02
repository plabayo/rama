//! Connection utilities

use std::io;

use rama_core::extensions::Extension;
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
pub struct ConnectionHealthWatcher(Reactive<ConnectionHealth>);

impl ConnectionHealthWatcher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
