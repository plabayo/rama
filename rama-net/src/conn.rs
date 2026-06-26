//! Connection utilities

use rama_core::extensions::Extension;
use std::{
    io,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::sync::watch;

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

#[derive(Clone, Debug, Extension)]
#[extension(tags(net))]
/// Watcher that can update and read the [`ConnectionHealth`]
///
/// Note: this should only be added once to extensions and
/// be used by all connection / health checks.
pub struct ConnectionHealthWatcher {
    sender: watch::Sender<ConnectionHealth>,
    receiver: watch::Receiver<ConnectionHealth>,
}

impl ConnectionHealthWatcher {
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
        self.sender.send_replace(health);
    }

    /// Get the [`ConnectionHealth`]
    pub fn health(&self) -> ConnectionHealth {
        *self.receiver.borrow()
    }

    /// Reference the [`watch::Sender<ConnectionHealth>`]
    pub fn sender(&self) -> &watch::Sender<ConnectionHealth> {
        &self.sender
    }

    /// Reference the [`watch::Sender<ConnectionHealth>`]
    ///
    /// Note: for keeping track of changes, prefer to clone this
    /// receiver so it has it's own subscribe logic
    pub fn receiver(&self) -> &watch::Receiver<ConnectionHealth> {
        &self.receiver
    }
}

impl Default for ConnectionHealthWatcher {
    fn default() -> Self {
        let (sender, receiver) = watch::channel(ConnectionHealth::Healthy);
        Self { sender, receiver }
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq)]
/// Health of the connection
pub enum ConnectionHealth {
    Broken,
    Healthy,
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
pub struct MaxConcurrency(AtomicUsize);

impl MaxConcurrency {
    #[must_use]
    pub fn new(max: usize) -> Self {
        let value = AtomicUsize::new(max);
        Self(value)
    }

    /// Get the maximum number of concurrent requests/streams.
    pub fn set(&self, max: usize) {
        self.0.store(max, Ordering::Relaxed);
    }

    /// Get the maximum number of concurrent requests/streams.
    #[must_use]
    pub fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}
