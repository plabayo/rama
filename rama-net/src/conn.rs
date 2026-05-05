//! Connection utilities

use rama_core::extensions::Extension;
use std::io;
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
