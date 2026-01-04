//! Connection utilities

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
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

#[derive(Clone, Default)]
/// Health of this connection
///
/// Note: this should only be added once to extensions and
/// be edited by all connection / health checks.
pub struct ConnectionHealth {
    status: Arc<AtomicU8>,
}

impl ConnectionHealth {
    #[must_use]
    /// Get the [`ConnectionHealthStatus`]
    pub fn status(&self) -> ConnectionHealthStatus {
        let val = self.status.load(Ordering::Relaxed);
        // SAFETY: ConnectionHealthStatus is stored with repr u8
        unsafe { std::mem::transmute::<u8, ConnectionHealthStatus>(val) }
    }

    /// Set status to provided [`ConnectionHealthStatus`]
    pub fn set_status(&self, status: ConnectionHealthStatus) {
        // SAFETY: ConnectionHealthStatus is stored with repr u8
        let val = unsafe { std::mem::transmute::<ConnectionHealthStatus, u8>(status) };
        self.status.store(val, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for ConnectionHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionHealth")
            .field("status", &self.status())
            .finish()
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub enum ConnectionHealthStatus {
    Unknown = 0,
    Broken = 1,
    Healthy = 2,
}
