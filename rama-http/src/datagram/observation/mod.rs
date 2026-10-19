//! Optional completion-only Capsule metadata, independent of HTTP version or transport.

use rama_core::extensions::Extension;
use rama_http_types::proto::capsule::CapsuleHeader;
use std::{fmt, sync::Arc};

/// A synchronous metadata observer. Methods must finish promptly without I/O, blocking
/// or reentering the session. Header metadata contains no value bytes. Retained data and
/// callback failures belong to the observer; observations must not control protocol behavior.
pub trait CapsuleObserver: Send + Sync + 'static {
    /// Cheap dynamic gate, checked at the completion boundary.
    fn is_enabled(&self) -> bool;
    /// A complete declared value was accepted by the sender, not necessarily delivered.
    fn created(&self, header: CapsuleHeader);
    /// The decoder consumed the complete declared value, including skipped/forwarded values.
    fn parsed(&self, header: CapsuleHeader);
}

/// An optional upgraded-I/O extension selecting a Capsule metadata observer.
/// Works on reliable streams even when no native HTTP Datagram carrier is available.
#[derive(Clone, Extension)]
#[non_exhaustive]
pub struct CapsuleObservation {
    observer: Arc<dyn CapsuleObserver>,
}

impl fmt::Debug for CapsuleObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapsuleObservation").finish_non_exhaustive()
    }
}

impl CapsuleObservation {
    /// Share an observer across a session's sending and receiving halves.
    pub fn new(observer: impl CapsuleObserver) -> Self {
        Self {
            observer: Arc::new(observer),
        }
    }
    pub(crate) fn created(&self, header: CapsuleHeader) {
        if self.observer.is_enabled() {
            self.observer.created(header);
        }
    }
    pub(crate) fn parsed(&self, header: CapsuleHeader) {
        if self.observer.is_enabled() {
            self.observer.parsed(header);
        }
    }
}

#[cfg(test)]
mod tests;
