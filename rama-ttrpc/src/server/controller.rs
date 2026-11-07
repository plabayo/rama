use rama_core::graceful::{Cause, WeakScope};

/// Handle for gracefully shutting down a running [`ServerConnection`](super::ServerConnection).
///
/// Reachable from within a method handler via [`get_server`](crate::get_server). Call
/// [`shutdown`](Self::shutdown) to stop accepting new requests and let `start` return once the
/// in-flight requests have drained. It acts on the connection's scope, so a parent scope can do
/// the same, and abort the connection at its hard phase.
#[derive(Debug, Clone)]
pub struct ServerController {
    pub(super) scope: WeakScope,
}

impl ServerController {
    /// Request a graceful shutdown.
    ///
    /// Stops accepting new requests; the server's `start` future returns once the currently
    /// in-flight requests have finished.
    pub fn shutdown(&self) {
        self.scope.cancel(Cause::Reason("ttRPC server shutdown"));
    }
}
