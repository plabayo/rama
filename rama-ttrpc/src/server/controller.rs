use tokio_util::sync::CancellationToken;

/// Handle for gracefully shutting down a running [`ServerConnection`](super::ServerConnection).
///
/// Reachable from within a method handler via [`get_server`](crate::get_server). Call
/// [`shutdown`](Self::shutdown) to stop accepting new requests and let `start` return once the
/// in-flight requests have drained.
#[derive(Clone, Default)]
pub struct ServerController {
    pub(super) token: CancellationToken,
}

impl ServerController {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request a graceful shutdown.
    ///
    /// Stops accepting new requests; the server's `start` future returns once the currently
    /// in-flight requests have finished.
    pub fn shutdown(&self) {
        self.token.cancel();
    }
}
