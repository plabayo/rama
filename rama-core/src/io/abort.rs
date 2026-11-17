use std::fmt;

use crate::extensions::Extension;

/// Ends an I/O abortively: its peer sees a reset (a TCP RST, an HTTP/2 `RST_STREAM`,
/// an HTTP/3 `RESET_STREAM`) instead of an orderly end of stream, and data not yet
/// delivered may be discarded.
///
/// An I/O publishes it in its own [`Extensions`] store, and a lookup with
/// [`Extensions::get_arc`] finds the nearest one: a level forked in front of an I/O
/// answers with that I/O's handle. A stream multiplexed on a connection publishes its
/// own, so that its lookup ends there instead of at the connection's. A relay calls it
/// to reflect a failure of the opposite side (RFC 9113 §8.5, RFC 9114 §4.4); without it
/// a relay can only close in order.
///
/// The reset is sent at once or, at the latest, when the I/O is dropped; built-in TCP
/// streams reset on drop. Repeated calls are harmless.
///
/// [`Extensions`]: crate::extensions::Extensions
/// [`Extensions::get_arc`]: crate::extensions::Extensions::get_arc
#[derive(Extension)]
pub struct AbortIo(Box<dyn Fn() + Send + Sync>);

impl AbortIo {
    /// Install the transport's abort.
    pub fn new(abort: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Box::new(abort))
    }

    /// Abort the I/O.
    pub fn abort(&self) {
        (self.0)();
    }

    /// Whether a relay reflects `err` of one side as a reset of both. A peer that
    /// stopped reading (`BrokenPipe`) or closed without TLS close_notify
    /// (`UnexpectedEof`, common in the wild) ended in order.
    #[must_use]
    pub fn reflects(err: &std::io::Error) -> bool {
        !matches!(
            err.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof
        )
    }
}

impl fmt::Debug for AbortIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbortIo").finish_non_exhaustive()
    }
}
