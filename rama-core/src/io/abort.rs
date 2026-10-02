use std::fmt;

use crate::extensions::Extension;

/// Ends an I/O abortively: its peer sees a reset (a TCP RST, an HTTP/2 `RST_STREAM`,
/// an HTTP/3 `RESET_STREAM`) instead of an orderly end of stream, and data not yet
/// delivered may be discarded.
///
/// An I/O publishes it in its own [`Extensions`] store, so a lookup with
/// [`Extensions::self_get_ref`] never reaches the handle of another I/O, such as the
/// connection that multiplexes this stream. A relay calls it to reflect a failure of the
/// opposite side (RFC 9113 §8.5, RFC 9114 §4.4); without it a relay can only close in order.
///
/// The reset is sent at once or, at the latest, when the I/O is dropped; built-in TCP
/// streams reset on drop. Repeated calls are harmless. Share it through
/// [`Extensions::self_get_arc`] and [`Extensions::insert_arc`].
///
/// [`Extensions`]: crate::extensions::Extensions
/// [`Extensions::self_get_ref`]: crate::extensions::Extensions::self_get_ref
/// [`Extensions::self_get_arc`]: crate::extensions::Extensions::self_get_arc
/// [`Extensions::insert_arc`]: crate::extensions::Extensions::insert_arc
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
}

impl fmt::Debug for AbortIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbortIo").finish_non_exhaustive()
    }
}
