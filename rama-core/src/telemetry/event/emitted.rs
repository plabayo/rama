use core::cell::OnceCell;

use tokio::time::Instant;

/// One emitted event, as a listener sees it.
pub struct Emitted<'a, E> {
    event: &'a E,
    at: OnceCell<Instant>,
}

impl<'a, E> Emitted<'a, E> {
    pub(super) fn new(event: &'a E) -> Self {
        Self {
            event,
            at: OnceCell::new(),
        }
    }

    pub(super) fn at_time(event: &'a E, at: Instant) -> Self {
        let cell = OnceCell::new();
        _ = cell.set(at);
        Self { event, at: cell }
    }

    /// When this event was emitted, read from the clock on the first call and
    /// shared by every listener of this event.
    pub fn at(&self) -> Instant {
        *self.at.get_or_init(Instant::now)
    }

    /// The event itself.
    pub fn event(&self) -> &E {
        self.event
    }
}
