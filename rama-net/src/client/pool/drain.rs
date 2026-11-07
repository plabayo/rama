//! Pooled connections follow the scope they run in: drained in its graceful phase.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use rama_core::{
    extensions::Extensions,
    graceful::{WeakScope, scope_context},
};
use tokio::sync::oneshot;

/// The scope a pooled connection runs in, read once as the pool adds it: once it is
/// cancelled the connection is never handed out again.
///
/// Observing a scope may run user code (a signal's destructor, a waker), so the scope is
/// only read outside the pool's locks, into a flag that checks under a lock read instead.
/// Drop it outside the pool's locks too: it may hold the last reference to its scope.
pub(super) struct ConnScope {
    scope: WeakScope,
    drained: Arc<AtomicBool>,
    // Dropped with the connection, which ends its watcher.
    _gone: oneshot::Sender<()>,
}

/// Takes a pooled connection out of its pool once its scope is cancelled, see
/// [`ConnScope::of`].
pub(super) struct Watcher {
    scope: WeakScope,
    drained: Arc<AtomicBool>,
    gone: oneshot::Receiver<()>,
}

impl ConnScope {
    /// The scope of a connection with `extensions` and its [`Watcher`]; `None` if it runs in
    /// none.
    pub(super) fn of(extensions: &Extensions) -> Option<(Self, Watcher)> {
        let scope = scope_context(extensions)?;
        let drained = Arc::new(AtomicBool::new(false));
        let (gone_tx, gone) = oneshot::channel();
        let watcher = Watcher {
            scope: scope.clone(),
            drained: drained.clone(),
            gone,
        };
        Some((
            Self {
                scope,
                drained,
                _gone: gone_tx,
            },
            watcher,
        ))
    }

    /// Whether the scope is cancelled, read from the scope itself: call it outside every
    /// pool lock.
    pub(super) fn observe(&self) -> bool {
        if self.is_drained() {
            return true;
        }
        let cancelled = self.scope.is_cancelled();
        if cancelled {
            self.drained.store(true, Ordering::Release);
        }
        cancelled
    }

    /// Whether the scope was seen cancelled, by [`Self::observe`] or the watcher: safe under a
    /// pool lock.
    pub(super) fn is_drained(&self) -> bool {
        self.drained.load(Ordering::Acquire)
    }
}

impl Watcher {
    /// Run `drain` once the scope is cancelled, unless the connection is gone first.
    ///
    /// A plain task that holds no scope; without a runtime the pool drains the connection
    /// once it meets it again. The flag is set before `drain` takes a pool lock, so a check
    /// under that lock either sees it or runs before the drain and is undone by it.
    pub(super) fn spawn(self, drain: impl FnOnce() + Send + 'static) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Self {
            scope,
            drained,
            gone,
        } = self;
        runtime.spawn(async move {
            tokio::select! {
                () = scope.cancelled() => {
                    drained.store(true, Ordering::Release);
                    drain();
                }
                _ = gone => {}
            }
        });
    }
}
