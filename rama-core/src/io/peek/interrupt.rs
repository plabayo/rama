use std::{
    fmt,
    future::poll_fn,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};

use parking_lot::Mutex;

use crate::extensions::Extension;

/// A condition that triggers a [`PeekInterrupt`] once it is met.
///
/// Sources are polled only while a peek waits for more input,
/// see [`PeekInterrupt::attach`].
pub trait PeekInterruptSource: Send + 'static {
    /// Poll whether the condition is met.
    ///
    /// Once this returns [`Poll::Ready`] the interrupt stays triggered
    /// and the source is not polled again.
    fn poll_interrupt(&mut self, cx: &mut Context<'_>) -> Poll<()>;
}

/// One-shot signal that tells protocol peeking to stop waiting for input.
///
/// Peekers find it in the [`Extensions`] of their input. Once triggered it
/// stays triggered: whether a peek then falls back, fails or keeps waiting
/// is decided by its [`PeekPolicy`] based on how far that peek got.
///
/// It is triggered explicitly via [`Self::trigger`] or by an attached
/// [`PeekInterruptSource`], e.g. the first byte probed by [`PeekEgressFirstByteLayer`].
///
/// [`Extensions`]: crate::extensions::Extensions
/// [`PeekPolicy`]: super::PeekPolicy
/// [`PeekEgressFirstByteLayer`]: super::PeekEgressFirstByteLayer
#[derive(Default, Extension)]
pub struct PeekInterrupt {
    triggered: AtomicBool,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    wakers: Vec<Waker>,
    sources: Vec<Box<dyn PeekInterruptSource>>,
}

impl fmt::Debug for PeekInterrupt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeekInterrupt")
            .field("triggered", &self.is_triggered())
            .finish()
    }
}

impl PeekInterrupt {
    /// Create a new [`PeekInterrupt`] that is not yet triggered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trigger the interrupt, waking all peeks waiting on it.
    pub fn trigger(&self) {
        if !self.triggered.swap(true, Ordering::AcqRel) {
            self.wake_all();
        }
    }

    /// Returns `true` once the interrupt was triggered.
    ///
    /// Attached sources are only polled by [`Self::triggered`].
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        self.triggered.load(Ordering::Acquire)
    }

    /// Attach a source that triggers this interrupt once its condition is met.
    pub fn attach(&self, source: impl PeekInterruptSource) {
        let wakers = {
            let mut state = self.state.lock();
            state.sources.push(Box::new(source));
            std::mem::take(&mut state.wakers)
        };
        // pending waiters poll again so the new source gets registered
        wakers.into_iter().for_each(Waker::wake);
    }

    /// Wait until the interrupt is triggered, driving attached sources.
    pub async fn triggered(&self) {
        poll_fn(|cx| self.poll_triggered(cx)).await;
    }

    /// Poll version of [`Self::triggered`].
    pub fn poll_triggered(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.is_triggered() {
            return Poll::Ready(());
        }

        let mut state = self.state.lock();
        if self.is_triggered() {
            return Poll::Ready(());
        }

        if state
            .sources
            .iter_mut()
            .any(|source| source.poll_interrupt(cx).is_ready())
        {
            state.sources.clear();
            drop(state);
            self.trigger();
            return Poll::Ready(());
        }

        if !state.wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
            state.wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }

    fn wake_all(&self) {
        let wakers = std::mem::take(&mut self.state.lock().wakers);
        wakers.into_iter().for_each(Waker::wake);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use super::*;

    struct Flag(Arc<AtomicBool>);

    impl PeekInterruptSource for Flag {
        fn poll_interrupt(&mut self, cx: &mut Context<'_>) -> Poll<()> {
            if self.0.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    #[tokio::test]
    async fn trigger_wakes_pending_waiters() {
        let interrupt = Arc::new(PeekInterrupt::new());
        let waiter = tokio::spawn({
            let interrupt = interrupt.clone();
            async move { interrupt.triggered().await }
        });
        tokio::task::yield_now().await;
        assert!(!interrupt.is_triggered());

        interrupt.trigger();
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .unwrap()
            .unwrap();
        assert!(interrupt.is_triggered());
    }

    #[tokio::test]
    async fn source_attached_while_waiting_triggers_the_interrupt() {
        let interrupt = Arc::new(PeekInterrupt::new());
        let waiter = tokio::spawn({
            let interrupt = interrupt.clone();
            async move { interrupt.triggered().await }
        });
        tokio::task::yield_now().await;

        let fired = Arc::new(AtomicBool::new(false));
        interrupt.attach(Flag(fired.clone()));
        tokio::task::yield_now().await;
        assert!(!interrupt.is_triggered());

        fired.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .unwrap()
            .unwrap();
        assert!(interrupt.is_triggered());
    }
}
