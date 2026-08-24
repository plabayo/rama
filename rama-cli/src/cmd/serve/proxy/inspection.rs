//! Runtime gate shared by MITM routing and capture writers.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Mutex, Notify};

const PAUSED: usize = 1 << (usize::BITS - 1);
const WRITER_MASK: usize = !PAUSED;

struct InspectionStateInner {
    /// The high bit is the paused flag; the remaining bits count writers.
    /// Keeping both in one atomic makes the pause boundary linearizable
    /// without a lock or sequentially consistent operations on the hot path.
    state: AtomicUsize,
    drained: Notify,
    transition: Mutex<()>,
}

/// Process-wide runtime state for inspection and capture.
///
/// The proxy hot path remains lock-free. Pausing prevents new permits and then
/// waits for writers that already hold one, so a successful pause response is
/// also a capture-write quiescence boundary.
#[derive(Clone)]
pub(super) struct InspectionState(Arc<InspectionStateInner>);

impl Default for InspectionState {
    fn default() -> Self {
        Self(Arc::new(InspectionStateInner {
            state: AtomicUsize::new(0),
            drained: Notify::new(),
            transition: Mutex::new(()),
        }))
    }
}

impl std::fmt::Debug for InspectionState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InspectionState")
            .field("enabled", &self.is_enabled())
            .finish_non_exhaustive()
    }
}

impl InspectionState {
    #[inline]
    pub(super) fn is_enabled(&self) -> bool {
        self.0.state.load(Ordering::Acquire) & PAUSED == 0
    }

    /// Enter one capture-write operation if inspection is still enabled.
    ///
    /// The compare-and-exchange closes the race with `pause`: either the
    /// writer count wins first and is awaited, or the paused bit wins first
    /// and this operation does not start.
    pub(super) fn try_capture(&self) -> Option<InspectionPermit> {
        let mut state = self.0.state.load(Ordering::Acquire);
        loop {
            if state & PAUSED != 0 || state & WRITER_MASK == WRITER_MASK {
                return None;
            }
            match self.0.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(InspectionPermit(self.0.clone())),
                Err(current) => state = current,
            }
        }
    }

    /// Disable inspection and wait until every capture write that already
    /// started has completed.
    pub(super) async fn pause(&self) -> bool {
        let _transition = self.0.transition.lock().await;
        let previous = self.0.state.fetch_or(PAUSED, Ordering::AcqRel);
        while self.0.state.load(Ordering::Acquire) & WRITER_MASK != 0 {
            self.0.drained.notified().await;
        }
        previous & PAUSED == 0
    }

    pub(super) async fn resume(&self) -> bool {
        let _transition = self.0.transition.lock().await;
        self.0.state.fetch_and(WRITER_MASK, Ordering::AcqRel) & PAUSED != 0
    }
}

#[must_use = "dropping the permit marks the capture operation complete"]
pub(super) struct InspectionPermit(Arc<InspectionStateInner>);

impl Drop for InspectionPermit {
    fn drop(&mut self) {
        leave_capture(&self.0);
    }
}

fn leave_capture(state: &InspectionStateInner) {
    let previous = state.state.fetch_sub(1, Ordering::Release);
    debug_assert!(
        previous & WRITER_MASK > 0,
        "inspection writer count underflow"
    );
    if previous & WRITER_MASK == 1 {
        state.drained.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn pause_is_a_quiescence_boundary_and_resume_reopens_the_gate() {
        let state = InspectionState::default();
        let permit = state.try_capture().unwrap();
        let pause = tokio::spawn({
            let state = state.clone();
            async move { state.pause().await }
        });

        tokio::task::yield_now().await;
        assert!(!state.is_enabled());
        assert!(state.try_capture().is_none());
        assert!(!pause.is_finished());

        drop(permit);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), pause)
                .await
                .unwrap()
                .unwrap()
        );
        assert!(!state.is_enabled());
        assert!(state.resume().await);
        assert!(state.is_enabled());
        assert!(state.try_capture().is_some());
    }
}
