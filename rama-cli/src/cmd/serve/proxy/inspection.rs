//! Shared pause boundary for MITM sessions, capture writers and traffic controls.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Mutex, Notify, watch};

const PAUSED: usize = 1 << (usize::BITS - 1);
const WRITER_MASK: usize = !PAUSED;

struct InspectionStateInner {
    /// The high bit is the paused flag; the remaining bits count writers.
    /// Keeping both in one atomic makes the pause boundary linearizable
    /// without a lock or sequentially consistent operations on the hot path.
    state: AtomicUsize,
    drained: Notify,
    paused: watch::Sender<()>,
    transition: Mutex<()>,
}

/// Process-wide runtime state for inspection.
///
/// Capture writes remain lock-free. Pausing prevents new permits and then
/// waits for writers that already hold one, so a successful pause response is
/// also a capture-write quiescence boundary.
#[derive(Clone)]
pub(super) struct InspectionState(Arc<InspectionStateInner>);

impl Default for InspectionState {
    fn default() -> Self {
        Self(Arc::new(InspectionStateInner {
            state: AtomicUsize::new(0),
            drained: Notify::new(),
            paused: watch::channel(()).0,
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

    /// Enter one capture-write operation if recording is still enabled.
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

    /// Register a cancellable MITM session before touching protocol data.
    /// Subscribe first so a concurrent pause cannot miss this session.
    pub(super) fn session(&self) -> Option<InspectionSession> {
        let paused = self.0.paused.subscribe();
        self.try_capture().map(|permit| InspectionSession {
            paused,
            _permit: permit,
        })
    }

    /// Stop new inspection, cancel MITM sessions and drain capture writes.
    pub(super) async fn pause(&self) -> bool {
        let _transition = self.0.transition.lock().await;
        let previous = self.0.state.fetch_or(PAUSED, Ordering::AcqRel);
        self.0.paused.send_replace(());
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

/// Holding this guard makes pause wait until the inspected future is dropped.
pub(super) struct InspectionSession {
    paused: watch::Receiver<()>,
    _permit: InspectionPermit,
}

impl InspectionSession {
    pub(super) async fn run<F, E>(mut self, future: F) -> Result<(), E>
    where
        F: Future<Output = Result<(), E>>,
    {
        tokio::select! {
            biased;
            _ = self.paused.changed() => Ok(()),
            result = future => result,
        }
    }
}

/// Choose raw forwarding while paused; end already inspected streams on pause.
#[derive(Debug, Clone)]
pub(super) struct InspectionGate<I, P> {
    pub inspection: InspectionState,
    pub inspect: I,
    pub passthrough: P,
}

impl<I, P, Input> rama::Service<Input> for InspectionGate<I, P>
where
    Input: Send + 'static,
    I: rama::Service<Input, Output = (), Error: Into<rama::error::BoxError>>,
    P: rama::Service<Input, Output = (), Error: Into<rama::error::BoxError>>,
{
    type Output = ();
    type Error = rama::error::BoxError;

    async fn serve(&self, input: Input) -> Result<(), Self::Error> {
        if let Some(session) = self.inspection.session() {
            session
                .run(self.inspect.serve(input))
                .await
                .map_err(Into::into)
        } else {
            self.passthrough.serve(input).await.map_err(Into::into)
        }
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
    async fn pause_cancels_idle_sessions_and_waits_for_their_drop() {
        let state = InspectionState::default();
        let session = state.session().unwrap();
        let writer = state.try_capture().unwrap();
        let task = tokio::spawn(session.run(std::future::pending::<Result<(), ()>>()));
        let pause = tokio::spawn({
            let state = state.clone();
            async move { state.pause().await }
        });
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!pause.is_finished());
        assert!(state.session().is_none());
        drop(writer);
        assert!(pause.await.unwrap());
        assert!(state.resume().await);
        // A fresh subscription must not inherit the previous pause event.
        let session = state.session().unwrap();
        assert_eq!(session.run(async { Err::<(), _>(42) }).await, Err(42));
    }

    #[tokio::test]
    async fn debug_reports_the_current_inspection_state() {
        let state = InspectionState::default();
        assert_eq!(
            format!("{state:?}"),
            "InspectionState { enabled: true, .. }"
        );
        assert!(state.pause().await);
        assert_eq!(
            format!("{state:?}"),
            "InspectionState { enabled: false, .. }"
        );
    }

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
