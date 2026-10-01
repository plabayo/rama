use std::{fmt, sync::Arc, time::Duration};

use rama_core::telemetry::tracing;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::Instant,
};

/// Default bound on concurrent lookups per resolver: 64 calls that each send
/// A and AAAA together (`getaddrinfo`) fit a local stub's default receive
/// buffer of about 256 small datagrams, with room to spare.
pub(crate) const DEFAULT_MAX_LOOKUPS: usize = 64;

/// Bounds concurrent lookups of one resolver.
#[derive(Debug, Clone)]
pub(crate) struct LookupLimit {
    permits: Arc<Semaphore>,
    max: usize,
}

impl Default for LookupLimit {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_LOOKUPS)
    }
}

impl LookupLimit {
    pub(crate) fn new(max: usize) -> Self {
        let max = max.clamp(1, Semaphore::MAX_PERMITS);
        Self {
            permits: Arc::new(Semaphore::new(max)),
            max,
        }
    }

    pub(crate) fn max(&self) -> usize {
        self.max
    }

    /// A lookup slot, or `None` when none frees up before `deadline`.
    pub(crate) async fn acquire(&self, deadline: Instant) -> Option<OwnedSemaphorePermit> {
        if let Ok(permit) = self.permits.clone().try_acquire_owned() {
            return Some(permit);
        }
        tracing::debug!(max = self.max, "dns: all lookup slots taken; waiting");
        tokio::time::timeout_at(deadline, self.permits.clone().acquire_owned())
            .await
            .ok()?
            .ok()
    }

    /// Run a blocking `lookup` once a slot is free, or `None` when none frees
    /// up before `deadline`.
    ///
    /// A timeout cannot cancel a blocking call, so its slot stays taken until
    /// the call itself returns. `lookup` gets the budget left when it starts:
    /// zero means its caller already gave up.
    pub(crate) async fn spawn_blocking<T, F>(
        &self,
        deadline: Instant,
        lookup: F,
    ) -> Option<JoinHandle<T>>
    where
        F: FnOnce(Duration) -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = self.acquire(deadline).await?;
        // budget in tokio time (which tests may pause), queueing in wall time
        let budget = deadline.saturating_duration_since(Instant::now());
        let queued = std::time::Instant::now();
        Some(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            lookup(budget.saturating_sub(queued.elapsed()))
        }))
    }
}

/// A DNS lookup that ran out of time, whichever resolver served it.
///
/// Every native resolver yields it as the error itself, also to callers that
/// shared a lookup, so a plain `downcast_ref` finds it.
#[derive(Debug, Clone, Copy)]
pub struct DnsTimeoutError {
    timeout: Duration,
}

impl DnsTimeoutError {
    pub(crate) const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// The budget the lookup ran out of.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl fmt::Display for DnsTimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dns lookup timed out after {:?}", self.timeout)
    }
}

impl std::error::Error for DnsTimeoutError {}

/// `timeout` from now, saturating instead of overflowing.
pub(crate) fn deadline_after(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout)
        .unwrap_or_else(|| now + Duration::from_hours(24 * 365 * 30))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    use rama_core::futures::future::join_all;

    use super::*;

    fn deadline_in(secs: u64) -> Instant {
        Instant::now() + Duration::from_secs(secs)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_lookups_stay_within_the_bound() {
        let lookups = LookupLimit::new(3);
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let calls = (0..24).map(|_| {
            let (running, peak) = (running.clone(), peak.clone());
            let lookups = lookups.clone();
            async move {
                let task = lookups
                    .spawn_blocking(deadline_in(10), move |_budget| {
                        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(5));
                        running.fetch_sub(1, Ordering::SeqCst);
                    })
                    .await
                    .expect("slot within deadline");
                task.await.expect("lookup ran");
            }
        });
        join_all(calls).await;

        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn waiting_for_a_slot_counts_against_the_deadline() {
        let lookups = LookupLimit::new(1);
        let (release, held) = mpsc::channel::<()>();
        let busy = lookups
            .spawn_blocking(deadline_in(10), move |_budget| held.recv().ok())
            .await
            .expect("first slot");

        let starved = lookups
            .spawn_blocking(Instant::now() + Duration::from_millis(50), |_budget| ())
            .await;
        assert!(starved.is_none(), "no slot frees up in time");

        drop(release);
        busy.await.expect("busy lookup ends");
        assert!(
            lookups
                .spawn_blocking(deadline_in(10), |_budget| ())
                .await
                .is_some(),
            "slot is free again once the call returns",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slot_stays_taken_after_the_caller_gave_up() {
        let lookups = LookupLimit::new(1);
        let (release, held) = mpsc::channel::<()>();
        let abandoned = lookups
            .spawn_blocking(deadline_in(10), move |_budget| held.recv().ok())
            .await
            .expect("first slot");
        drop(abandoned);

        let starved = lookups
            .spawn_blocking(Instant::now() + Duration::from_millis(50), |_budget| ())
            .await;
        assert!(
            starved.is_none(),
            "the uncancellable call still holds its slot"
        );
        drop(release);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookup_gets_the_remaining_budget() {
        let lookups = LookupLimit::default();
        assert_eq!(lookups.max(), DEFAULT_MAX_LOOKUPS);

        let budget = lookups
            .spawn_blocking(deadline_in(5), |budget| budget)
            .await
            .expect("slot")
            .await
            .expect("lookup ran");
        assert!(budget > Duration::from_secs(4) && budget <= Duration::from_secs(5));

        // a free slot is still handed out at the deadline, with nothing left
        let expired = lookups
            .spawn_blocking(Instant::now(), |budget| budget)
            .await
            .expect("a free slot is taken even at the deadline");
        assert!(expired.await.expect("lookup ran").is_zero());
    }

    #[tokio::test]
    async fn huge_timeouts_saturate() {
        assert!(deadline_after(Duration::MAX) > Instant::now() + Duration::from_hours(24 * 365));
    }

    #[tokio::test(start_paused = true)]
    async fn budget_follows_a_paused_clock() {
        let lookups = LookupLimit::new(1);
        // the paused clock runs ahead of wall time from here on
        tokio::time::sleep(Duration::from_secs(60)).await;

        let budget = lookups
            .spawn_blocking(deadline_in(5), |budget| budget)
            .await
            .expect("slot")
            .await
            .expect("lookup ran");
        assert!(
            budget > Duration::from_secs(4) && budget <= Duration::from_secs(5),
            "budget {budget:?}",
        );
    }

    #[test]
    fn timeout_error_reads_the_same_for_every_backend() {
        let err = DnsTimeoutError::new(Duration::from_millis(50));
        assert_eq!(err.to_string(), "dns lookup timed out after 50ms");
        assert_eq!(err.timeout(), Duration::from_millis(50));
    }

    #[test]
    fn bound_is_clamped() {
        assert_eq!(LookupLimit::new(0).max(), 1);
        assert_eq!(LookupLimit::new(usize::MAX).max(), Semaphore::MAX_PERMITS);
    }
}
