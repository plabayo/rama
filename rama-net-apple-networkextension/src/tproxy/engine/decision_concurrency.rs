use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

use crate::tproxy::{FlowRefusalAction, TransparentProxyFlowProtocol};

/// Shared decision-poll concurrency for one immutable engine generation.
///
/// This is deliberately independent from the admitted-flow limits: until a
/// policy returns, the engine cannot know whether a flow should be blocked,
/// passed through, or intercepted. The gate only bounds the lightweight
/// pre-decision work retained by concurrently delivered Apple callbacks.
pub(super) struct DecisionConcurrencyGate {
    limit: usize,
    active: AtomicUsize,
    overload_refusals: AtomicU64,
    #[cfg(test)]
    peak_active: AtomicUsize,
}

impl DecisionConcurrencyGate {
    pub(super) fn new(limit: usize) -> Self {
        debug_assert!(limit > 0);
        Self {
            limit,
            active: AtomicUsize::new(0),
            overload_refusals: AtomicU64::new(0),
            #[cfg(test)]
            peak_active: AtomicUsize::new(0),
        }
    }

    /// Reserve one policy-decision slot.
    ///
    /// Successful flows pay one atomic RMW here and one in `Drop`; there is no
    /// mutex, wait queue, allocation, or per-packet involvement. `fetch_update`
    /// prevents even a transient accepted count above the configured limit.
    pub(super) fn try_acquire(self: &Arc<Self>) -> Option<DecisionPermit> {
        let _previous = self
            .active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.limit).then_some(active + 1)
            })
            .ok()?;
        #[cfg(test)]
        self.peak_active.fetch_max(_previous + 1, Ordering::Relaxed);
        Some(DecisionPermit { gate: self.clone() })
    }

    /// Emit one signal initially and then only at exponentially increasing
    /// totals. This keeps sustained overload visible without a line per flow;
    /// the cumulative counter on each line makes skipped events explicit.
    pub(super) fn record_overload(
        &self,
        flow_id: u64,
        protocol: TransparentProxyFlowProtocol,
        action: FlowRefusalAction,
    ) {
        let total = self
            .overload_refusals
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if total.is_power_of_two() {
            tracing::warn!(
                target: "rama_apple_ne::tproxy",
                flow_id,
                %protocol,
                decision_concurrency_limit = self.limit,
                decision_concurrency_active = self.active.load(Ordering::Relaxed),
                overload_refusals_total = total,
                %action,
                "transparent proxy decision concurrency saturated; applying overload action",
            );
        }
    }

    #[cfg(test)]
    pub(super) fn snapshot(&self) -> DecisionConcurrencySnapshot {
        DecisionConcurrencySnapshot {
            limit: self.limit,
            active: self.active.load(Ordering::Acquire),
            peak_active: self.peak_active.load(Ordering::Relaxed),
            overload_refusals: self.overload_refusals.load(Ordering::Relaxed),
        }
    }
}

pub(super) struct DecisionPermit {
    gate: Arc<DecisionConcurrencyGate>,
}

impl Drop for DecisionPermit {
    fn drop(&mut self) {
        let previous = self.gate.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

#[cfg(test)]
pub(super) struct DecisionConcurrencySnapshot {
    pub(super) limit: usize,
    pub(super) active: usize,
    pub(super) peak_active: usize,
    pub(super) overload_refusals: u64,
}
