//! The bytes a demux holds queued: bounded per demux, per association and, when demuxes share
//! one, in total.

use std::{
    fmt,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use super::Counters;

/// A byte budget several [`DatagramDemux`](super::DatagramDemux)es share, so that what they
/// queue together stays within one bound, as a proxy serving many flows needs.
#[derive(Clone)]
pub struct SharedQueueBudget(Arc<Shared>);

struct Shared {
    queued: AtomicUsize,
    limit: usize,
}

impl fmt::Debug for SharedQueueBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedQueueBudget")
            .field("queued", &self.queued())
            .field("limit", &self.0.limit)
            .finish()
    }
}

impl SharedQueueBudget {
    /// A budget of `limit` bytes queued across every demux that shares it.
    #[must_use]
    pub fn new(limit: NonZeroUsize) -> Self {
        Self(Arc::new(Shared {
            queued: AtomicUsize::new(0),
            limit: limit.get(),
        }))
    }

    /// Payload bytes queued now, across every demux that shares this budget.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.0.queued.load(Ordering::Relaxed)
    }
}

/// Add `len` to `counter` if the total stays within `limit`.
fn try_reserve(counter: &AtomicUsize, len: usize, limit: usize) -> bool {
    let mut queued = counter.load(Ordering::Acquire);
    loop {
        let Some(total) = queued.checked_add(len).filter(|total| *total <= limit) else {
            return false;
        };
        match counter.compare_exchange_weak(queued, total, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(current) => queued = current,
        }
    }
}

/// One queued datagram's bytes, held against every budget it counts in until it is read or
/// dropped.
#[derive(Debug)]
pub(super) struct Charge {
    counters: Arc<Counters>,
    shared: Option<SharedQueueBudget>,
    association: Option<Arc<AtomicUsize>>,
    len: usize,
}

impl Charge {
    /// Reserve `len` bytes within the demux's `budget` and the `shared` one, or `None` when
    /// they do not fit.
    pub(super) fn try_new(
        counters: &Arc<Counters>,
        shared: Option<&SharedQueueBudget>,
        len: usize,
        budget: usize,
    ) -> Option<Self> {
        if let Some(shared) = shared
            && !try_reserve(&shared.0.queued, len, shared.0.limit)
        {
            return None;
        }
        if !try_reserve(&counters.queued_bytes, len, budget) {
            if let Some(shared) = shared {
                shared.0.queued.fetch_sub(len, Ordering::AcqRel);
            }
            return None;
        }
        Some(Self {
            counters: counters.clone(),
            shared: shared.cloned(),
            association: None,
            len,
        })
    }

    /// Count these bytes against `association` too, unless it already holds its `share`; an
    /// association's first queued datagram always fits.
    pub(super) fn try_assign(&mut self, association: &Arc<AtomicUsize>, share: usize) -> bool {
        let held = association.load(Ordering::Acquire);
        if held != 0 && held.saturating_add(self.len) > share {
            return false;
        }
        association.fetch_add(self.len, Ordering::AcqRel);
        self.association = Some(association.clone());
        true
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.counters
            .queued_bytes
            .fetch_sub(self.len, Ordering::AcqRel);
        if let Some(shared) = &self.shared {
            shared.0.queued.fetch_sub(self.len, Ordering::AcqRel);
        }
        if let Some(association) = &self.association {
            association.fetch_sub(self.len, Ordering::AcqRel);
        }
    }
}
