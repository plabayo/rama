//! Bounded extensible-priority scheduling independent of frame parsing.

use super::Error;
use rama_http::headers::Priority;
use rama_http_types::proto::h3::Code;
use rama_quic_proto::range_set::ArrayRangeSet;
use std::{
    collections::BTreeMap,
    task::{Context, Poll, Waker},
};

/// HTTP urgency runs from most to least urgent; QUIC schedules larger values
/// first. Reserve priorities above this range for connection-critical streams.
pub(super) fn transport_priority(priority: Priority) -> i32 {
    const LEAST_URGENT: u8 = 7;
    i32::from(LEAST_URGENT - priority.urgency())
}

/// Update the peer's response scheduling through RFC 9218 PRIORITY_UPDATE.
/// Available in client response extensions, including informational responses.
/// This weak handle does not keep the connection or response body alive.
#[derive(Clone, rama_core::extensions::Extension)]
pub struct PriorityHandle {
    shared: std::sync::Weak<super::connection::Shared>,
    id: u64,
    push: bool,
}

impl std::fmt::Debug for PriorityHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PriorityHandle")
            .field("id", &self.id)
            .field("push", &self.push)
            .finish_non_exhaustive()
    }
}

impl PriorityHandle {
    pub(crate) fn new(
        shared: &std::sync::Arc<super::connection::Shared>,
        id: u64,
        push: bool,
    ) -> Self {
        Self {
            shared: std::sync::Arc::downgrade(shared),
            id,
            push,
        }
    }

    /// Queue a bounded priority update. Scheduling remains advisory to the peer.
    pub fn update(&self, priority: Priority) -> Result<(), Error> {
        self.shared
            .upgrade()
            .ok_or(Error::stream(
                Code::H3_REQUEST_CANCELLED,
                "connection closed",
            ))?
            .send_priority(self.id, self.push, priority)
    }
}

struct Entry {
    priority: Priority,
    overridden: bool,
    ready: bool,
    order: u64,
    waker: Option<Waker>,
}

pub(crate) struct Schedule {
    active: BTreeMap<u64, Entry>,
    pending: BTreeMap<u64, Priority>,
    completed: ArrayRangeSet,
    limit: usize,
    clock: u64,
}

impl Schedule {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            active: BTreeMap::new(),
            pending: BTreeMap::new(),
            completed: ArrayRangeSet::default(),
            limit,
            clock: 0,
        }
    }

    pub(crate) fn register(&mut self, id: u64, priority: Priority) -> Result<(), Error> {
        if self.active.len() >= self.limit {
            return Err(Error::connection(
                Code::H3_EXCESSIVE_LOAD,
                "priority active stream budget exceeded",
            ));
        }
        let priority = self.pending.remove(&id).unwrap_or(priority);
        self.active.insert(
            id,
            Entry {
                priority,
                overridden: false,
                ready: false,
                order: self.clock,
                waker: None,
            },
        );
        self.clock = self.clock.saturating_add(1);
        Ok(())
    }

    pub(crate) fn update(&mut self, id: u64, priority: Priority) -> Result<(), Error> {
        if !id.is_multiple_of(4) {
            return Err(Error::connection(
                Code::H3_ID_ERROR,
                "priority target is not a request stream",
            ));
        }
        if self.completed.contains(id / 4) {
            return Ok(());
        }
        if let Some(entry) = self.active.get_mut(&id) {
            if !entry.overridden {
                entry.priority = priority;
            }
        } else {
            if self.pending.len() >= self.limit && !self.pending.contains_key(&id) {
                return Err(Error::connection(
                    Code::H3_EXCESSIVE_LOAD,
                    "pending priority budget exceeded",
                ));
            }
            self.pending.insert(id, priority);
        }
        self.wake_next();
        Ok(())
    }

    pub(crate) fn peer_priority(&mut self, id: u64, priority: Priority) {
        if let Some(entry) = self.active.get_mut(&id)
            && !entry.overridden
        {
            entry.priority = priority;
        }
        self.wake_next();
    }

    pub(crate) fn override_priority(&mut self, id: u64, priority: Priority) {
        if let Some(entry) = self.active.get_mut(&id) {
            entry.priority = priority;
            entry.overridden = true;
        }
        self.wake_next();
    }

    fn next(&self) -> Option<u64> {
        self.active
            .iter()
            .filter(|(_, entry)| entry.ready)
            .min_by_key(|(id, entry)| {
                (
                    entry.priority.urgency(),
                    entry.priority.incremental(),
                    entry.order,
                    **id,
                )
            })
            .map(|(id, _)| *id)
    }

    fn wake_next(&self) {
        if let Some(id) = self.next()
            && let Some(waker) = &self.active[&id].waker
        {
            waker.wake_by_ref();
        }
    }

    pub(crate) fn poll_turn(&mut self, id: u64, cx: &Context<'_>) -> Poll<Priority> {
        let Some(entry) = self.active.get_mut(&id) else {
            return Poll::Ready(Priority::default());
        };
        entry.ready = true;
        match &mut entry.waker {
            Some(waker) => waker.clone_from(cx.waker()),
            None => entry.waker = Some(cx.waker().clone()),
        }
        let priority = entry.priority;
        if self.next() == Some(id) {
            Poll::Ready(priority)
        } else {
            self.wake_next();
            Poll::Pending
        }
    }

    /// A blocked writer must let another stream progress. Incremental writers move
    /// behind other ready streams after each bounded payload quantum.
    pub(crate) fn release(&mut self, id: u64) {
        if let Some(entry) = self.active.get_mut(&id) {
            entry.ready = false;
            if entry.priority.incremental() {
                entry.order = self.clock;
                self.clock = self.clock.saturating_add(1);
            }
        }
        self.wake_next();
    }

    pub(crate) fn complete(&mut self, id: u64) -> Result<(), Error> {
        self.active.remove(&id);
        self.pending.remove(&id);
        if id.is_multiple_of(4) {
            self.completed.insert(id / 4..id / 4 + 1);
        }
        self.wake_next();
        if self.completed.len() > self.limit + 1 {
            return Err(Error::connection(
                Code::H3_EXCESSIVE_LOAD,
                "completed priority range budget exceeded",
            ));
        }
        Ok(())
    }
}

pub(crate) struct Lease {
    pub(crate) shared: std::sync::Arc<super::connection::Shared>,
    pub(crate) id: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let result = self.shared.schedule.lock().complete(self.id);
        if let Err(error) = result {
            self.shared.fail(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_priority_preserves_http_urgency_order() {
        for urgency in 0..=7 {
            let priority = transport_priority(Priority::new(urgency, false).unwrap());
            assert!((0..=7).contains(&priority));
            assert!(priority < i32::MAX);
            if urgency != 7 {
                assert!(priority > transport_priority(Priority::new(urgency + 1, true).unwrap()));
            }
        }
    }

    #[test]
    fn pre_stream_updates_coalesce_and_are_bounded() {
        let mut schedule = Schedule::new(1);
        schedule.update(4, Priority::new(1, true).unwrap()).unwrap();
        schedule.update(4, Priority::new(2, true).unwrap()).unwrap();
        schedule.update(8, Priority::default()).unwrap_err();
        schedule.register(4, Priority::default()).unwrap();
        let cx = Context::from_waker(Waker::noop());
        assert_eq!(
            schedule.poll_turn(4, &cx),
            Poll::Ready(Priority::new(2, true).unwrap())
        );
        schedule.complete(4).unwrap();
        schedule.update(4, Priority::default()).unwrap();
        assert!(schedule.pending.is_empty());
        schedule.update(1, Priority::default()).unwrap_err();
    }

    #[test]
    fn urgency_incremental_and_stalled_writer_progress() {
        let mut schedule = Schedule::new(3);
        let incremental = Priority::new(3, true).unwrap();
        schedule.register(0, incremental).unwrap();
        schedule.register(4, incremental).unwrap();
        schedule
            .register(8, Priority::new(0, false).unwrap())
            .unwrap();
        let cx = Context::from_waker(Waker::noop());
        assert!(schedule.poll_turn(0, &cx).is_ready());
        assert!(schedule.poll_turn(4, &cx).is_pending());
        assert!(schedule.poll_turn(8, &cx).is_ready());
        schedule.release(8);
        schedule.release(0);
        assert!(schedule.poll_turn(4, &cx).is_ready());
        assert!(schedule.poll_turn(0, &cx).is_pending());
    }
}
