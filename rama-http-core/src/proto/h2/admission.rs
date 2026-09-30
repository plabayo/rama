//! Exact request admission for pooled HTTP/2 connections.
//!
//! A pool checkout reserves one of the peer's concurrent streams. The request takes that ticket
//! into its stream, where it lives as long as the stream does: with the pool handout for a
//! plain response, and additionally with a request-body pipe or an upgraded tunnel, which can
//! outlive the response body. HTTP/3 admission follows the same shape.

use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extension, Extensions},
};
use rama_net::{
    client::{
        ConnectionError, ConnectionErrorKind,
        pool::{ConnectionAdmission, ConnectionAdmissionLease, ConnectionAdmissionPolicy},
    },
    conn::MaxConcurrency,
};
use rama_utils::reactive::Reactive;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

/// Per-connection admission state, shared by the connection task and its senders.
#[derive(Debug)]
pub(crate) struct Admission {
    // Tickets alive: reserved by a checkout, or held by a stream that has not ended.
    live: AtomicUsize,
    max: Arc<MaxConcurrency>,
    changed: Reactive<usize>,
    closed: AtomicBool,
}

impl Admission {
    pub(crate) fn new(max: Arc<MaxConcurrency>) -> Arc<Self> {
        Arc::new(Self {
            live: AtomicUsize::new(0),
            max,
            changed: Reactive::new(0),
            closed: AtomicBool::new(false),
        })
    }

    /// The pool-facing policy; it holds the state weakly, so it never keeps a connection alive.
    pub(crate) fn policy(self: &Arc<Self>) -> ConnectionAdmission {
        ConnectionAdmission::new(AdmissionPolicy(Arc::downgrade(self)))
    }

    /// The connection ended: nothing more is admitted, and waiters look again.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.bump();
    }

    /// The ticket a request carries in its extensions, if it was checked out on this connection.
    pub(crate) fn ticket(self: &Arc<Self>, extensions: &Extensions) -> Option<Ticket> {
        let slot = extensions.get_ref::<TicketBinding>()?.0.upgrade()?;
        slot.state
            .upgrade()
            .is_some_and(|state| Arc::ptr_eq(&state, self))
            .then_some(Ticket { _slot: slot })
    }

    fn bump(&self) {
        self.changed.set(self.changed.get().wrapping_add(1));
    }
}

/// Held by the connection task: once it ends, the connection admits nothing more.
#[derive(Debug)]
pub(crate) struct AdmissionOwner(Arc<Admission>);

impl AdmissionOwner {
    pub(crate) fn new(max: Arc<MaxConcurrency>) -> Self {
        Self(Admission::new(max))
    }

    pub(crate) fn policy(&self) -> ConnectionAdmission {
        self.0.policy()
    }

    pub(crate) fn ticket(&self, extensions: &Extensions) -> Option<Ticket> {
        self.0.ticket(extensions)
    }
}

impl Drop for AdmissionOwner {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// One reserved stream; released when its last holder drops.
#[derive(Debug)]
struct Slot {
    state: Weak<Admission>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        // Release first, then wake: a woken acquirer must see the returned slot.
        if let Some(state) = self.state.upgrade() {
            state.live.fetch_sub(1, Ordering::AcqRel);
            state.bump();
        }
    }
}

/// A request's hold on its reserved stream, released when its last clone drops.
#[derive(Clone, Debug)]
pub(crate) struct Ticket {
    _slot: Arc<Slot>,
}

/// Published in the request's extensions; weak, so cloned request metadata never keeps an
/// unused checkout's slot alive.
#[derive(Clone, Debug, Extension)]
#[extension(tags(http))]
struct TicketBinding(Weak<Slot>);

#[derive(Debug)]
struct AdmissionPolicy(Weak<Admission>);

fn unavailable(reason: &'static str) -> BoxError {
    ConnectionError::application(
        BoxError::from_static_str(reason),
        ConnectionErrorKind::Unavailable,
    )
    .into()
}

impl ConnectionAdmissionPolicy for AdmissionPolicy {
    fn try_acquire(
        &self,
        _input: &Extensions,
    ) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
        let state = self
            .0
            .upgrade()
            .ok_or_else(|| unavailable("HTTP/2 connection released"))?;
        if state.closed.load(Ordering::Acquire) {
            return Err(unavailable("HTTP/2 connection closed"));
        }
        let max = state.max.get();
        if state
            .live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                (live < max).then_some(live + 1)
            })
            .is_err()
        {
            return Ok(None);
        }
        let slot = Arc::new(Slot {
            state: Arc::downgrade(&state),
        });
        let binding = TicketBinding(Arc::downgrade(&slot));
        Ok(Some(ConnectionAdmissionLease::new(slot, binding)))
    }

    fn watch(&self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let Some(state) = self.0.upgrade() else {
            return Box::pin(async {});
        };
        // Subscribe before the pool looks again, so no release or limit change is missed.
        let mut released = state.changed.watch();
        let mut limit = state.max.watch();
        Box::pin(async move {
            tokio::select! {
                _ = released.changed() => (),
                _ = limit.changed() => (),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn admission(max: usize) -> (Arc<Admission>, ConnectionAdmission) {
        let admission = Admission::new(Arc::new(MaxConcurrency::new(max)));
        let policy = admission.policy();
        (admission, policy)
    }

    fn acquire(policy: &ConnectionAdmission) -> Option<ConnectionAdmissionLease> {
        policy.try_acquire(&Extensions::new()).unwrap()
    }

    #[test]
    fn checkouts_are_bounded_by_the_peer_limit() {
        let (state, policy) = admission(2);
        let first = acquire(&policy).unwrap();
        let _second = acquire(&policy).unwrap();
        assert!(acquire(&policy).is_none());
        drop(first);
        assert!(acquire(&policy).is_some());
        assert_eq!(state.live.load(Ordering::Acquire), 1);
    }

    #[test]
    fn a_ticket_outlives_its_checkout() {
        let (state, policy) = admission(1);
        let lease = acquire(&policy).unwrap();
        let mut extensions = Extensions::new();
        lease.bind(&mut extensions);
        let ticket = state.ticket(&extensions).unwrap();
        drop(lease);
        // The stream still holds the slot, like an upgraded tunnel after its response.
        assert!(acquire(&policy).is_none());
        drop(ticket);
        assert!(acquire(&policy).is_some());
    }

    #[test]
    fn tickets_from_another_connection_are_ignored() {
        let (_state, policy) = admission(1);
        let (other, _) = admission(1);
        let lease = acquire(&policy).unwrap();
        let mut extensions = Extensions::new();
        lease.bind(&mut extensions);
        assert!(other.ticket(&extensions).is_none());
    }

    #[test]
    fn a_higher_peer_limit_admits_more() {
        let (state, policy) = admission(1);
        let _first = acquire(&policy).unwrap();
        assert!(acquire(&policy).is_none());
        state.max.set(2);
        assert!(acquire(&policy).is_some());
    }

    #[test]
    fn closed_connections_admit_nothing() {
        let (state, policy) = admission(4);
        state.close();
        policy.try_acquire(&Extensions::new()).unwrap_err();
    }

    #[tokio::test]
    async fn waiters_wake_on_release_and_on_a_limit_change() {
        let (state, policy) = admission(1);
        let lease = acquire(&policy).unwrap();
        let watch = policy.watch();
        drop(lease);
        tokio::time::timeout(Duration::from_secs(5), watch)
            .await
            .unwrap();
        let watch = policy.watch();
        state.max.set(3);
        tokio::time::timeout(Duration::from_secs(5), watch)
            .await
            .unwrap();
    }
}
