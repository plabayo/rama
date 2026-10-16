//! Connection ownership for optional fingerprint collection.

use std::sync::Arc;

use parking_lot::Mutex;
use rama::{
    Service,
    extensions::{Extension, ExtensionsRef},
    layer::Layer,
    ua::profile::format::canonical::ValueId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CollectionOwner {
    pub authorized: bool,
    pub profile: ValueId,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ConnectionPhase {
    #[default]
    Available,
    Preparing,
    Queued,
    Stored,
    Rejected,
    Unconfirmed,
}

#[derive(Debug, Default)]
struct LeaseState {
    owner: Option<CollectionOwner>,
    phase: ConnectionPhase,
}

/// Installed once on each accepted connection, before any request is dispatched.
#[derive(Debug, Default, Extension)]
pub(super) struct CollectionLease {
    state: Mutex<LeaseState>,
}

#[derive(Debug)]
pub(super) enum CollectionClaim {
    OwnerMismatch,
    RequestOnly,
    Connection(ConnectionPermit),
}

impl CollectionLease {
    /// Eligible collection pins one authorization/profile owner. Preparation can
    /// be retried after cancellation; an enqueued connection never gets another ID.
    pub(super) fn claim(self: &Arc<Self>, owner: CollectionOwner) -> CollectionClaim {
        let mut state = self.state.lock();
        if state.owner.is_some_and(|previous| previous != owner) {
            return CollectionClaim::OwnerMismatch;
        }
        state.owner = Some(owner);
        if state.phase != ConnectionPhase::Available {
            return CollectionClaim::RequestOnly;
        }
        state.phase = ConnectionPhase::Preparing;
        CollectionClaim::Connection(ConnectionPermit {
            lease: self.clone(),
            owner,
            armed: true,
        })
    }
}

#[derive(Debug)]
pub(super) struct ConnectionPermit {
    lease: Arc<CollectionLease>,
    owner: CollectionOwner,
    armed: bool,
}

impl ConnectionPermit {
    pub(super) const fn owner(&self) -> CollectionOwner {
        self.owner
    }
    /// The reserved queue slot receives the returned completion handle. This
    /// transition and the send contain no await point, so cancellation cannot
    /// leave a queued observation available for a second writer ID.
    pub(super) fn queued(mut self) -> ConnectionCompletion {
        self.lease.state.lock().phase = ConnectionPhase::Queued;
        self.armed = false;
        ConnectionCompletion {
            lease: self.lease.clone(),
            armed: true,
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if self.armed {
            self.lease.state.lock().phase = ConnectionPhase::Available;
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum CollectionResult {
    Stored,
    Rejected,
    Unconfirmed,
}

#[derive(Debug)]
pub(super) struct ConnectionCompletion {
    lease: Arc<CollectionLease>,
    armed: bool,
}

impl ConnectionCompletion {
    pub(super) fn finish(mut self, result: CollectionResult) {
        self.lease.state.lock().phase = match result {
            CollectionResult::Stored => ConnectionPhase::Stored,
            CollectionResult::Rejected => ConnectionPhase::Rejected,
            CollectionResult::Unconfirmed => ConnectionPhase::Unconfirmed,
        };
        self.armed = false;
    }
}

impl Drop for ConnectionCompletion {
    fn drop(&mut self) {
        if self.armed {
            // A dropped worker may have lost a commit reply. Do not issue a new
            // observation ID for the same connection or report it as stored.
            self.lease.state.lock().phase = ConnectionPhase::Unconfirmed;
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CollectionLayer;

impl<S> Layer<S> for CollectionLayer {
    type Service = ConnectionCollection<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConnectionCollection { inner }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ConnectionCollection { inner }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ConnectionCollection<S> {
    inner: S,
}

impl<Input, S> Service<Input> for ConnectionCollection<S>
where
    Input: Send + ExtensionsRef + 'static,
    S: Service<Input>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        input.extensions().insert(CollectionLease::default());
        self.inner.serve(input).await
    }
}

#[cfg(test)]
mod tests;
