//! Connection ownership for optional fingerprint collection.

use std::sync::Arc;

use parking_lot::Mutex;
use rama::{
    Service,
    extensions::{Extension, ExtensionsRef},
    layer::Layer,
    ua::profile::{capture::observation::ProfileCapture, format::canonical::ValueId},
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

/// A public connection capture with the first request its H3 bootstrap refers to.
#[derive(Debug)]
pub(super) struct ConnectionHandover {
    pub(super) request: ProfileCapture,
    pub(super) connection: ProfileCapture,
}

/// A connection is collected at most once per storage partition, for one profile.
#[derive(Debug, Default)]
struct LeaseState {
    profile: Option<ValueId>,
    phases: [ConnectionPhase; 2],
    handover: Option<Box<ConnectionHandover>>,
}

impl LeaseState {
    fn phase(&mut self, authorized: bool) -> &mut ConnectionPhase {
        &mut self.phases[usize::from(authorized)]
    }
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
    Connection(ConnectionPermit, Option<Box<ConnectionHandover>>),
}

impl CollectionLease {
    /// Eligible collection pins one profile; each partition collects the connection once.
    /// Preparation can be retried after cancellation; an enqueued connection never gets
    /// another ID in its partition.
    pub(super) fn claim(self: &Arc<Self>, owner: CollectionOwner) -> CollectionClaim {
        let mut state = self.state.lock();
        if state
            .profile
            .is_some_and(|previous| previous != owner.profile)
        {
            return CollectionClaim::OwnerMismatch;
        }
        state.profile = Some(owner.profile);
        if *state.phase(owner.authorized) != ConnectionPhase::Available {
            return CollectionClaim::RequestOnly;
        }
        *state.phase(owner.authorized) = ConnectionPhase::Preparing;
        let handover = if owner.authorized {
            state.handover.take()
        } else {
            None
        };
        CollectionClaim::Connection(
            ConnectionPermit {
                lease: self.clone(),
                owner,
                armed: true,
            },
            handover,
        )
    }

    /// A runner can install the authorization cookie after the first request; keep the
    /// public capture so the authorized partition still gets the connection once.
    pub(super) fn offer_handover(&self, handover: Box<ConnectionHandover>) {
        let mut state = self.state.lock();
        if *state.phase(true) == ConnectionPhase::Available {
            state.handover = Some(handover);
        }
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
        *self.lease.state.lock().phase(self.owner.authorized) = ConnectionPhase::Queued;
        self.armed = false;
        ConnectionCompletion {
            lease: self.lease.clone(),
            authorized: self.owner.authorized,
            armed: true,
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if self.armed {
            *self.lease.state.lock().phase(self.owner.authorized) = ConnectionPhase::Available;
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
    authorized: bool,
    armed: bool,
}

impl ConnectionCompletion {
    pub(super) fn finish(mut self, result: CollectionResult) {
        *self.lease.state.lock().phase(self.authorized) = match result {
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
            *self.lease.state.lock().phase(self.authorized) = ConnectionPhase::Unconfirmed;
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
