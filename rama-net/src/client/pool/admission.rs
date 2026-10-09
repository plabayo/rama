//! Transport-owned capacity reservations for retaining pool handouts.

use rama_core::{
    error::BoxError,
    extensions::{Extension, Extensions, TypeErasedExtension},
};
use rama_utils::reactive::{ChangeListener, ChangeWaiter};
use std::{
    fmt,
    future::Future,
    sync::{Arc, Weak},
};

/// A transport's resources reserved for one pool handout.
///
/// The handout publishes the provider's weak, typed binding in a private
/// request extension store. The handout keeps unused resources alive; the
/// protocol takes ownership when starting the request. Dropping an unused
/// handout releases its resources without sending a request.
pub struct ConnectionAdmissionLease {
    keepalive: Arc<dyn Send + Sync>,
    binding: TypeErasedExtension,
}

impl ConnectionAdmissionLease {
    /// Retain a resource and its typed weak binding for the request.
    ///
    /// The binding must not own the reservation: cloned request metadata must
    /// not prolong an unused handout's resource lifetime.
    pub fn new<T: Send + Sync + 'static>(reservation: Arc<T>, binding: impl Extension) -> Self {
        Self {
            keepalive: reservation,
            binding: TypeErasedExtension::new(binding),
        }
    }

    /// Install this handout's binding in an isolated request extension store.
    ///
    /// Call before dispatching the owned input and retain the lease through
    /// dispatch. Cloned input stores remain unchanged.
    pub fn bind(&self, extensions: &mut Extensions) {
        let local = extensions.fork();
        local.insert_erased(self.binding.clone());
        *extensions = local;
    }
}

impl fmt::Debug for ConnectionAdmissionLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionAdmissionLease")
            .field("owners", &Arc::strong_count(&self.keepalive))
            .finish()
    }
}

/// Transport resources required before a pooled connection can be handed out.
///
/// Unlike a concurrency limit, this reserves actual availability. A protocol can
/// consume its typed reservation when it starts the request. Implementations
/// must be nonblocking and must not reenter the pool. The pool calls
/// [`Self::try_acquire`] outside its storage and admission locks;
/// [`Self::subscribe`] and [`Self::in_use`] may run under them, so they only
/// read state and subscribe.
pub trait ConnectionAdmissionPolicy: fmt::Debug + Send + Sync + 'static {
    /// Reserve one request's resources, or return `None` when currently exhausted.
    ///
    /// An error permanently rejects this connection: cached connections are
    /// retired and selection continues; failure on a new connection is returned
    /// to the caller. Request compatibility belongs in `ConnectionReusePolicy`,
    /// not in this resource provider.
    ///
    /// Inspect `input` without mutating it. Return the typed request binding in
    /// the lease; the handout publishes it in an isolated child store when
    /// serving the request.
    fn try_acquire(&self, input: &Extensions)
    -> Result<Option<ConnectionAdmissionLease>, BoxError>;

    /// Wake `listener` after every later availability change, until it is dropped.
    ///
    /// Takes effect before it returns. Wake for returned reservations, peer
    /// credit, the end of work [`Self::in_use`] reports, and the end of the
    /// connection; after that, never again. Spurious wakes are permitted. Report
    /// one returned stream as [`Freed`](rama_utils::reactive::Change::Freed), so
    /// one waiter wakes for it, and anything else as
    /// [`Other`](rama_utils::reactive::Change::Other), which wakes them all. Keep
    /// listeners in a [`ChangeSignal`](rama_utils::reactive::ChangeSignal) or
    /// subscribe them to the sources: a change then wakes them without a task
    /// or an allocation. A source that only has an async change future
    /// forwards it from a task that notifies such a signal.
    fn subscribe(&self, listener: Weak<dyn ChangeListener>);

    /// Whether the connection still carries work no handout accounts for, such
    /// as an upgraded tunnel or a request body still being sent.
    ///
    /// The pool never treats such a connection as idle, so it is neither evicted
    /// nor expired; subscribers must also wake once this work ends. The pool
    /// asks while it holds its own locks: answer from atomics, never block.
    fn in_use(&self) -> bool;
}

/// Resource admission published on an established connection's extensions.
#[derive(Clone, Debug, Extension)]
pub struct ConnectionAdmission(Arc<dyn ConnectionAdmissionPolicy>);

impl ConnectionAdmission {
    /// Publish this connection's resource provider.
    pub fn new(policy: impl ConnectionAdmissionPolicy) -> Self {
        Self(Arc::new(policy))
    }

    /// Attempt a reservation without waiting.
    pub fn try_acquire(
        &self,
        input: &Extensions,
    ) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
        self.0.try_acquire(input)
    }

    /// Wake `listener` after every later availability change, until it is dropped.
    pub fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
        self.0.subscribe(listener);
    }

    /// Subscribe now: completes after the next availability change. Subscribe
    /// before checking availability to avoid missing a returned credit.
    pub fn changed(&self) -> impl Future<Output = ()> + Send + 'static {
        let waiter = ChangeWaiter::new();
        self.0.subscribe(waiter.listener());
        async move { waiter.wait().await }
    }

    /// Whether the connection still carries work no handout accounts for.
    pub fn in_use(&self) -> bool {
        self.0.in_use()
    }

    pub(super) async fn acquire(
        &self,
        input: &Extensions,
    ) -> Result<ConnectionAdmissionLease, BoxError> {
        loop {
            let changed = self.changed();
            if let Some(lease) = self.try_acquire(input)? {
                return Ok(lease);
            }
            changed.await;
        }
    }
}
