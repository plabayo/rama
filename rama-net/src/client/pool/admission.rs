//! Transport-owned capacity reservations for retaining pool handouts.

use rama_core::{
    error::BoxError,
    extensions::{Extension, Extensions, TypeErasedExtension},
};
use std::{fmt, future::Future, pin::Pin, sync::Arc};

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
/// must be nonblocking and must not reenter the pool. The pool calls providers
/// outside its storage and admission locks.
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

    /// Subscribe now to the next availability change.
    ///
    /// Subscription must happen before this method returns, rather than when
    /// the future is first polled. Wake for returned reservations, peer credit,
    /// and terminal connection changes. Spurious notifications are permitted.
    fn watch(&self) -> Pin<Box<dyn Future<Output = ()> + Send>>;
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

    /// Subscribe before checking availability to avoid missing a returned credit.
    pub fn watch(&self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        self.0.watch()
    }

    pub(super) async fn acquire(
        &self,
        input: &Extensions,
    ) -> Result<ConnectionAdmissionLease, BoxError> {
        loop {
            let changed = self.watch();
            if let Some(lease) = self.try_acquire(input)? {
                return Ok(lease);
            }
            changed.await;
        }
    }
}
