//! What a pool does at its limits: the saturation policy and the create permit.

use super::*;

/// What a [`MultiplexPool`] at a [connection limit] does for a checkout that
/// needs a new connection: wait, or replace an idle connection, of its own id
/// at the id's limit and of any id at the total one.
///
/// Closing another connection costs that connection's next request a new
/// handshake, so the default waits a little for the checkout's own connections
/// first (see [`Self::EvictIdleAfter`] for its timer). An idle connection goes
/// to the checkout that arrived first among those waiting to use it, to replace
/// it for the total limit and to replace it for its id's limit.
///
/// [connection limit]: MultiplexPool::with_max_connections_total
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SaturationPolicy {
    /// Wait for a connection slot; never close another connection for one.
    Wait,
    /// Close the least recently used idle connection only for a checkout none
    /// of whose connections can take a stream; others wait for their own.
    EvictIdleWhenCold,
    /// As [`Self::EvictIdleWhenCold`], and for any checkout that waited this long.
    ///
    /// Waits on a tokio timer: the runtime needs its time driver enabled.
    EvictIdleAfter(Duration),
    /// Close the least recently used idle connection whenever a checkout needs a
    /// slot.
    EvictIdle,
}

impl Default for SaturationPolicy {
    fn default() -> Self {
        Self::EvictIdleAfter(DEFAULT_EVICT_IDLE_AFTER)
    }
}

/// The share of a [`MultiplexPool`]'s limits a new connection takes: the create
/// permit of [`MultiplexPool::get_conn`]. The connection keeps it while stored.
#[derive(Debug)]
pub struct MultiplexSlot {
    /// Of the total limit, if the pool has one.
    pub(super) total: Option<OwnedSemaphorePermit>,
    /// Of the connection's id, if the pool limits connections per id.
    pub(super) id: Option<IdPermit>,
}

/// The connection limit of one id: its slots, and the checkouts at the limit
/// that may replace one of its idle connections.
#[derive(Debug)]
pub(super) struct IdLimit {
    pub(super) slots: Arc<Semaphore>,
    pub(super) evictors: Arc<WaitQueue>,
}

impl IdLimit {
    pub(super) fn new(max: NonZeroUsize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(max.get())),
            evictors: Arc::new(WaitQueue::new()),
        }
    }

    /// Whether nothing holds a slot of it, waits for one, or a checkout of its
    /// id may queue in it.
    pub(super) fn is_unused(self: &Arc<Self>) -> bool {
        Arc::strong_count(self) == 1
            && Arc::strong_count(&self.slots) == 1
            && Arc::strong_count(&self.evictors) == 1
    }
}

/// One slot of an id's limit, with the limit it belongs to.
#[derive(Debug)]
pub(super) struct IdPermit {
    #[expect(dead_code, reason = "held: dropping it frees the id's slot")]
    pub(super) permit: OwnedSemaphorePermit,
    pub(super) limit: Arc<IdLimit>,
}

/// How long [`SaturationPolicy::default`] lets a checkout wait for its own
/// connections before it may close another id's idle one.
pub(super) const DEFAULT_EVICT_IDLE_AFTER: Duration = Duration::from_millis(100);
