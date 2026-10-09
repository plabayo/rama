//! What a pool does at its limits: the saturation policy and the create permit.

use super::*;

/// What a [`MultiplexPool`] at its [total connection limit] does for a checkout
/// that needs a new connection.
///
/// Closing another connection costs that connection's next request a new
/// handshake, so the default waits a little for the checkout's own connections
/// first (see [`Self::EvictIdleAfter`] for its timer). Waiting checkouts are
/// served in arrival order, across ids.
///
/// [total connection limit]: MultiplexPool::with_max_connections_total
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaturationPolicy {
    /// Wait for a connection slot; never close another connection for one.
    Wait,
    /// Close the least recently used idle connection only for a checkout none
    /// of whose connections exist yet; others wait for their own.
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "held: dropping it frees the id's slot")
    )]
    pub(super) id: Option<OwnedSemaphorePermit>,
}

/// How long [`SaturationPolicy::default`] lets a checkout wait for its own
/// connections before it may close another id's idle one.
pub(super) const DEFAULT_EVICT_IDLE_AFTER: Duration = Duration::from_millis(100);
