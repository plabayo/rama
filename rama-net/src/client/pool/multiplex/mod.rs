//! Multiplexing connection pool.
//!
//! [`MultiplexPool`] keeps every connection in storage and hands out a cheap
//! [`MultiplexedConnection`] that shares a connection through `&self`. A single connection
//! serves up to `min(max_streams_per_connection, MaxConcurrency)` concurrent users, where
//! [`MaxConcurrency`] is the connection's advertised capacity ([`usize::MAX`] when unset) and
//! the pool's own cap is unset by default, so the peer decides. The exclusive
//! [`super::LruDropPool`] is the special case of capacity 1 for owned connections.
//!
//! Because the connector stack runs for every request, a [`MultiplexedConnection`] is
//! established, serves its single request, and is dropped, so a [`MultiplexedConnection`]
//! is bound to exactly one connection (its [`super::ExtensionsRef`] forwards to that
//! connection, which is required for extension propagation such as
//! the negotiated http version) and concurrency is metered by counting live
//! handouts. A [`MultiplexedConnection`] is not meant to outlive a single logical request and
//! when it does it should only be used for one input/request at a time.
//!
//! Checking out a connection does not look at every connection of the ID. Each ID keeps an
//! index of its connections that have a free stream slot, in creation order, and the selection
//! strategy picks from it: the cost of a checkout does not grow with the number of idle
//! connections an ID has accumulated. Selection prefers earlier connections, so a burst that
//! opened many connections leaves the later ones untouched and idle, where the idle timeout
//! reaps them (see [`MultiplexPool::with_idle_timeout`]).
//!
//! Connections are not limited by default. With a limit per ID or in total (see
//! [`MultiplexPool::with_max_connections_per_id`] and
//! [`MultiplexPool::with_max_connections_total`]), a checkout that needs a new connection at
//! the limit waits for a slot or, as the [`SaturationPolicy`] allows, replaces an idle
//! connection: of its own ID at the ID's limit, of any ID at the total one.
//!
//! A checkout that finds no room waits, first come first served, in every lane it can be
//! served from: a released stream wakes the first waiter of its lane, a capacity change of a
//! connection wakes all of them, and newcomers never take capacity ahead of them. A waiter
//! that leaves without using a wake passes it on. An idle connection goes to the checkout
//! that arrived first among its lane's front and the fronts of those waiting to evict it, for
//! the total limit or for its id's: whoever runs first, the others give way to it, and it is
//! told; once it leaves, they are.

mod connection;
mod lanes;
mod policy;
mod waiting;

pub use self::connection::MultiplexedConnection;
use self::connection::{Admitted, ConnectionSlot, StoredConnection, relist_stored, trim_idle};
use self::lanes::{Claimed, IdBucket, Lane, OnlyLane, RequestLanes, Snapshot, select_and_admit};
use self::policy::{IdLimit, IdPermit, IdleLimits};
pub use self::policy::{MultiplexSlot, SaturationPolicy};
use self::waiting::{Blocked, IdSlotWait, Look, SlotWait, Waiting, maybe, maybe_pinned};

use super::reuse::{KeyedLane, LaneKey, ReuseClass};
use super::{
    ConnID, ConnectionAdmission, ConnectionAdmissionLease, ConnectionResult, ConnectionReuse, Pool,
    ReuseKey,
};
use crate::conn::{ConnectionHealth, ConnectionHealthWatcher, MaxConcurrency};
use ahash::{HashMap, HashMapExt as _};
use parking_lot::Mutex;
use rama_core::Service;
use rama_core::error::BoxError;
use rama_core::extensions::{Extension, Extensions, ExtensionsMut, ExtensionsRef, NetExtension};
use rama_core::telemetry::tracing::trace;
use rama_utils::collections::smallvec::SmallVec;
use rama_utils::macros::generate_set_and_with;
use rama_utils::reactive::{Change, ChangeListener, Party, WaitQueue, Waiter, Wakes};
use rama_utils::time::{AtomicInstant, now_monotonic_nanos};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::{AcquireError, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Sleep;

#[cfg(feature = "opentelemetry")]
use super::metrics;
#[cfg(feature = "opentelemetry")]
use std::time::Instant;

/// Strategy used to pick a connection among several that share the same
/// [`ConnID`] and still have stream capacity.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub enum MuxSelection {
    /// Pick the connection with the most free stream slots (best spread).
    #[default]
    LeastLoaded,
    /// Pick the first connection with a free stream slot.
    FirstAvailable,
    /// Cycle through the eligible connections.
    RoundRobin,
}

/// Connections taken out of storage, dropped only after the storage lock is
/// released so their sockets close outside it.
type Doomed<C, ID> = Vec<Arc<StoredConnection<C, ID>>>;

/// What a sweep found under the storage lock, settled once it is released:
/// see [`MultiplexPool::settle`].
struct Swept<C, ID> {
    doomed: Doomed<C, ID>,
    /// Idle connections past the idle timeout whose admission is asked, outside
    /// the lock, whether work outlives their handouts.
    expiring: Doomed<C, ID>,
    /// When the first idle connection the sweep kept expires.
    next_expiry: u64,
}

impl<C, ID> Default for Swept<C, ID> {
    fn default() -> Self {
        Self {
            doomed: Vec::new(),
            expiring: Vec::new(),
            next_expiry: u64::MAX,
        }
    }
}

/// A connection taken out of storage to make room, with its slots.
struct Evicted<C, ID> {
    conn: Arc<StoredConnection<C, ID>>,
    slots: MultiplexSlot,
    /// Whether another connection could have gone instead.
    more: bool,
}

/// How many `open` candidates one checkout tries before it falls back to the
/// exact path. Refusing candidates are the exception; the exact path handles
/// them (and stays O(connections of the lane)).
const OPEN_CANDIDATES: usize = 4;

/// Upper bound on how long an idle or broken connection can linger unnoticed
/// in a bucket whose checkouts never come across it. Sweeping the bucket at
/// this pace amortizes to nothing.
const MAX_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

const MIN_SWEEP_INTERVAL: Duration = Duration::from_millis(1);

/// Connections grouped by id, so a handout only touches its own bucket and
/// the lock is never held for a scan of the whole pool.
struct Storage<C, ID> {
    by_id: HashMap<ID, IdBucket<C, ID>>,
    /// The connection slots of every id, if the pool limits them per id: kept
    /// while a connection, create permit or waiter holds one of them.
    id_slots: HashMap<ID, Arc<IdLimit>>,
}

/// Take `conn` out of storage, if it is still stored.
fn unstore<C, ID: ConnID>(
    storage: &mut Storage<C, ID>,
    conn: &StoredConnection<C, ID>,
) -> Option<Arc<StoredConnection<C, ID>>> {
    let bucket = storage.by_id.get_mut(&conn.id)?;
    let removed = bucket.remove(conn);
    if bucket.is_empty() {
        storage.by_id.remove(&conn.id);
    }
    removed
}

/// Connection pool that multiplexes concurrent users over shared
/// connections.
pub struct MultiplexPool<C, ID> {
    storage: Arc<Mutex<Storage<C, ID>>>,
    max_connections_total: Option<NonZeroUsize>,
    total_slots: Option<Arc<Semaphore>>,
    saturation: SaturationPolicy,
    max_connections_per_id: Option<NonZeroUsize>,
    idle_limits: Option<Arc<IdleLimits>>,
    idle_timeout: Option<Duration>,
    max_concurrent_streams: usize,
    selection: MuxSelection,
    rr_cursor: Arc<AtomicUsize>,
    next_seq: Arc<AtomicU64>,
    /// See [`StoredConnection::notify`].
    notify: Arc<Notify>,
    /// Checkouts waiting for capacity, see [`StoredConnection::waiting`].
    waiting: Arc<AtomicUsize>,
    /// See [`StoredConnection::slot_waiters`].
    slot_waiters: Arc<WaitQueue>,
    /// Arrival order of waiting checkouts, across ids.
    next_order: Arc<AtomicU64>,
    #[cfg(feature = "opentelemetry")]
    metrics: Option<Arc<metrics::PoolMetrics>>,
}

// We need a manual impl, derive(Extension) adds a Debug bound on all generics otherwise

impl<C: Send, ID> Extension for MultiplexPool<C, ID>
where
    C: Send + Sync + 'static,
    ID: Send + Sync + Debug + 'static,
{
}

impl<C, ID> NetExtension for MultiplexPool<C, ID>
where
    C: Send + Sync + 'static,
    ID: Send + Sync + Debug + 'static,
{
}

impl<C, ID> Debug for MultiplexPool<C, ID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexPool")
            .field("max_connections_total", &self.max_connections_total)
            .field("saturation", &self.saturation)
            .field("max_connections_per_id", &self.max_connections_per_id)
            .field("idle_limits", &self.idle_limits)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_concurrent_streams", &self.max_concurrent_streams)
            .field("selection", &self.selection)
            .finish()
    }
}

impl<C, ID> Clone for MultiplexPool<C, ID> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            max_connections_total: self.max_connections_total,
            total_slots: self.total_slots.clone(),
            saturation: self.saturation,
            max_connections_per_id: self.max_connections_per_id,
            idle_limits: self.idle_limits.clone(),
            idle_timeout: self.idle_timeout,
            max_concurrent_streams: self.max_concurrent_streams,
            selection: self.selection,
            rr_cursor: self.rr_cursor.clone(),
            next_seq: self.next_seq.clone(),
            notify: self.notify.clone(),
            waiting: self.waiting.clone(),
            slot_waiters: self.slot_waiters.clone(),
            next_order: self.next_order.clone(),
            #[cfg(feature = "opentelemetry")]
            metrics: self.metrics.clone(),
        }
    }
}

impl<C, ID> Default for MultiplexPool<C, ID> {
    fn default() -> Self {
        Self {
            storage: Arc::new(Mutex::new(Storage {
                by_id: HashMap::new(),
                id_slots: HashMap::new(),
            })),
            max_connections_total: None,
            total_slots: None,
            saturation: SaturationPolicy::default(),
            max_connections_per_id: None,
            idle_limits: None,
            idle_timeout: None,
            max_concurrent_streams: usize::MAX,
            selection: MuxSelection::default(),
            rr_cursor: Arc::new(AtomicUsize::new(0)),
            next_seq: Arc::new(AtomicU64::new(0)),
            notify: Arc::new(Notify::new()),
            waiting: Arc::new(AtomicUsize::new(0)),
            slot_waiters: Arc::new(WaitQueue::new()),
            next_order: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "opentelemetry")]
            metrics: None,
        }
    }
}

impl<C, ID> MultiplexPool<C, ID> {
    /// Create a [`MultiplexPool`] without limits: each connection serves as many
    /// concurrent users as its peer allows, and connections are added as needed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The pool most tests use: at most `streams` per connection and `total`
    /// connections, evicting an idle one whenever a checkout needs a slot.
    #[cfg(test)]
    pub(crate) fn evicting(streams: usize, total: usize) -> Self {
        Self::new()
            .with_max_streams_per_connection(NonZeroUsize::new(streams).unwrap())
            .with_max_connections_total(NonZeroUsize::new(total).unwrap())
            .with_saturation_policy(SaturationPolicy::EvictIdle)
    }

    /// The total limit's free slots.
    #[cfg(test)]
    pub(crate) fn free_slots(&self) -> usize {
        self.total_slots
            .as_ref()
            .expect("a total limit")
            .available_permits()
    }

    /// A create permit taken from the total limit directly.
    #[cfg(test)]
    pub(crate) fn test_slot(&self) -> MultiplexSlot {
        let total = self.total_slots.as_ref().expect("a total limit");
        MultiplexSlot {
            total: Some(total.clone().try_acquire_owned().expect("a free slot")),
            id: None,
        }
    }

    generate_set_and_with! {
        /// Serve at most this many concurrent users per connection, below what the
        /// connection's [`MaxConcurrency`] allows. Unset, the peer decides.
        pub fn max_streams_per_connection(mut self, max: Option<NonZeroUsize>) -> Self {
            self.max_concurrent_streams = max.map_or(usize::MAX, NonZeroUsize::get);
            self
        }
    }

    /// Keep at most `max` connections, stored or being established, across all
    /// ids. At the limit, [`SaturationPolicy`] decides. Without it, no limit.
    ///
    /// Configure it before the pool is used: clones share its connections, and
    /// so the slots they hold. Waiting at the limit may use tokio timers (the
    /// default policy's, the idle timeout's): the runtime needs its time driver.
    #[must_use]
    pub fn with_max_connections_total(self, max: NonZeroUsize) -> Self {
        self.maybe_with_max_connections_total(Some(max))
    }

    /// See [`Self::with_max_connections_total`]; `None` is no limit.
    #[must_use]
    pub fn maybe_with_max_connections_total(mut self, max: Option<NonZeroUsize>) -> Self {
        self.max_connections_total = max;
        self.total_slots = max.map(|max| Arc::new(Semaphore::new(max.get())));
        self
    }

    generate_set_and_with! {
        /// What a checkout that needs a connection does at a limit, see
        /// [`Self::with_max_connections_total`] and
        /// [`Self::with_max_connections_per_id`].
        pub fn saturation_policy(mut self, policy: SaturationPolicy) -> Self {
            self.saturation = policy;
            self
        }
    }

    /// Keep at most `max` connections, stored or being established, per id: at
    /// the limit a checkout waits for its id's capacity or, as
    /// [`SaturationPolicy`] allows, replaces one of the id's idle connections;
    /// other ids go on. Without it, no limit.
    ///
    /// Configure it before the pool is used: clones share the slots of each id.
    /// Waiting at the limit may use tokio timers (the default policy's, the idle
    /// timeout's): the runtime needs its time driver.
    #[must_use]
    pub fn with_max_connections_per_id(self, max: NonZeroUsize) -> Self {
        self.maybe_with_max_connections_per_id(Some(max))
    }

    /// See [`Self::with_max_connections_per_id`]; `None` is no limit.
    #[must_use]
    pub fn maybe_with_max_connections_per_id(mut self, max: Option<NonZeroUsize>) -> Self {
        self.max_connections_per_id = max;
        self
    }

    /// Keep at most `max` idle connections per id: once more go idle, the least
    /// recently used ones close. It never holds back a checkout, and nothing
    /// closes while checkouts wait. Without it, no limit.
    ///
    /// Configure it before the pool is used: clones share their count.
    #[must_use]
    pub fn with_max_idle_per_id(self, max: NonZeroUsize) -> Self {
        self.maybe_with_max_idle_per_id(Some(max))
    }

    /// See [`Self::with_max_idle_per_id`]; `None` is no limit.
    #[must_use]
    pub fn maybe_with_max_idle_per_id(mut self, max: Option<NonZeroUsize>) -> Self {
        let total = self.idle_limits.as_ref().and_then(|limits| limits.total);
        self.idle_limits = IdleLimits::new(max, total);
        self
    }

    /// Keep at most `max` idle connections across all ids, as
    /// [`Self::with_max_idle_per_id`] does per id.
    #[must_use]
    pub fn with_max_idle_total(self, max: NonZeroUsize) -> Self {
        self.maybe_with_max_idle_total(Some(max))
    }

    /// See [`Self::with_max_idle_total`]; `None` is no limit.
    #[must_use]
    pub fn maybe_with_max_idle_total(mut self, max: Option<NonZeroUsize>) -> Self {
        let per_id = self.idle_limits.as_ref().and_then(|limits| limits.per_id);
        self.idle_limits = IdleLimits::new(per_id, max);
        self
    }

    generate_set_and_with! {
        /// Drop connections that have been idle (no active streams) for longer than
        /// the given timeout. Only checked when a connection is requested: the
        /// connection a checkout is about to hand out is always checked, and the
        /// id's other connections are swept at least about once a second. A
        /// checkout waiting at a connection limit looks again once one would
        /// expire, on a tokio timer: the runtime needs its time driver enabled.
        pub fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.idle_timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Set the [`MuxSelection`] strategy used to pick among same-id connections.
        pub fn selection(mut self, selection: MuxSelection) -> Self {
            self.selection = selection;
            self
        }
    }

    #[cfg(feature = "opentelemetry")]
    generate_set_and_with! {
        #[cfg_attr(docsrs, doc(cfg(feature = "opentelemetry")))]
        pub fn metrics(mut self, metrics: Option<Arc<metrics::PoolMetrics>>) -> Self {
            self.metrics = metrics;
            self
        }
    }
}

impl<C, ID> MultiplexPool<C, ID>
where
    C: Send + Sync + ExtensionsRef + 'static,
    ID: ConnID,
{
    /// Whether a stored connection may still be handed out: not marked broken
    /// (in-flight streams keep a broken connection alive via the outstanding
    /// handles, but it is no longer handed out) and not idle past the idle
    /// timeout, which retires it. Asks its admission: call without the storage
    /// lock.
    fn is_eligible(&self, conn: &StoredConnection<C, ID>, now: u64) -> bool {
        if Self::is_broken(conn) {
            return false;
        }
        !(self.expiry(conn).is_some_and(|at| at <= now)
            && conn.retire_if(|conn| self.has_expired(conn)).is_some())
    }

    /// Whether the health watcher of `conn` marks it broken.
    fn is_broken(conn: &StoredConnection<C, ID>) -> bool {
        let broken = conn
            .conn
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .is_some_and(|watcher| watcher.health() == ConnectionHealth::Broken);
        if broken {
            trace!(id = ?conn.id, "multiplex pool: dropping broken connection");
        }
        broken
    }

    /// When `conn` passes the idle timeout, if it can be idle: from atomics, so
    /// work outliving its handouts is only known once its admission is asked.
    fn expiry(&self, conn: &StoredConnection<C, ID>) -> Option<u64> {
        let timeout = self.idle_timeout?;
        conn.maybe_idle().then(|| {
            conn.last_idle
                .as_nanos()
                .saturating_add(timeout.as_nanos() as u64)
        })
    }

    /// Whether `conn` is idle past the idle timeout. Asks its admission first:
    /// seeing work that outlived its handouts restarts the idle clock.
    fn has_expired(&self, conn: &StoredConnection<C, ID>) -> bool {
        let expired = conn.is_idle()
            && self
                .idle_timeout
                .is_some_and(|timeout| conn.last_idle.elapsed() >= timeout);
        if expired {
            trace!(id = ?conn.id, "multiplex pool: dropping idle connection");
        }
        expired
    }

    /// The pace of the full bucket sweeps that reap connections which checkouts
    /// never come across, a quarter of the idle timeout within fixed bounds.
    fn sweep_interval(&self) -> Duration {
        self.idle_timeout
            .map_or(MAX_SWEEP_INTERVAL, |timeout| timeout / 4)
            .clamp(MIN_SWEEP_INTERVAL, MAX_SWEEP_INTERVAL)
    }

    /// The instant the next sweep of a bucket swept now is due.
    fn next_sweep_after(&self, now: u64) -> u64 {
        now.saturating_add(self.sweep_interval().as_nanos() as u64)
    }

    /// Move broken connections, and idle ones past the idle timeout without an
    /// admission to ask, out of `bucket` into `swept`. Idle ones past it with
    /// an admission stay: their admission is asked once the lock is released.
    fn sweep_bucket(&self, bucket: &mut IdBucket<C, ID>, swept: &mut Swept<C, ID>) {
        let now = now_monotonic_nanos();
        bucket.next_sweep = self.next_sweep_after(now);
        bucket.retain(|conn| {
            let gone = if Self::is_broken(conn) {
                conn.pool_slot.lock().retired = true;
                true
            } else {
                match self.expiry(conn) {
                    Some(at) if at > now => {
                        swept.next_expiry = swept.next_expiry.min(at);
                        false
                    }
                    Some(_) if conn.admission.is_some() => {
                        swept.expiring.push(conn.clone());
                        false
                    }
                    // Nothing outlives its handouts unannounced: it is idle.
                    Some(_) => conn.retire_if(StoredConnection::maybe_idle).is_some(),
                    None => false,
                }
            };
            if gone {
                swept.doomed.push(conn.clone());
            }
            !gone
        });
    }

    /// Finish a sweep without the storage lock: retire the expiring connections
    /// their admission reports idle, take them out of storage, and close
    /// everything the sweep took out.
    fn settle(&self, swept: Swept<C, ID>) {
        let Swept {
            doomed, expiring, ..
        } = swept;
        let expired: Doomed<C, ID> = expiring
            .into_iter()
            .filter(|conn| conn.retire_if(|conn| self.has_expired(conn)).is_some())
            .collect();
        if !expired.is_empty() {
            let mut storage = self.storage.lock();
            for conn in &expired {
                drop(unstore(&mut storage, conn));
            }
        }
        drop((expired, doomed));
    }

    /// The lanes able to serve `input`: its key's lane in each class of the
    /// id's bucket, and the unrestricted lane.
    ///
    /// Derives request keys through the connectors' policies, outside the
    /// storage lock. A lane can be missing from storage by the time it is
    /// used, which only means it has no connections.
    fn request_lanes(&self, id: &ID, input: &Extensions) -> RequestLanes {
        let classes = self
            .storage
            .lock()
            .by_id
            .get(id)
            .and_then(IdBucket::classes);
        RequestLanes::derive(classes, input)
    }

    /// Sweep the bucket for `id` and copy out what is left in `lanes`. Every
    /// exact handout path must go through this before selecting.
    fn snapshot(
        &self,
        storage: &mut Storage<C, ID>,
        id: &ID,
        lanes: &RequestLanes,
        swept: &mut Swept<C, ID>,
        look: &mut Look<'_>,
    ) -> Snapshot<C, ID> {
        let Some(bucket) = storage.by_id.get_mut(id) else {
            return Snapshot::new();
        };
        self.sweep_bucket(bucket, swept);
        look.note_expiry(swept.next_expiry);
        if bucket.is_empty() {
            storage.by_id.remove(id);
            return Snapshot::new();
        }
        let mut snapshot = Snapshot::new();
        let mut lanes_seen = 0;
        for lane in bucket.request_lanes_mut(lanes) {
            if let Look::Register(waiting) = look {
                waiting.register(&lane.waiters);
            }
            if !lane.waiters.admits(
                look.waiting()
                    .and_then(|waiting| waiting.waiter_in(&lane.waiters)),
            ) {
                continue;
            }
            lanes_seen += usize::from(!lane.conns.is_empty());
            snapshot.extend(
                lane.conns
                    .iter()
                    .filter(|conn| !swept.expiring.iter().any(|gone| Arc::ptr_eq(gone, conn)))
                    .map(|conn| {
                        let Claimed { conn, lane_gen } = Claimed::new(conn.clone());
                        (conn, lane_gen)
                    }),
            );
        }
        // Selection treats the lanes as one index in creation order.
        if lanes_seen > 1 {
            snapshot.sort_unstable_by_key(|(conn, _)| conn.seq);
        }
        snapshot
    }

    /// Sweep every bucket. Slow path only: it frees pool slots held by stale
    /// connections of other ids before falling back to LRU eviction.
    fn sweep_all(&self, storage: &mut Storage<C, ID>, swept: &mut Swept<C, ID>) {
        storage.by_id.retain(|_, bucket| {
            self.sweep_bucket(bucket, swept);
            !bucket.is_empty()
        });
    }

    /// Evict the least recently used idle connection, of `within` or of any
    /// id, for `evictor` (none: a newcomer) of `chances`, returning it with its
    /// slots, so the caller can take them over, and whether another one could
    /// have gone.
    ///
    /// Picks from atomics under `storage`, then retires the pick with the lock
    /// released: its admission is asked about work outliving its handouts and
    /// may take the source's own locks. A pick that turns out busy is skipped.
    fn evict_lru_idle<'a>(
        &'a self,
        mut storage: parking_lot::MutexGuard<'a, Storage<C, ID>>,
        evictor: Option<&Waiting>,
        chances: &Arc<WaitQueue>,
        within: Option<&ID>,
    ) -> Option<Evicted<C, ID>> {
        let mut busy: SmallVec<[u64; 2]> = SmallVec::new();
        loop {
            let (conn, more) = self.pick_lru_idle(&storage, evictor, chances, within, &busy)?;
            drop(storage);
            let retired = conn.retire_if(StoredConnection::is_idle).map(|mut slot| {
                std::mem::replace(
                    &mut slot.slots,
                    MultiplexSlot {
                        total: None,
                        id: None,
                    },
                )
            });
            if let Some(slots) = retired {
                let stored = unstore(&mut self.storage.lock(), &conn);
                return Some(Evicted {
                    conn: stored.unwrap_or(conn),
                    slots,
                    more,
                });
            }
            busy.push(conn.seq);
            storage = self.storage.lock();
            // An older evictor may have queued ahead meanwhile.
            if !chances.admits(evictor.and_then(|evictor| evictor.waiter_in(chances))) {
                return None;
            }
        }
    }

    /// The least recently used connection that can be idle, of `within` or of
    /// any id, but not `busy`, and whether another one could have gone instead.
    ///
    /// An idle connection that can take a stream is its lane's waiters', unless
    /// the evictor arrived before them or is their front (its own look just
    /// found nothing it could use there). Its slots are the other limit's
    /// evictors' if one of them arrived first: the evictor gives way to them,
    /// queued in `chances`.
    fn pick_lru_idle(
        &self,
        storage: &Storage<C, ID>,
        evictor: Option<&Waiting>,
        chances: &Arc<WaitQueue>,
        within: Option<&ID>,
        busy: &[u64],
    ) -> Option<(Arc<StoredConnection<C, ID>>, bool)> {
        let order = evictor.map_or(u64::MAX, |evictor| evictor.party.order());
        loop {
            let mut gave_way = SmallVec::new();
            let picked = match within {
                Some(id) => Self::pick_lru_idle_of(
                    storage.by_id.get(id).into_iter().flat_map(IdBucket::lanes),
                    order,
                    Some(&self.slot_waiters),
                    busy,
                    &mut gave_way,
                ),
                None => Self::pick_lru_idle_of(
                    storage.by_id.values().flat_map(IdBucket::lanes),
                    order,
                    None,
                    busy,
                    &mut gave_way,
                ),
            };
            if let Some((conn, more)) = picked {
                return Some((conn.clone(), more));
            }
            // Woken once they leave. One that left meanwhile left its
            // connection to this evictor: look again.
            if evictor.is_none()
                || gave_way
                    .iter()
                    .all(|rivals: &&Arc<WaitQueue>| rivals.give_way(order, order, chances))
            {
                return None;
            }
        }
    }

    /// [`Self::pick_lru_idle`] among `lanes` for an evictor of `order`.
    /// Connections whose slots the other limit's older evictors contend for,
    /// `rivals` or else their id's, are left to them: their queues are
    /// collected in `gave_way`.
    fn pick_lru_idle_of<'a>(
        lanes: impl Iterator<Item = &'a Lane<C, ID>>,
        order: u64,
        rivals: Option<&'a Arc<WaitQueue>>,
        busy: &[u64],
        gave_way: &mut SmallVec<[&'a Arc<WaitQueue>; 2]>,
    ) -> Option<(&'a Arc<StoredConnection<C, ID>>, bool)>
    where
        C: 'a,
        ID: 'a,
    {
        let mut candidate = None;
        let mut oldest = u64::MAX;
        let mut found = 0_usize;
        // Plain loops: this scans every connection of the lanes.
        for lane in lanes {
            let spoken_for = lane
                .waiters
                .front_order()
                .is_some_and(|front| front < order);
            for conn in &lane.conns {
                if spoken_for && conn.has_capacity(conn.stream_cap) {
                    continue;
                }
                if !conn.maybe_idle() || busy.contains(&conn.seq) {
                    continue;
                }
                if let Some(rivals) = rivals.or(conn.id_evictors.as_ref())
                    && rivals.front_order().is_some_and(|front| front < order)
                {
                    if !gave_way.iter().any(|queue| Arc::ptr_eq(queue, rivals)) {
                        gave_way.push(rivals);
                    }
                    continue;
                }
                found += 1;
                let last_idle = conn.last_idle.as_nanos();
                if last_idle < oldest {
                    oldest = last_idle;
                    candidate = Some(conn);
                }
            }
        }
        Some((candidate?, found > 1))
    }

    /// Evict an idle connection, of `within` or of any id, for a checkout of
    /// `id` the saturation policy lets evict: it queues for the chances of
    /// `chances` first, and the older ones there go first. Returns the slots of
    /// the evicted connection.
    fn evict_for(
        &self,
        id: &ID,
        lanes: &RequestLanes,
        look: &mut Look<'_>,
        patient: bool,
        chances: &Arc<WaitQueue>,
        within: Option<&ID>,
    ) -> Option<MultiplexSlot> {
        let evicted = {
            let mut storage = self.storage.lock();
            // Connections that cannot take a stream do not count.
            let cold = storage.by_id.get_mut(id).is_none_or(|bucket| {
                bucket.request_lanes_mut(lanes).into_iter().all(|lane| {
                    !lane
                        .conns
                        .iter()
                        .any(|conn| conn.effective_capacity(conn.stream_cap) > 0)
                })
            });
            if !self.may_evict(cold, patient) {
                return None;
            }
            // Queued before looking for a connection to evict: see
            // `StoredConnection::freed`.
            if let Look::Register(waiting) = look {
                waiting.register_for_chances(chances);
            }
            let waiting = look.waiting();
            if !chances.admits(waiting.and_then(|waiting| waiting.waiter_in(chances))) {
                return None;
            }
            self.evict_lru_idle(storage, waiting, chances, within)?
        };
        drop(evicted.conn);
        if let Look::Register(waiting) = look {
            waiting.served(Some(chances.clone()));
        }
        if evicted.more {
            // Another idle connection could go too: the next one may look.
            chances.wake_one();
        }
        Some(evicted.slots)
    }

    /// Whether `conn` is idle and kept for a checkout waiting to evict it that
    /// arrived before this one (`waiting`, or a newcomer) and before its lane's
    /// front: a waiting checkout gives way to it, which looks then, and its
    /// lane is woken once it leaves. Asks its admission whether work outlives
    /// its handouts: call without the storage lock.
    fn kept_for_evictor(&self, conn: &StoredConnection<C, ID>, waiting: Option<&Waiting>) -> bool {
        let lane = conn.lane_waiters.lock().clone();
        // The lane's own front goes first: its FIFO serves this checkout in turn.
        let than = waiting
            .map_or(u64::MAX, |waiting| waiting.party.order())
            .min(
                lane.as_ref()
                    .and_then(|lane| lane.front_order())
                    .unwrap_or(u64::MAX),
            );
        let older = |evictors: &WaitQueue| evictors.front_order().is_some_and(|front| front < than);
        if !(older(&self.slot_waiters) || conn.id_evictors.as_deref().is_some_and(older))
            || !conn.is_idle()
        {
            return false;
        }
        // A newcomer looks again once it waits.
        let (Some(waiting), Some(lane)) = (waiting, lane) else {
            return true;
        };
        let from = waiting.party.order();
        let total = self.slot_waiters.give_way(than, from, &lane);
        let id = conn
            .id_evictors
            .as_ref()
            .is_some_and(|evictors| evictors.give_way(than, from, &lane));
        total || id
    }

    /// Leave the connections of `snapshot` kept for an older evictor out: see
    /// [`Self::kept_for_evictor`].
    fn leave_kept(&self, snapshot: &mut Snapshot<C, ID>, waiting: Option<&Waiting>) {
        snapshot.retain(|(conn, _)| !self.kept_for_evictor(conn, waiting));
    }

    /// Fast checkout: hand out the connection the selection strategy prefers
    /// among those the request's lanes list as having room, without looking at
    /// any other connection. Without a handout it returns the request's lanes:
    /// nothing listed can take the request, which does not mean no connection
    /// can, see [`Self::snapshot_exact`].
    ///
    /// A bucket with a single lane, the common case, is claimed from before
    /// the request's lanes are derived outside the lock, so the storage lock
    /// is taken once. The lock is held only to pick and claim a candidate,
    /// no longer than a map lookup and a pop, and never across a compatibility
    /// policy, a resource provider or the connection's own admission.
    fn checkout_open(
        &self,
        id: &ID,
        input: &Extensions,
        waiting: Option<&Waiting>,
    ) -> Result<MultiplexedConnection<C, ID>, Box<RequestLanes>> {
        if !id.is_reusable() {
            return Err(Box::new(RequestLanes::unrestricted()));
        }
        let cap = self.max_concurrent_streams;
        // Candidates claimed but not used, tried in this order of trouble:
        // `rejected` ones are alive but refused the stream or serve other
        // requests, and go back to `open`, `retired` ones are gone. Settled
        // under one lock once the checkout is done.
        let mut rejected: SmallVec<[Arc<StoredConnection<C, ID>>; 2]> = SmallVec::new();
        let mut retired: SmallVec<[Arc<StoredConnection<C, ID>>; 2]> = SmallVec::new();
        let mut skip: SmallVec<[u64; 4]> = SmallVec::new();
        let mut swept = Swept::default();
        let mut handout = None;

        let now = now_monotonic_nanos();
        let (only_lane, mut next, mut classes) = {
            let mut storage = self.storage.lock();
            let Some(bucket) = storage.by_id.get_mut(id) else {
                return Err(Box::new(RequestLanes::unrestricted()));
            };
            if now >= bucket.next_sweep {
                self.sweep_bucket(bucket, &mut swept);
            }
            let classes = bucket.classes();
            match bucket.claim_only(self.selection, cap, waiting) {
                Some((only, claimed)) => (Some(only), claimed, classes),
                None => (None, None, classes),
            }
        };
        // Derived once needed: a hit in an unrestricted lane needs no lanes.
        let mut lanes = None;
        // With a single lane the first look saw every connection listed.
        let mut exhausted = only_lane.is_some();
        // A keyed only lane has the only class: its one key decides.
        if let Some(OnlyLane::Keyed(key)) = &only_lane {
            let derived = lanes.insert(RequestLanes::derive(classes.take(), input));
            if derived.keys.first().and_then(Option::as_ref) != Some(key)
                && let Some(claimed) = next.take()
            {
                rejected.push(claimed.conn);
            }
        }

        for _ in 0..OPEN_CANDIDATES {
            let Claimed { conn, lane_gen } = match next.take() {
                Some(claimed) => claimed,
                None if exhausted => break,
                None => {
                    let lanes =
                        lanes.get_or_insert_with(|| RequestLanes::derive(classes.take(), input));
                    let mut storage = self.storage.lock();
                    let Some(bucket) = storage.by_id.get_mut(id) else {
                        break;
                    };
                    let Some(claimed) = bucket.claim(lanes, self.selection, cap, &skip, waiting)
                    else {
                        break;
                    };
                    claimed
                }
            };
            exhausted = false;
            skip.push(conn.seq);
            if !self.is_eligible(&conn, now) {
                retired.push(conn);
                continue;
            }
            if self.kept_for_evictor(&conn, waiting) {
                rejected.push(conn);
                continue;
            }
            match conn.try_admit(lane_gen, cap, input) {
                Some(Admitted(admission)) => {
                    handout = Some(MultiplexedConnection {
                        inner: conn,
                        admission,
                    });
                    break;
                }
                None => rejected.push(conn),
            }
        }

        if !rejected.is_empty() || !retired.is_empty() {
            {
                let mut storage = self.storage.lock();
                let mut empty = false;
                if let Some(bucket) = storage.by_id.get_mut(id) {
                    for conn in &retired {
                        if let Some(removed) = bucket.remove(conn) {
                            removed.pool_slot.lock().retired = true;
                            swept.doomed.push(removed);
                        }
                    }
                    for conn in &rejected {
                        bucket.list(conn);
                    }
                    empty = bucket.is_empty();
                }
                if empty {
                    storage.by_id.remove(id);
                }
            }
            // Connections that were retired, and so may be the last handle to a
            // socket, close outside the lock.
            drop((retired, rejected));
        }
        self.settle(swept);
        handout
            .ok_or_else(|| Box::new(lanes.unwrap_or_else(|| RequestLanes::derive(classes, input))))
    }

    /// Exact checkout: sweep the bucket, then select among every connection of
    /// the request's lanes with room. Where [`Self::checkout_open`] trusts the
    /// lanes' index, this reads every connection's live capacity, so it also
    /// finds room the index does not show, and lists it.
    ///
    /// A waiting checkout queues in the lanes it reads, before it reads them.
    /// A new checkout only takes a snapshot if some connection has room,
    /// keeping fully busy lanes, which are the reason to create a connection
    /// or wait, at a bare scan of counters. Then the snapshot is empty and the
    /// flag says the lanes hold saturated connections.
    fn snapshot_exact(
        &self,
        id: &ID,
        lanes: &RequestLanes,
        look: &mut Look<'_>,
    ) -> (Snapshot<C, ID>, bool) {
        if !id.is_reusable() {
            return (Snapshot::new(), false);
        }
        let mut storage = self.storage.lock();
        if !storage.by_id.contains_key(id) {
            return (Snapshot::new(), false);
        }
        if matches!(look, Look::New) {
            let Some(bucket) = storage.by_id.get_mut(id) else {
                return (Snapshot::new(), false);
            };
            let mut stored = false;
            let mut room = false;
            for lane in bucket.request_lanes_mut(lanes) {
                stored |= !lane.conns.is_empty();
                room |= lane.waiters.admits(None)
                    && lane
                        .conns
                        .iter()
                        .any(|conn| conn.has_capacity(self.max_concurrent_streams));
            }
            if !room {
                return (Snapshot::new(), stored);
            }
        }
        let mut swept = Swept::default();
        let snapshot = self.snapshot(&mut storage, id, lanes, &mut swept, look);
        drop(storage);
        self.settle(swept);
        (snapshot, false)
    }

    /// Turn a fairly acquired total-slot permit into a handout. Reuse a
    /// connection of the request's lanes if capacity became available while
    /// waiting; otherwise return the permit for creating a connection.
    fn admit_with_permit(
        &self,
        id: &ID,
        slot: MultiplexSlot,
        input: &Extensions,
        waiting: &Waiting,
    ) -> ConnectionResult<MultiplexedConnection<C, ID>, MultiplexSlot> {
        let lanes = self.request_lanes(id, input);
        let mut swept = Swept::default();
        let mut same_lane = if id.is_reusable() {
            self.snapshot(
                &mut self.storage.lock(),
                id,
                &lanes,
                &mut swept,
                &mut Look::Waiting(waiting),
            )
        } else {
            Snapshot::new()
        };
        self.settle(swept);
        self.leave_kept(&mut same_lane, Some(waiting));
        if let Some(conn) = select_and_admit(
            &same_lane,
            id,
            self.selection,
            &self.rr_cursor,
            self.max_concurrent_streams,
            input,
        ) {
            trace!(
                ?id,
                "multiplex pool: reusing connection (woken by freed slot)"
            );
            conn.inner.relist();
            return ConnectionResult::Connection(conn);
        }
        trace!(
            ?id,
            "multiplex pool: freed slot acquired, returning create permit"
        );
        ConnectionResult::CreatePermit(slot)
    }

    /// A slot of `id`'s connection limit, if the pool has one per id.
    fn try_id_slot(&self, id: &ID) -> Result<Option<IdPermit>, Blocked> {
        let Some(limit) = self.id_limit(id) else {
            return Ok(None);
        };
        match limit.slots.clone().try_acquire_owned() {
            Ok(permit) => Ok(Some(IdPermit { permit, limit })),
            Err(_at_limit) => Err(Blocked::Id),
        }
    }

    /// Queue for a slot of `id`'s connection limit, if the pool has one per id.
    fn id_slot_wait(&self, id: &ID) -> Option<IdSlotWait> {
        let limit = self.id_limit(id)?;
        Some(Box::pin(async move {
            let permit = limit.slots.clone().acquire_owned().await?;
            Ok(IdPermit { permit, limit })
        }))
    }

    /// The connection limit of `id`, if the pool has one per id.
    fn id_limit(&self, id: &ID) -> Option<Arc<IdLimit>> {
        let max = self.max_connections_per_id?;
        Some(Self::id_limit_in(&mut self.storage.lock(), id, max))
    }

    fn id_limit_in(storage: &mut Storage<C, ID>, id: &ID, max: NonZeroUsize) -> Arc<IdLimit> {
        if let Some(limit) = storage.id_slots.get(id) {
            return limit.clone();
        }
        // Forget the limits of ids that use none, once the map is full; then
        // leave it room for as many again, so this amortizes to O(1).
        let capacity = storage.id_slots.capacity();
        if storage.id_slots.len() >= capacity {
            storage.id_slots.retain(|_, limit| !limit.is_unused());
            if storage.id_slots.len() * 2 > capacity {
                storage.id_slots.reserve(capacity);
            }
        }
        storage
            .id_slots
            .entry(id.clone())
            .or_insert_with(|| Arc::new(IdLimit::new(max)))
            .clone()
    }

    /// A slot of the total limit for a new connection of `id`, if the pool has
    /// one: a free one, one freed by sweeping stale connections, or one evicted
    /// as the saturation policy allows. Also says whether it was evicted.
    fn take_total_slot(
        &self,
        id: &ID,
        lanes: &RequestLanes,
        look: &mut Look<'_>,
        patient: bool,
    ) -> Result<(Option<OwnedSemaphorePermit>, bool), Blocked> {
        let Some(total) = &self.total_slots else {
            return Ok((None, false));
        };
        if let Ok(permit) = total.clone().try_acquire_owned() {
            return Ok((Some(permit), false));
        }
        // Stale connections of any id may hold slots: sweep them out, then let
        // their permits flow back through the semaphore (to the oldest queued
        // waiter, if any) first.
        let mut swept = Swept::default();
        self.sweep_all(&mut self.storage.lock(), &mut swept);
        look.note_expiry(swept.next_expiry);
        self.settle(swept);
        if let Ok(permit) = total.clone().try_acquire_owned() {
            return Ok((Some(permit), false));
        }
        let slots = self
            .evict_for(id, lanes, look, patient, &self.slot_waiters, None)
            .ok_or(Blocked::Total)?;
        // The evicted connection's total slot moves to this checkout without
        // passing the semaphore, where it would go to the oldest queued waiter.
        slots
            .total
            .map(|permit| (Some(permit), true))
            .ok_or(Blocked::Total)
    }

    /// A slot of `id`'s limit taken over from one of its idle connections, as
    /// the saturation policy allows, with that connection's total slot.
    fn replace_within_id(
        &self,
        id: &ID,
        lanes: &RequestLanes,
        look: &mut Look<'_>,
        patient: bool,
    ) -> Option<(IdPermit, Option<OwnedSemaphorePermit>)> {
        let limit = self.id_limit(id)?;
        let mut slots = self.evict_for(id, lanes, look, patient, &limit.evictors, Some(id))?;
        Some((slots.id.take()?, slots.total.take()))
    }

    /// Whether the saturation policy lets a checkout of `lanes` evict: `cold`
    /// says none of its lanes holds a connection, `patient` that it has not
    /// waited past [`SaturationPolicy::EvictIdleAfter`].
    fn may_evict(&self, cold: bool, patient: bool) -> bool {
        match self.saturation {
            SaturationPolicy::Wait => false,
            SaturationPolicy::EvictIdleWhenCold => cold,
            SaturationPolicy::EvictIdleAfter(after) => cold || !patient || after.is_zero(),
            SaturationPolicy::EvictIdle => true,
        }
    }
}

impl<C, ID> Pool<C, ID> for MultiplexPool<C, ID>
where
    C: Send + Sync + ExtensionsRef + 'static,
    ID: ConnID,
{
    type Connection = MultiplexedConnection<C, ID>;
    type CreatePermit = MultiplexSlot;

    async fn get_conn(
        &self,
        id: &ID,
        input: &Extensions,
    ) -> Result<ConnectionResult<Self::Connection, Self::CreatePermit>, BoxError> {
        #[cfg(feature = "opentelemetry")]
        let metrics = self
            .metrics
            .as_ref()
            .map(|metrics| (metrics, metrics.attributes(id)));
        #[cfg(feature = "opentelemetry")]
        let start = Instant::now();

        let reused = |conn: MultiplexedConnection<C, ID>| {
            trace!(?id, "multiplex pool: reusing connection");
            #[cfg(feature = "opentelemetry")]
            if let Some((metrics, attrs)) = &metrics {
                metrics.reused_connections.add(1, attrs);
                metrics.streams.add(1, attrs);
                metrics
                    .concurrent_streams
                    .record(conn.inner.active.load(Ordering::Relaxed) as f64, attrs);
                metrics
                    .active_connection_delay_nanoseconds
                    .record(start.elapsed().as_nanos() as f64, attrs);
            }
            ConnectionResult::Connection(conn)
        };

        // One look for a connection with room or a create permit. A waiting
        // checkout queues in the lanes it looks at before it looks. A slot of
        // the id's limit taken by an earlier look is used, or kept.
        let attempt = |look: &mut Look<'_>,
                       held_id: &mut Option<IdPermit>,
                       patient: bool|
         -> Result<ConnectionResult<_, _>, Blocked> {
            // Common case: an idle or shareable connection is listed in one of
            // the request's lanes.
            let lanes = match self.checkout_open(id, input, look.waiting()) {
                Ok(conn) => return Ok(reused(conn)),
                Err(lanes) => *lanes,
            };

            // Only this id's bucket is touched under the lock; swept
            // connections close after it is released.
            let (mut same_id, saturated_bucket) = self.snapshot_exact(id, &lanes, look);
            if let Look::Register(waiting) = look {
                waiting.leave_other_lanes();
            }
            self.leave_kept(&mut same_id, look.waiting());

            if let Some(conn) = select_and_admit(
                &same_id,
                id,
                self.selection,
                &self.rr_cursor,
                self.max_concurrent_streams,
                input,
            ) {
                // Room the bucket's index did not show is listed from now on.
                conn.inner.relist();
                return Ok(reused(conn));
            }

            let saturation = !same_id.is_empty() || saturated_bucket;
            drop(same_id);

            // A new connection takes a slot of its id's limit, then one of the
            // total; replacing one of the id's idle connections takes both.
            let (id_slot, replaced) = match held_id.take() {
                Some(slot) => (Some(slot), None),
                None => match self.try_id_slot(id) {
                    Ok(slot) => (slot, None),
                    Err(blocked) => match self.replace_within_id(id, &lanes, look, patient) {
                        Some((slot, total)) => (Some(slot), Some(total)),
                        None => return Err(blocked),
                    },
                },
            };
            let (total, evicted) = match replaced {
                Some(total) => (total, true),
                None => match self.take_total_slot(id, &lanes, look, patient) {
                    Ok(taken) => taken,
                    Err(blocked) => {
                        *held_id = id_slot;
                        return Err(blocked);
                    }
                },
            };
            #[cfg(feature = "opentelemetry")]
            if evicted && let Some((metrics, attrs)) = &metrics {
                metrics.evicted_connections.add(1, attrs);
            }
            #[cfg(not(feature = "opentelemetry"))]
            let _ = evicted;

            trace!(
                ?id,
                "multiplex pool: no connection with capacity, returning create permit"
            );
            #[cfg(feature = "opentelemetry")]
            if let Some((metrics, attrs)) = &metrics {
                if saturation {
                    metrics.saturation_created_connections.add(1, attrs);
                }
                metrics
                    .active_connection_delay_nanoseconds
                    .record(start.elapsed().as_nanos() as f64, attrs);
            }
            #[cfg(not(feature = "opentelemetry"))]
            let _ = saturation;
            Ok(ConnectionResult::CreatePermit(MultiplexSlot {
                total,
                id: id_slot,
            }))
        };

        // Fast path: a look without waiting.
        let mut held_id = None;
        if let Ok(result) = attempt(&mut Look::New, &mut held_id, true) {
            return Ok(result);
        }

        // Saturated: queue in the request's lanes, FIFO, and look again on
        // every wake. Slot acquisitions start once a look is blocked on them.
        let mut waiting = Waiting::new(
            &self.waiting,
            &self.slot_waiters,
            self.id_limit(id).map(|limit| limit.evictors.clone()),
            self.next_order.fetch_add(1, Ordering::Relaxed),
        );
        let party = waiting.party.clone();
        let mut id_slot_wait: Option<IdSlotWait> = None;
        let mut total_slot_wait: Option<SlotWait> = None;
        // Armed once a look is blocked on a limit, in place.
        let mut patience: Pin<&mut Option<Sleep>> = std::pin::pin!(None);
        let mut expiry: Pin<&mut Option<Sleep>> = std::pin::pin!(None);
        let mut patient = true;
        loop {
            // Enabled before the look, so no wake between both is lost.
            let mut notified = std::pin::pin!(self.notify.notified());
            notified.as_mut().enable();
            let seen = waiting.begin_look();
            let blocked = match attempt(&mut Look::Register(&mut waiting), &mut held_id, patient) {
                Ok(result) => {
                    if let ConnectionResult::Connection(conn) = &result {
                        waiting.served(conn.inner.lane_waiters.lock().clone());
                    }
                    // A create permit leaves the capacity a wake stood for unused:
                    // dropping `waiting` passes the wake on.
                    return Ok(result);
                }
                Err(blocked) => blocked,
            };
            // Nothing for the wakes this look answered: wait for the next one,
            // keeping the place.
            waiting.end_fruitless_look();
            match blocked {
                Blocked::Id => {
                    if id_slot_wait.is_none() {
                        id_slot_wait = self.id_slot_wait(id);
                    }
                }
                Blocked::Total => {
                    if total_slot_wait.is_none() {
                        total_slot_wait = self
                            .total_slots
                            .clone()
                            .map(|total| Box::pin(total.acquire_owned()) as SlotWait);
                    }
                }
            }
            if let SaturationPolicy::EvictIdleAfter(after) = self.saturation
                && patient
                && patience.is_none()
            {
                patience.set(Some(tokio::time::sleep(after)));
            }
            if let Some(timeout) = self.idle_timeout {
                // An idle connection frees its slots once it expires, and one
                // going idle after this look does not expire before the timeout.
                let now = now_monotonic_nanos();
                let at = waiting
                    .next_expiry
                    .min(now.saturating_add(timeout.as_nanos() as u64));
                let deadline =
                    tokio::time::Instant::now() + Duration::from_nanos(at.saturating_sub(now));
                match expiry.as_mut().as_pin_mut() {
                    Some(sleep) => sleep.reset(deadline),
                    None => expiry.set(Some(tokio::time::sleep_until(deadline))),
                }
            }

            trace!(
                ?id,
                ?blocked,
                "multiplex pool: saturated, waiting for capacity"
            );
            tokio::select! {
                _ = notified => {}
                () = party.woken(seen) => {}
                permit = maybe(&mut id_slot_wait) => {
                    id_slot_wait = None;
                    // The pool never closes its semaphores.
                    held_id = permit.ok();
                }
                () = maybe_pinned(patience.as_mut()) => {
                    patience.set(None);
                    patient = false;
                }
                // Looks again: its sweep takes out what expired.
                () = maybe_pinned(expiry.as_mut()) => {}
                permit = maybe(&mut total_slot_wait) => {
                    total_slot_wait = None;
                    let Ok(permit) = permit else {
                        // The pool never closes its semaphores; treat as spurious.
                        continue;
                    };
                    waiting.begin_look();
                    let slot = MultiplexSlot {
                        total: Some(permit),
                        id: held_id.take(),
                    };
                    let result = self.admit_with_permit(id, slot, input, &waiting);
                    match &result {
                        ConnectionResult::Connection(conn) => {
                            waiting.served(conn.inner.lane_waiters.lock().clone());
                            #[cfg(feature = "opentelemetry")]
                            if let Some((metrics, attrs)) = &metrics {
                                metrics.reused_connections.add(1, attrs);
                                metrics.streams.add(1, attrs);
                                metrics
                                    .concurrent_streams
                                    .record(conn.inner.active.load(Ordering::Relaxed) as f64, attrs);
                                metrics
                                    .active_connection_delay_nanoseconds
                                    .record(start.elapsed().as_nanos() as f64, attrs);
                            }
                            #[cfg(not(feature = "opentelemetry"))]
                            let _ = conn;
                        }
                        ConnectionResult::CreatePermit(_) => {
                            #[cfg(feature = "opentelemetry")]
                            if let Some((metrics, attrs)) = &metrics {
                                metrics
                                    .active_connection_delay_nanoseconds
                                    .record(start.elapsed().as_nanos() as f64, attrs);
                            }
                        }
                    }
                    return Ok(result);
                }
            }
        }
    }

    async fn create(
        &self,
        id: ID,
        conn: C,
        slot: MultiplexSlot,
        input: &Extensions,
    ) -> Result<Self::Connection, BoxError> {
        // The establishing request owns the first reservation before concurrent
        // checkouts can see this connection in storage.
        let admission = match conn.extensions().self_get_ref::<ConnectionAdmission>() {
            Some(provider) => Some(provider.acquire(input).await?),
            None => None,
        };
        // Reuse requirements are read once: the connection keeps its lane.
        let reuse = conn.extensions().get_ref::<ConnectionReuse>();
        let lane = LaneKey::of_connection(reuse).filter(|_| id.is_reusable());
        let id_evictors = slot.id.as_ref().map(|id| id.limit.evictors.clone());
        let conn = Arc::new(StoredConnection {
            max_concurrency: conn.extensions().get_arc::<MaxConcurrency>(),
            health: conn.extensions().get_arc::<ConnectionHealthWatcher>(),
            broken_told: AtomicBool::new(false),
            admission: conn
                .extensions()
                .self_get_ref::<ConnectionAdmission>()
                .cloned(),
            conn,
            id,
            lane: Mutex::new(None),
            filed: AtomicBool::new(false),
            lane_gen: AtomicU64::new(0),
            seq: self.next_seq.fetch_add(1, Ordering::Relaxed),
            stream_cap: self.max_concurrent_streams,
            changes: AtomicU64::new(0),
            busy_at: AtomicU64::new(0),
            active: AtomicUsize::new(1),
            lane_waiters: Mutex::new(None),
            waiting: self.waiting.clone(),
            notify: self.notify.clone(),
            slot_waiters: self.slot_waiters.clone(),
            id_evictors,
            last_idle: AtomicInstant::now(),
            pool_slot: Mutex::new(ConnectionSlot {
                slots: slot,
                retired: false,
            }),
            listed: AtomicBool::new(false),
            storage: Arc::downgrade(&self.storage),
            relist_fn: relist_stored,
            idle_limits: self.idle_limits.clone(),
            counted_idle: AtomicBool::new(false),
            trim_fn: trim_idle,
        });

        // The connection is its sources' listener: a change wakes its lane's
        // waiters, without a task or an allocation per change.
        let listener: Weak<dyn ChangeListener> =
            Arc::downgrade(&conn) as Weak<StoredConnection<C, ID>>;
        if let Some(max_concurrency) = &conn.max_concurrency {
            max_concurrency.subscribe(listener.clone());
        }
        if let Some(health) = conn.conn.extensions().get_ref::<ConnectionHealthWatcher>() {
            health.subscribe(listener.clone());
        }
        if let Some(admission) = &conn.admission {
            admission.subscribe(listener);
        }

        trace!(id = ?conn.id, "multiplex pool: adding new connection");
        if let Some(lane) = lane {
            self.storage
                .lock()
                .by_id
                .entry(conn.id.clone())
                .or_insert_with(|| IdBucket::new(self.next_sweep_after(now_monotonic_nanos())))
                .insert(&conn, lane);
        }

        // A freshly added connection has spare capacity beyond its establishing
        // handout, so make sure to wake parked waiters.
        self.notify.notify_waiters();

        #[cfg(feature = "opentelemetry")]
        if let Some(metrics) = self.metrics.as_ref() {
            let attrs = metrics.attributes(&conn.id);
            metrics.total_connections.add(1, &attrs);
            metrics.created_connections.add(1, &attrs);
            metrics.streams.add(1, &attrs);
            metrics.concurrent_streams.record(1.0, &attrs);
        }

        Ok(MultiplexedConnection {
            inner: conn,
            admission,
        })
    }
}

#[cfg(test)]
mod tests;
