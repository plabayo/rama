//! Multiplexing connection pool.
//!
//! [`MultiplexPool`] keeps every connection in storage and hands out a cheap
//! [`MultiplexedConnection`] that shares a connection connection through `&self`. A single
//! connection serves up to `min(max_concurrent_streams, MaxConcurrency)` concurrent
//! users (where [`MaxConcurrency`] is the connection's advertised capacity,
//! defaulting to [`usize::MAX`] when unset), the exclusive [`super::LruDropPool`] is the
//! special case of capacity = 1 for owned connections. If the connection pool is at max
//! capacity the pool will wait until a connection with a matching ID has capacity again
//! or it will evict an idle connection with a LRU policy.
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
//! A checkout that finds no room waits, first come first served, in every lane it can be
//! served from: a released stream wakes the first waiter of its lane, a capacity change of a
//! connection wakes all of them, and newcomers never take capacity ahead of them. A waiter
//! that leaves without using a wake passes it on. Idle connections of a lane with waiters are
//! theirs: only once nobody waits there can they be evicted for another ID.

use super::reuse::{KeyedLane, LaneKey, ReuseClass};
use super::{
    ConnID, ConnectionAdmission, ConnectionAdmissionLease, ConnectionResult, ConnectionReuse, Pool,
    PoolSlot, ReuseKey,
};
use crate::conn::{ConnectionHealth, ConnectionHealthWatcher, MaxConcurrency};
use ahash::{HashMap, HashMapExt as _};
use parking_lot::Mutex;
use rama_core::Service;
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorExt};
use rama_core::extensions::{Extension, Extensions, ExtensionsMut, ExtensionsRef, NetExtension};
use rama_core::telemetry::tracing::trace;
use rama_utils::collections::smallvec::SmallVec;
use rama_utils::macros::generate_set_and_with;
use rama_utils::reactive::{Change, ChangeListener, WaitQueue, Waiter, Wakes};
use rama_utils::time::{AtomicInstant, now_monotonic_nanos};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

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

/// A connection stored in a [`MultiplexPool`].
///
/// The connection never leaves the pool, it is shared through [`MultiplexedConnection`]
/// handles and only ever used via `&self`.
struct StoredConnection<C, ID> {
    conn: C,
    id: ID,
    /// The lane the connection is filed under, `None` while it is not stored.
    /// Only accessed with the storage lock held.
    lane: Mutex<Option<LaneKey>>,
    /// Whether the connection is filed in a lane: a hint, so releases of a
    /// connection that is not stored skip the storage lock. Written with it.
    filed: AtomicBool,
    /// Bumped by every [`MultiplexedConnection::rekey`], under the `pool_slot`
    /// lock that admission holds: a candidate selected under an earlier lane
    /// can no longer be admitted.
    lane_gen: AtomicU64,
    /// Creation order within the pool. Orders a lane, and so
    /// [`MuxSelection::FirstAvailable`].
    seq: u64,
    /// The pool's `max_concurrent_streams`, needed to judge spare capacity when
    /// a handout is released.
    stream_cap: usize,
    max_concurrency: Option<Arc<MaxConcurrency>>,
    admission: Option<ConnectionAdmission>,
    active: AtomicUsize,
    /// The waiters of the lane the connection is filed under. A leaf lock:
    /// releases and pushed changes reach it without the storage lock.
    lane_waiters: Mutex<Option<Arc<WaitQueue>>>,
    /// Checkouts waiting anywhere in the pool: while none waits, releases and
    /// pushed changes skip the waiters.
    waiting: Arc<AtomicUsize>,
    /// Every waiter of the pool: new connections, rekeys, eviction chances.
    notify: Arc<Notify>,
    last_idle: AtomicInstant,
    pool_slot: Mutex<ConnectionSlot>,
    /// Whether the lane's `open` set lists this connection. Only written with
    /// the storage lock held; released handouts read it without the lock to
    /// skip re-listing a connection that is still listed.
    listed: AtomicBool,
    /// Where released handouts re-list this connection. Weak, since storage owns
    /// the connection.
    storage: Weak<Mutex<Storage<C, ID>>>,
    relist_fn: fn(&Arc<Self>),
}

/// A stream reserved on a connection by [`StoredConnection::try_admit`], with
/// the transport credit reserved for it, if the connection has a provider.
struct Admitted(Option<ConnectionAdmissionLease>);

/// Admission and eviction share this lock so a previously captured snapshot
/// cannot acquire a stream after the connection's capacity has been transferred.
struct ConnectionSlot {
    permit: Option<PoolSlot>,
    retired: bool,
}

impl<C, ID> StoredConnection<C, ID> {
    /// A connection is idle when none of its handouts are in flight and no work
    /// they outlived still occupies it.
    fn is_idle(&self) -> bool {
        if self.active.load(Ordering::Relaxed) != 0 {
            return false;
        }
        if self.in_use_unleased() {
            // Such work is activity: the idle clock starts once it ends.
            self.last_idle.set_now();
            return false;
        }
        true
    }

    /// Work outlived its handouts, such as an upgraded tunnel.
    fn in_use_unleased(&self) -> bool {
        self.admission
            .as_ref()
            .is_some_and(ConnectionAdmission::in_use)
    }

    /// Effective per-connection concurrency: the connection's [`MaxConcurrency`]
    /// extension ([`usize::MAX`] if unset), capped by the pool's
    /// `max_concurrent_streams`. Read live on every admission, so it tracks
    /// changes (e.g. h2 SETTINGS updates).
    ///
    /// A value of 0 is valid, e.g. a peer advertising `SETTINGS_MAX_CONCURRENT_STREAMS=0`
    fn effective_capacity(&self, cap: usize) -> usize {
        self.max_concurrency
            .as_ref()
            .map_or(usize::MAX, |m| m.get())
            .min(cap)
    }

    /// Whether a stream slot is free right now, judged live like every admission.
    fn has_capacity(&self, cap: usize) -> bool {
        self.active.load(Ordering::Relaxed) < self.effective_capacity(cap)
    }

    /// Re-list a connection that has spare stream capacity in its lane's
    /// `open` set after a handout was released.
    ///
    /// A connection stays listed while it has room, so a busy multiplexed
    /// connection costs no lock here. It is only unlisted when a checkout took
    /// its last slot, and only exclusive connections pay the lock on every
    /// release. A release racing that unlisting can skip the re-listing; the
    /// connection then rejoins on its next release, or on the next exact
    /// checkout, since `open` is only a hint (see [`Lane`]).
    fn relist(self: &Arc<Self>) {
        if !self.listed.load(Ordering::Relaxed) && self.filed.load(Ordering::Relaxed) {
            (self.relist_fn)(self);
        }
    }

    /// Admit a new in-flight stream (while `active < limit`) and bind it to a
    /// [`MultiplexedConnection`] in one step, so `active` is never incremented
    /// without a handout to release it on drop. Returns `None` at capacity.
    ///
    /// Takes `&Arc<Self>` (not `&self`) since the handout needs to share the
    /// `Arc`; `&Arc<Self>` as a method receiver is still unstable.
    fn try_create_multiplexed(
        self: &Arc<Self>,
        lane_gen: u64,
        cap: usize,
        input: &Extensions,
    ) -> Option<MultiplexedConnection<C, ID>>
    where
        C: ExtensionsRef,
    {
        self.try_admit(lane_gen, cap, input)
            .map(|Admitted(admission)| MultiplexedConnection {
                inner: self.clone(),
                admission,
            })
    }

    /// Reserve one stream, and its transport credit if the connection publishes
    /// a provider, or return `None` without side effects when the connection
    /// cannot take a stream now, or was rekeyed since it was selected under
    /// `lane_gen`.
    ///
    /// The caller must turn a successful result into a handout, since the
    /// stream counter is only released by dropping one.
    fn try_admit(&self, lane_gen: u64, cap: usize, input: &Extensions) -> Option<Admitted>
    where
        C: ExtensionsRef,
    {
        // Resource providers run outside all pool locks. If admission loses a
        // race below, dropping this reservation immediately returns its credit.
        let admission = match &self.admission {
            Some(provider) => match provider.try_acquire(input) {
                Ok(Some(lease)) => Some(lease),
                Ok(None) => return None,
                Err(error) => {
                    // Publish retirement through the existing health signal so
                    // later sweeps need no additional lock on healthy lookups.
                    if let Some(health) =
                        self.conn.extensions().get_ref::<ConnectionHealthWatcher>()
                    {
                        health.mark_broken();
                    } else {
                        let health = ConnectionHealthWatcher::default();
                        health.mark_broken();
                        self.conn.extensions().insert(health);
                    }
                    self.pool_slot.lock().retired = true;
                    trace!(%error, "multiplex pool: resource provider retired connection");
                    return None;
                }
            },
            None => None,
        };
        let slot = self.pool_slot.lock();
        // A close can be reported while the connector's compatibility policy
        // runs outside the storage lock. Do not hand out a known-broken
        // connection merely because its earlier snapshot was healthy.
        let broken = self
            .conn
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .is_some_and(|health| health.health() == ConnectionHealth::Broken);
        let rekeyed = self.lane_gen.load(Ordering::Acquire) != lane_gen;
        if slot.retired || rekeyed || broken || !self.has_capacity(cap) {
            return None;
        }
        // Admission is serialized with retirement. Concurrent lease drops only
        // decrease the count, so no compare/exchange loop is needed here.
        self.active.fetch_add(1, Ordering::Relaxed);
        drop(slot);
        Some(Admitted(admission))
    }
}

impl<C, ID> StoredConnection<C, ID> {
    /// Capacity of the connection was freed: hand its lane's waiters to
    /// `wake` or, if nobody waits there, offer an idle connection to the
    /// pool's waiters for eviction. Skipped while no checkout waits.
    ///
    /// Call after a `SeqCst` fence that follows the change. It pairs with the
    /// fence of [`WaitQueue::push`]: of a waiter queuing and this change, one
    /// sees the other; a waiter leaving meets it under the queue's lock.
    fn freed(&self, wake: fn(&WaitQueue) -> bool) {
        if self.waiting.load(Ordering::Relaxed) == 0 {
            return;
        }
        let waiters = self.lane_waiters.lock().clone();
        // Eviction skips lanes with waiters, so only without is it a chance.
        if !waiters.is_some_and(|waiters| wake(&waiters)) && self.is_idle() {
            self.notify.notify_one();
        }
    }
}

/// A source of the connection changed: its MaxConcurrency, transport credit,
/// health, or work outliving its handouts.
impl<C: Send + Sync + 'static, ID: Send + Sync + 'static> ChangeListener
    for StoredConnection<C, ID>
{
    fn changed(&self, change: Change) {
        fence(Ordering::SeqCst);
        self.freed(match change {
            Change::Freed => WaitQueue::wake_one,
            // How much capacity changed is unknown: every waiter of the lane looks.
            Change::Other => WaitQueue::wake_all,
        });
    }
}

/// [`StoredConnection::relist_fn`]: lock the storage the connection belongs to
/// and list the connection again, if it is still stored and has room.
///
/// Free function since the handout's `Drop` impl cannot carry the `ConnID`
/// bounds that hashing needs; connections capture this at creation.
fn relist_stored<C, ID: ConnID>(conn: &Arc<StoredConnection<C, ID>>) {
    let Some(storage) = conn.storage.upgrade() else {
        return;
    };
    if let Some(bucket) = storage.lock().by_id.get_mut(&conn.id) {
        bucket.list(conn);
    }
}

/// A cheap handle to a shared connection in a [`MultiplexPool`].
///
/// It implements [`Service`] by forwarding to the inner connection and counts as
/// one of the connection's in-flight streams for its lifetime, the stream is
/// released on drop.
pub struct MultiplexedConnection<C, ID> {
    inner: Arc<StoredConnection<C, ID>>,
    admission: Option<ConnectionAdmissionLease>,
}

impl<C, ID> Drop for MultiplexedConnection<C, ID> {
    fn drop(&mut self) {
        // Return unused transport credit before waking pool-capacity waiters.
        self.admission.take();
        if self.inner.active.fetch_sub(1, Ordering::Release) == 1 {
            self.inner.last_idle.set_now();
        }
        // Pairs with the fences of a checkout unlisting a full connection and
        // of a waiter queuing: of either and this release, one sees the other.
        fence(Ordering::SeqCst);
        // Make the spare stream slot visible to checkouts before waking any
        // waiter that will look for it.
        self.inner.relist();
        // One released handout is one unit of capacity: for the first waiter
        // of its lane without a wake, else an eviction chance if now idle.
        // Work outliving the handout is announced by the admission's change.
        self.inner.freed(WaitQueue::wake_one);
    }
}

impl<C: ExtensionsRef, ID: ConnID> MultiplexedConnection<C, ID> {
    /// File the shared connection under new reuse requirements, such as an
    /// identity it authenticated after it was established.
    ///
    /// Also publishes `reuse` on the connection. Pools otherwise keep the
    /// requirements the connection was added with. A connection the pool has
    /// already dropped stays dropped. Checkouts that have not been admitted
    /// yet no longer get a stream under the old requirements; streams already
    /// admitted keep theirs, so rekey while this handout is the only one.
    pub fn rekey(&self, reuse: ConnectionReuse) {
        let conn = &self.inner;
        let lane = LaneKey::of_connection(Some(&reuse)).filter(|_| conn.id.is_reusable());
        conn.conn.extensions().insert(reuse);
        let Some(storage) = conn.storage.upgrade() else {
            return;
        };
        let mut storage = storage.lock();
        // Candidates selected under the old lane can no longer be admitted.
        let retired = {
            let slot = conn.pool_slot.lock();
            conn.lane_gen.fetch_add(1, Ordering::Release);
            slot.retired
        };
        if let Some(bucket) = storage.by_id.get_mut(&conn.id) {
            bucket.remove(conn);
            if bucket.is_empty() {
                storage.by_id.remove(&conn.id);
            }
        }
        let Some(lane) = lane else {
            return;
        };
        if retired {
            return;
        }
        storage
            .by_id
            .entry(conn.id.clone())
            .or_insert_with(|| IdBucket::new(now_monotonic_nanos()))
            .insert(conn, lane);
        drop(storage);
        // Requests of the new lane may be waiting for it.
        conn.notify.notify_waiters();
    }
}

impl<C: ExtensionsRef, ID> ExtensionsRef for MultiplexedConnection<C, ID> {
    fn extensions(&self) -> &Extensions {
        self.inner.conn.extensions()
    }
}

impl<Input, C, ID> Service<Input> for MultiplexedConnection<C, ID>
where
    C: Service<Input> + ExtensionsRef,
    ID: Send + Sync + 'static,
    Input: ExtensionsMut + Send + 'static,
{
    type Output = C::Output;
    type Error = C::Error;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        if let Some(admission) = &self.admission {
            admission.bind(input.extensions_mut());
        }

        self.inner.conn.serve(input).await
    }
}

impl<C, ID> Debug for MultiplexedConnection<C, ID>
where
    ID: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexedConnection")
            .field("id", &self.inner.id)
            .field("active_streams", &self.inner.active.load(Ordering::Relaxed))
            .finish()
    }
}

/// Connections taken out of storage, dropped only after the storage lock is
/// released so their sockets close outside it.
type Doomed<C, ID> = Vec<Arc<StoredConnection<C, ID>>>;

/// Connections of the request's lanes copied out of storage, in creation order,
/// each with the lane generation it was selected under, so selection and
/// waiter registration run without holding the storage lock.
type Snapshot<C, ID> = SmallVec<[(Arc<StoredConnection<C, ID>>, u64); 4]>;

/// The lanes a request can be served from: the lane of its key in each class
/// of its id, then the unrestricted lane.
struct RequestLanes {
    /// The classes the keys were derived with, `None` if the id had none.
    classes: Option<Arc<[ReuseClass]>>,
    /// The key derived with each of `classes`, in order.
    keys: SmallVec<[Option<ReuseKey>; 1]>,
}

impl RequestLanes {
    /// Derive the request's keys from its id's `classes`, outside pool locks.
    fn derive(classes: Option<Arc<[ReuseClass]>>, input: &Extensions) -> Self {
        let keys = classes
            .iter()
            .flat_map(|classes| classes.iter())
            .map(|class| class.request_key(input))
            .collect();
        Self { classes, keys }
    }

    /// Lanes of a request that can only use connections without requirements.
    fn unrestricted() -> Self {
        Self {
            classes: None,
            keys: SmallVec::new(),
        }
    }
}

/// A request's lanes in one bucket, see [`IdBucket::request_lanes_mut`].
type RequestLanesMut<'a, C, ID> = SmallVec<[&'a mut Lane<C, ID>; 2]>;

/// How many `open` candidates one checkout tries before it falls back to the
/// exact path. Refusing candidates are the exception; the exact path handles
/// them (and stays O(connections of the lane)).
const OPEN_CANDIDATES: usize = 4;

/// Upper bound on how long an idle or broken connection can linger unnoticed
/// in a bucket whose checkouts never come across it. Sweeping the bucket at
/// this pace amortizes to nothing.
const MAX_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
const MIN_SWEEP_INTERVAL: Duration = Duration::from_millis(1);

/// Who looks at a bucket's lanes.
enum Look<'a> {
    /// A checkout that does not wait: lanes with waiters are closed to it.
    New,
    /// A waiting checkout, queuing in the lanes it looks at.
    Register(&'a mut Waiting),
    /// A waiting checkout, looking again.
    Waiting(&'a Waiter),
}

impl Look<'_> {
    fn waiter(&self) -> Option<&Waiter> {
        match self {
            Self::New => None,
            Self::Register(waiting) => Some(&waiting.waiter),
            Self::Waiting(waiter) => Some(waiter),
        }
    }
}

/// A waiting checkout's place in the lanes it can be served from, and in the
/// pool's count of waiting checkouts. Dropped when the checkout ends: an
/// unused wake passes on to the next waiter of each lane.
struct Waiting {
    waiter: Arc<Waiter>,
    lanes: SmallVec<[Arc<WaitQueue>; 2]>,
    /// The lane of the connection that served the checkout, if filed.
    served: Option<Arc<WaitQueue>>,
    /// Whether serving it spent a wake.
    spent: bool,
    waiting: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl Waiting {
    fn new(waiting: &Arc<AtomicUsize>, notify: &Arc<Notify>) -> Self {
        waiting.fetch_add(1, Ordering::Relaxed);
        Self {
            waiter: Waiter::new(),
            lanes: SmallVec::new(),
            served: None,
            spent: false,
            waiting: waiting.clone(),
            notify: notify.clone(),
        }
    }

    /// Queue in `lane`, once. Call with the storage lock held, before the
    /// look at the lane's capacity: see [`StoredConnection::freed`].
    fn register(&mut self, lane: &Arc<WaitQueue>) {
        if !self.lanes.iter().any(|known| Arc::ptr_eq(known, lane)) {
            lane.push(&self.waiter);
            self.lanes.push(lane.clone());
        }
    }
}

impl Waiting {
    /// The checkout was served by `conn`, in a look begun at `seen`.
    fn served<C, ID>(&mut self, conn: &StoredConnection<C, ID>, seen: Wakes) {
        self.served = conn.lane_waiters.lock().clone();
        self.spent = seen.held();
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let mut emptied = false;
        for lane in &self.lanes {
            let mut held = lane.remove(&self.waiter);
            if self.spent
                && self
                    .served
                    .as_ref()
                    .is_some_and(|served| Arc::ptr_eq(served, lane))
            {
                held = held.saturating_sub(1);
            }
            // Which lane sent a wake is unknown: each passes on all it may
            // have sent, the capacity they stand for is there for others.
            for _ in 0..held {
                lane.wake_one();
            }
            emptied |= lane.is_empty();
        }
        if self.waiting.fetch_sub(1, Ordering::Relaxed) > 1 && emptied {
            // Idle connections of a lane nobody waits in can be evicted now.
            self.notify.notify_one();
        }
    }
}

/// The connections of one id filed under one [`LaneKey`]: each of them can
/// serve every request of the lane, so selection needs no compatibility check.
///
/// `conns` is every connection in creation order. `open` is an index over it:
/// the connections which have a free stream slot, ordered by creation, so a
/// checkout picks its connection in O(1) instead of looking at every one.
///
/// `open` is a hint, not a copy of the truth. A live capacity change (an h2
/// SETTINGS raise, transport credit returning) is only seen by a checkout that
/// reads the connection, and a release can race an unlisting. So it can hold
/// entries that turn out full, which selection unlists as it meets them, and
/// it can miss a connection with room. A checkout that finds nothing in `open`
/// therefore takes the exact path, which reads every connection and lists the
/// ones the hint missed.
struct Lane<C, ID> {
    conns: Vec<Arc<StoredConnection<C, ID>>>,
    open: BTreeMap<u64, Arc<StoredConnection<C, ID>>>,
    waiters: Arc<WaitQueue>,
}

impl<C, ID> Lane<C, ID> {
    fn new() -> Self {
        Self {
            conns: Vec::new(),
            open: BTreeMap::new(),
            waiters: Arc::default(),
        }
    }

    /// Where `conn` is stored in this lane.
    fn position(&self, conn: &StoredConnection<C, ID>) -> Option<usize> {
        let pos = self.conns.partition_point(|stored| stored.seq < conn.seq);
        self.conns
            .get(pos)
            .is_some_and(|stored| stored.seq == conn.seq)
            .then_some(pos)
    }

    /// Store `conn`, keeping creation order even if concurrent creations
    /// publish out of order, and list it if it can take more than the
    /// establishing stream.
    fn insert(&mut self, conn: &Arc<StoredConnection<C, ID>>) {
        let pos = self.conns.partition_point(|stored| stored.seq < conn.seq);
        self.conns.insert(pos, conn.clone());
        *conn.lane_waiters.lock() = Some(self.waiters.clone());
        self.list(conn);
    }

    /// List `conn` as having room, if it is stored, unlisted and has room.
    fn list(&mut self, conn: &Arc<StoredConnection<C, ID>>) {
        if conn.listed.load(Ordering::Relaxed)
            || !conn.has_capacity(conn.stream_cap)
            || self.position(conn).is_none()
        {
            return;
        }
        conn.listed.store(true, Ordering::Relaxed);
        self.open.insert(conn.seq, conn.clone());
    }

    fn unlist(&mut self, seq: u64) -> Option<Arc<StoredConnection<C, ID>>> {
        let conn = self.open.remove(&seq)?;
        conn.listed.store(false, Ordering::Relaxed);
        Some(conn)
    }

    /// Keep only the connections `keep` accepts.
    fn retain(&mut self, keep: &mut impl FnMut(&Arc<StoredConnection<C, ID>>) -> bool) {
        let Self { conns, open, .. } = self;
        conns.retain(|conn| {
            if keep(conn) {
                return true;
            }
            if open.remove(&conn.seq).is_some() {
                conn.listed.store(false, Ordering::Relaxed);
            }
            *conn.lane.lock() = None;
            *conn.lane_waiters.lock() = None;
            conn.filed.store(false, Ordering::Relaxed);
            false
        });
    }

    /// Remove the connection at `pos` from the lane, and from `open`.
    /// The caller takes the connection's lane.
    fn remove_at(&mut self, pos: usize) -> Arc<StoredConnection<C, ID>> {
        let conn = self.conns.remove(pos);
        self.unlist(conn.seq);
        *conn.lane_waiters.lock() = None;
        conn.filed.store(false, Ordering::Relaxed);
        conn
    }

    /// The listed connection the selection strategy prefers, skipping
    /// `skip`; round robin continues after `rr_after`. Entries without room
    /// are unlisted on the way.
    fn pick(
        &mut self,
        selection: MuxSelection,
        cap: usize,
        skip: &[u64],
        rr_after: Option<u64>,
    ) -> Option<Pick> {
        let mut full: SmallVec<[u64; 2]> = SmallVec::new();
        let usable =
            |seq: u64, conn: &Arc<StoredConnection<C, ID>>, full: &mut SmallVec<[u64; 2]>| {
                if skip.contains(&seq) {
                    return false;
                }
                if conn.has_capacity(cap) {
                    return true;
                }
                full.push(seq);
                false
            };
        let pick = |(seq, conn): (&u64, &Arc<StoredConnection<C, ID>>), wrapped| Pick {
            seq: *seq,
            active: conn.active.load(Ordering::Relaxed),
            wrapped,
        };
        let chosen = match selection {
            MuxSelection::FirstAvailable => self
                .open
                .iter()
                .find(|(seq, conn)| usable(**seq, conn, &mut full))
                .map(|entry| pick(entry, false)),
            MuxSelection::LeastLoaded => {
                // Ties go to the earliest connection. A connection with no
                // streams cannot be beaten, which ends the scan at once for
                // exclusive connections however many are listed.
                let mut best: Option<Pick> = None;
                for entry in &self.open {
                    if !usable(*entry.0, entry.1, &mut full) {
                        continue;
                    }
                    let candidate = pick(entry, false);
                    if best.is_none_or(|best| candidate.active < best.active) {
                        best = Some(candidate);
                        if candidate.active == 0 {
                            break;
                        }
                    }
                }
                best
            }
            MuxSelection::RoundRobin => {
                // Continue after the connection chosen last, then wrap around.
                let start = rr_after.map_or(0, |seq| seq.saturating_add(1));
                self.open
                    .range(start..)
                    .find(|(seq, conn)| usable(**seq, conn, &mut full))
                    .map(|entry| pick(entry, false))
                    .or_else(|| {
                        self.open
                            .range(..start)
                            .find(|(seq, conn)| usable(**seq, conn, &mut full))
                            .map(|entry| pick(entry, true))
                    })
            }
        };
        if !full.is_empty() {
            let unlisted: SmallVec<[_; 2]> = full
                .into_iter()
                .filter_map(|seq| self.unlist(seq))
                .collect();
            // Pairs with the fence of a release: of it and this unlisting, one
            // sees the other, so room freed meanwhile stays listed.
            fence(Ordering::SeqCst);
            for conn in &unlisted {
                self.list(conn);
            }
        }
        chosen
    }

    /// Claim the picked connection `seq` for one checkout.
    ///
    /// A connection this checkout is about to fill is unlisted, which makes
    /// the claim exclusive, so concurrent checkouts spread over distinct
    /// exclusive connections instead of racing for one; the release relists
    /// it. Any other connection stays listed for concurrent users.
    fn take(&mut self, seq: u64, cap: usize) -> Option<Arc<StoredConnection<C, ID>>> {
        let conn = self.open.get(&seq)?;
        // Read after the pick, this checkout's own stream not counted yet.
        if conn.active.load(Ordering::Relaxed) + 1 >= conn.effective_capacity(cap) {
            self.unlist(seq)
        } else {
            Some(conn.clone())
        }
    }
}

/// A connection claimed for one checkout, with the lane generation it was
/// claimed under: admission refuses it once it was rekeyed since.
struct Claimed<C, ID> {
    conn: Arc<StoredConnection<C, ID>>,
    lane_gen: u64,
}

impl<C, ID> Claimed<C, ID> {
    /// Read under the storage lock that found `conn` in its lane.
    fn new(conn: Arc<StoredConnection<C, ID>>) -> Self {
        let lane_gen = conn.lane_gen.load(Ordering::Acquire);
        Self { conn, lane_gen }
    }
}

/// A lane's preferred connection, compared across the request's lanes.
#[derive(Clone, Copy)]
struct Pick {
    seq: u64,
    active: usize,
    /// Round robin found it only after wrapping around.
    wrapped: bool,
}

impl Pick {
    /// Whether the strategy prefers this pick over `other`, as if both lanes
    /// were one index in creation order.
    fn beats(self, other: Self, selection: MuxSelection) -> bool {
        match selection {
            MuxSelection::FirstAvailable => self.seq < other.seq,
            MuxSelection::LeastLoaded => (self.active, self.seq) < (other.active, other.seq),
            MuxSelection::RoundRobin => (self.wrapped, self.seq) < (other.wrapped, other.seq),
        }
    }
}

/// All connections of one id, filed by lane.
///
/// A checkout derives its key in each of the bucket's classes, the distinct
/// reuse classifiers among its connections, so its cost does not grow with
/// the number of lanes or connections.
struct IdBucket<C, ID> {
    /// Connections without requirements: any request of the id may use them.
    unrestricted: Lane<C, ID>,
    /// Connections with requirements, per classifier, by key.
    keyed: Vec<ClassLanes<C, ID>>,
    /// The classes of `keyed`, in its order. Replaced, never mutated, so a
    /// checkout copies it out of the lock with one reference count.
    classes: Arc<[ReuseClass]>,
    /// The `seq` last chosen by [`MuxSelection::RoundRobin`], across lanes.
    rr_after: Option<u64>,
    /// Nanoseconds (see [`now_monotonic_nanos`]) when the next full sweep is due.
    next_sweep: u64,
}

/// The lanes of one classifier.
struct ClassLanes<C, ID> {
    classifier: ReuseKey,
    lanes: HashMap<ReuseKey, Lane<C, ID>>,
}

/// The lane a bucket has, when it has exactly one.
enum OnlyLane {
    Unrestricted,
    Keyed(ReuseKey),
}

impl<C, ID> IdBucket<C, ID> {
    fn new(next_sweep: u64) -> Self {
        Self {
            unrestricted: Lane::new(),
            keyed: Vec::new(),
            classes: Arc::new([]),
            rr_after: None,
            next_sweep,
        }
    }

    fn is_empty(&self) -> bool {
        self.unrestricted.conns.is_empty() && self.keyed.is_empty()
    }

    fn lanes(&self) -> impl Iterator<Item = &Lane<C, ID>> {
        std::iter::once(&self.unrestricted)
            .chain(self.keyed.iter().flat_map(|class| class.lanes.values()))
    }

    #[cfg(test)]
    fn conns(&self) -> impl Iterator<Item = &Arc<StoredConnection<C, ID>>> {
        self.lanes().flat_map(|lane| &lane.conns)
    }

    /// The classes, `None` when the bucket has unrestricted connections only.
    fn classes(&self) -> Option<Arc<[ReuseClass]>> {
        (!self.classes.is_empty()).then(|| self.classes.clone())
    }

    /// Claim a connection of the bucket's lane for one checkout, if the bucket
    /// has exactly one lane: a request's lanes can only contain that one.
    fn claim_only(
        &mut self,
        selection: MuxSelection,
        cap: usize,
        waiter: Option<&Waiter>,
    ) -> Option<(OnlyLane, Option<Claimed<C, ID>>)> {
        let Self {
            unrestricted,
            keyed,
            rr_after,
            ..
        } = self;
        let (only, lane) = match keyed.as_mut_slice() {
            [] if !unrestricted.conns.is_empty() => (OnlyLane::Unrestricted, unrestricted),
            [class] if unrestricted.conns.is_empty() && class.lanes.len() == 1 => {
                let (key, lane) = class.lanes.iter_mut().next()?;
                (OnlyLane::Keyed(key.clone()), lane)
            }
            _ => return None,
        };
        let admitted = lane.waiters.admits(waiter);
        let claimed = admitted
            .then(|| lane.pick(selection, cap, &[], *rr_after))
            .flatten()
            .and_then(|pick| {
                if matches!(selection, MuxSelection::RoundRobin) {
                    *rr_after = Some(pick.seq);
                }
                lane.take(pick.seq, cap)
            })
            .map(Claimed::new);
        Some((only, claimed))
    }

    /// Claim the connection the selection strategy prefers across all of the
    /// request's lanes, as if they were one index in creation order.
    fn claim(
        &mut self,
        request: &RequestLanes,
        selection: MuxSelection,
        cap: usize,
        skip: &[u64],
        waiter: Option<&Waiter>,
    ) -> Option<Claimed<C, ID>> {
        let rr_after = self.rr_after;
        let mut lanes = self.request_lanes_mut(request);
        let mut best: Option<(usize, Pick)> = None;
        for (index, lane) in lanes.iter_mut().enumerate() {
            if !lane.waiters.admits(waiter) {
                continue;
            }
            let Some(pick) = lane.pick(selection, cap, skip, rr_after) else {
                continue;
            };
            if best.is_none_or(|(_, best)| pick.beats(best, selection)) {
                best = Some((index, pick));
            }
        }
        let (index, pick) = best?;
        let claimed = lanes[index].take(pick.seq, cap).map(Claimed::new);
        drop(lanes);
        if matches!(selection, MuxSelection::RoundRobin) {
            self.rr_after = Some(pick.seq);
        }
        claimed
    }

    fn class_mut(&mut self, classifier: &ReuseKey) -> Option<&mut ClassLanes<C, ID>> {
        self.keyed
            .iter_mut()
            .find(|class| &class.classifier == classifier)
    }

    fn lane_mut(&mut self, lane: &LaneKey) -> Option<&mut Lane<C, ID>> {
        match lane {
            LaneKey::Unrestricted => Some(&mut self.unrestricted),
            LaneKey::Keyed(keyed) => self
                .class_mut(keyed.class.classifier())?
                .lanes
                .get_mut(&keyed.key),
        }
    }

    /// The request's lanes the bucket has connections in: the lane of its key
    /// in each class, then the unrestricted lane. A request has one key per
    /// class, so these are distinct lanes, each looked up once.
    fn request_lanes_mut<'a>(&'a mut self, request: &RequestLanes) -> RequestLanesMut<'a, C, ID> {
        // Keys derived from this very snapshot sit at the same index.
        let aligned = request
            .classes
            .as_ref()
            .is_some_and(|classes| Arc::ptr_eq(classes, &self.classes));
        let classes = request.classes.as_deref().unwrap_or_default();
        let mut lanes = RequestLanesMut::new();
        for (index, class) in self.keyed.iter_mut().enumerate() {
            let derived = if aligned {
                Some(index)
            } else {
                classes
                    .iter()
                    .position(|derived| derived.classifier() == &class.classifier)
            };
            if let Some(key) = derived
                .and_then(|derived| request.keys.get(derived))
                .and_then(Option::as_ref)
                && let Some(lane) = class.lanes.get_mut(key)
            {
                lanes.push(lane);
            }
        }
        if !self.unrestricted.conns.is_empty() {
            lanes.push(&mut self.unrestricted);
        }
        lanes
    }

    /// Store `conn` in `lane`.
    fn insert(&mut self, conn: &Arc<StoredConnection<C, ID>>, lane: LaneKey) {
        *conn.lane.lock() = Some(lane.clone());
        conn.filed.store(true, Ordering::Relaxed);
        let LaneKey::Keyed(keyed) = lane else {
            self.unrestricted.insert(conn);
            return;
        };
        let KeyedLane { class, key } = *keyed;
        let known = self
            .keyed
            .iter()
            .position(|known| &known.classifier == class.classifier());
        let index = known.unwrap_or_else(|| {
            self.keyed.push(ClassLanes {
                classifier: class.classifier().clone(),
                lanes: HashMap::new(),
            });
            self.classes = self.classes.iter().cloned().chain([class]).collect();
            self.keyed.len() - 1
        });
        self.keyed[index]
            .lanes
            .entry(key)
            .or_insert_with(Lane::new)
            .insert(conn);
    }

    /// List `conn` in its lane as having room, if it is stored and has room.
    fn list(&mut self, conn: &Arc<StoredConnection<C, ID>>) {
        let lane = conn.lane.lock();
        if let Some(stored) = lane.as_ref().and_then(|lane| self.lane_mut(lane)) {
            stored.list(conn);
        }
    }

    /// Take `conn` out of the bucket, if it is stored in it.
    fn remove(&mut self, conn: &StoredConnection<C, ID>) -> Option<Arc<StoredConnection<C, ID>>> {
        let mut filed = conn.lane.lock();
        let lane = filed.as_ref()?;
        let stored = self.lane_mut(lane)?;
        let removed = stored.remove_at(stored.position(conn)?);
        if let Some(LaneKey::Keyed(keyed)) = filed.take() {
            drop(filed);
            self.drop_lane_if_empty(keyed.class.classifier(), &keyed.key);
        }
        Some(removed)
    }

    fn drop_lane_if_empty(&mut self, classifier: &ReuseKey, key: &ReuseKey) {
        let Some(index) = self
            .keyed
            .iter()
            .position(|class| &class.classifier == classifier)
        else {
            return;
        };
        let lanes = &mut self.keyed[index].lanes;
        if lanes.get(key).is_some_and(|lane| lane.conns.is_empty()) {
            lanes.remove(key);
        }
        if lanes.is_empty() {
            self.remove_class(index);
        }
    }

    fn remove_class(&mut self, index: usize) {
        self.keyed.remove(index);
        self.classes = self
            .classes
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .map(|(_, class)| class.clone())
            .collect();
    }

    /// Keep only the connections `keep` accepts, dropping emptied lanes.
    fn retain(&mut self, mut keep: impl FnMut(&Arc<StoredConnection<C, ID>>) -> bool) {
        self.unrestricted.retain(&mut keep);
        let mut index = 0;
        while index < self.keyed.len() {
            let lanes = &mut self.keyed[index].lanes;
            lanes.retain(|_, lane| {
                lane.retain(&mut keep);
                !lane.conns.is_empty()
            });
            if lanes.is_empty() {
                self.remove_class(index);
            } else {
                index += 1;
            }
        }
    }

    /// The bucket's only lane, for tests of single-lane buckets.
    #[cfg(test)]
    fn only_lane(&self) -> &Lane<C, ID> {
        let mut lanes = self.lanes().filter(|lane| !lane.conns.is_empty());
        let lane = lanes.next().expect("a lane");
        assert!(lanes.next().is_none(), "expected a single lane");
        lane
    }
}

/// Connections grouped by id, so a handout only touches its own bucket and
/// the lock is never held for a scan of the whole pool.
struct Storage<C, ID> {
    by_id: HashMap<ID, IdBucket<C, ID>>,
}

/// Connection pool that multiplexes concurrent users over shared
/// connections.
pub struct MultiplexPool<C, ID> {
    storage: Arc<Mutex<Storage<C, ID>>>,
    total_slots: Arc<Semaphore>,
    idle_timeout: Option<Duration>,
    max_concurrent_streams: usize,
    selection: MuxSelection,
    rr_cursor: Arc<AtomicUsize>,
    next_seq: Arc<AtomicU64>,
    /// See [`StoredConnection::notify`].
    notify: Arc<Notify>,
    /// Checkouts waiting for capacity, see [`StoredConnection::waiting`].
    waiting: Arc<AtomicUsize>,
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
            total_slots: self.total_slots.clone(),
            idle_timeout: self.idle_timeout,
            max_concurrent_streams: self.max_concurrent_streams,
            selection: self.selection,
            rr_cursor: self.rr_cursor.clone(),
            next_seq: self.next_seq.clone(),
            notify: self.notify.clone(),
            waiting: self.waiting.clone(),
            #[cfg(feature = "opentelemetry")]
            metrics: self.metrics.clone(),
        }
    }
}

impl<C, ID> MultiplexPool<C, ID> {
    /// Create a new [`MultiplexPool`] from validated, non-zero limits.
    #[must_use]
    pub fn new(max_concurrent_streams: NonZeroUsize, max_total: NonZeroUsize) -> Self {
        Self {
            storage: Arc::new(Mutex::new(Storage {
                by_id: HashMap::new(),
            })),
            total_slots: Arc::new(Semaphore::new(max_total.get())),
            idle_timeout: None,
            max_concurrent_streams: max_concurrent_streams.get(),
            selection: MuxSelection::default(),
            rr_cursor: Arc::new(AtomicUsize::new(0)),
            next_seq: Arc::new(AtomicU64::new(0)),
            notify: Arc::new(Notify::new()),
            waiting: Arc::new(AtomicUsize::new(0)),
            #[cfg(feature = "opentelemetry")]
            metrics: None,
        }
    }

    /// Create a new [`MultiplexPool`].
    ///
    /// - `max_concurrent_streams`: upper bound on the concurrent users a single
    ///   connection serves. The actual per-connection concurrency is the minimum of
    ///   this and the connection's [`MaxConcurrency`] extension ([`usize::MAX`] if unset), so
    ///   use [`usize::MAX`] to defer entirely to what each connection advertises.
    /// - `max_total`: max number of connections (across all ids).
    pub fn try_new(max_concurrent_streams: usize, max_total: usize) -> Result<Self, BoxError> {
        let (Some(max_concurrent_streams), Some(max_total)) = (
            NonZeroUsize::new(max_concurrent_streams),
            NonZeroUsize::new(max_total),
        ) else {
            return Err(BoxError::from_static_str(
                "max_concurrent_streams and max_total must be greater than 0",
            )
            .context_field("max_concurrent_streams", max_concurrent_streams)
            .context_field("max_total", max_total));
        };
        Ok(Self::new(max_concurrent_streams, max_total))
    }

    generate_set_and_with! {
        /// Drop connections that have been idle (no active streams) for longer than
        /// the given timeout. Only checked when a connection is requested: the
        /// connection a checkout is about to hand out is always checked, and the
        /// id's other connections are swept at least about once a second.
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
    /// Whether a stored connection may still be handed out: not idle past the
    /// idle timeout and not marked broken (in-flight streams keep a broken
    /// connection alive via the outstanding handles, but it is no longer
    /// handed out).
    fn is_eligible(&self, conn: &StoredConnection<C, ID>) -> bool {
        // Idle first: seeing work that outlived its handouts restarts the idle clock.
        if let Some(idle_timeout) = self.idle_timeout
            && conn.is_idle()
            && conn.last_idle.elapsed() >= idle_timeout
        {
            trace!(id = ?conn.id, "multiplex pool: dropping idle connection");
            return false;
        }
        let broken = conn
            .conn
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .is_some_and(|watcher| watcher.health() == ConnectionHealth::Broken);
        if broken {
            trace!(id = ?conn.id, "multiplex pool: dropping broken connection");
        }
        !broken
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

    /// Move ineligible connections out of `bucket` into `doomed`, so their
    /// sockets close once the caller has released the storage lock.
    fn sweep_bucket(&self, bucket: &mut IdBucket<C, ID>, doomed: &mut Doomed<C, ID>) {
        bucket.next_sweep = self.next_sweep_after(now_monotonic_nanos());
        bucket.retain(|conn| {
            if self.is_eligible(conn) {
                return true;
            }
            conn.pool_slot.lock().retired = true;
            doomed.push(conn.clone());
            false
        });
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
        doomed: &mut Doomed<C, ID>,
        mut look: Look<'_>,
    ) -> Snapshot<C, ID> {
        let Some(bucket) = storage.by_id.get_mut(id) else {
            return Snapshot::new();
        };
        self.sweep_bucket(bucket, doomed);
        if bucket.is_empty() {
            storage.by_id.remove(id);
            return Snapshot::new();
        }
        let mut snapshot = Snapshot::new();
        let mut lanes_seen = 0;
        for lane in bucket.request_lanes_mut(lanes) {
            if let Look::Register(waiting) = &mut look {
                waiting.register(&lane.waiters);
            }
            if !lane.waiters.admits(look.waiter()) {
                continue;
            }
            lanes_seen += usize::from(!lane.conns.is_empty());
            snapshot.extend(lane.conns.iter().map(|conn| {
                let Claimed { conn, lane_gen } = Claimed::new(conn.clone());
                (conn, lane_gen)
            }));
        }
        // Selection treats the lanes as one index in creation order.
        if lanes_seen > 1 {
            snapshot.sort_unstable_by_key(|(conn, _)| conn.seq);
        }
        snapshot
    }

    /// Sweep every bucket. Slow path only: it frees pool slots held by stale
    /// connections of other ids before falling back to LRU eviction.
    fn sweep_all(&self, storage: &mut Storage<C, ID>, doomed: &mut Doomed<C, ID>) {
        storage.by_id.retain(|_, bucket| {
            self.sweep_bucket(bucket, doomed);
            !bucket.is_empty()
        });
    }

    /// Remove the least-recently-used idle connection (any id), returning it
    /// together with its pool slot so the caller can reuse the slot and drop
    /// the connection outside the lock.
    fn evict_lru_idle(
        storage: &mut Storage<C, ID>,
    ) -> Option<(Arc<StoredConnection<C, ID>>, Option<PoolSlot>)> {
        let (conn, slot) = {
            let mut candidate = None;
            let mut oldest = u64::MAX;
            // Plain loops: this scans every stored connection.
            for lane in storage.by_id.values().flat_map(IdBucket::lanes) {
                if !lane.waiters.is_empty() {
                    // Spoken for: the lane's waiters take its idle connections.
                    continue;
                }
                for conn in &lane.conns {
                    let last_idle = conn.last_idle.as_nanos();
                    if last_idle >= oldest || !conn.is_idle() {
                        continue;
                    }
                    let slot = conn.pool_slot.lock();
                    if slot.retired || !conn.is_idle() {
                        continue;
                    }
                    // Keep the best candidate idle until its slot is transferred.
                    // Admission takes this same lock; no retry loop is needed.
                    oldest = last_idle;
                    candidate = Some((conn, slot));
                }
            }
            let (conn, mut slot) = candidate?;
            slot.retired = true;
            (conn.clone(), slot.permit.take())
        };
        let bucket = storage.by_id.get_mut(&conn.id)?;
        let evicted = bucket.remove(&conn)?;
        if bucket.is_empty() {
            storage.by_id.remove(&conn.id);
        }
        Some((evicted, slot))
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
        waiter: Option<&Waiter>,
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
        let mut doomed = Doomed::new();
        let mut handout = None;

        let now = now_monotonic_nanos();
        let (only_lane, mut next, mut classes) = {
            let mut storage = self.storage.lock();
            let Some(bucket) = storage.by_id.get_mut(id) else {
                return Err(Box::new(RequestLanes::unrestricted()));
            };
            if now >= bucket.next_sweep {
                self.sweep_bucket(bucket, &mut doomed);
            }
            let classes = bucket.classes();
            match bucket.claim_only(self.selection, cap, waiter) {
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
                    let Some(claimed) = bucket.claim(lanes, self.selection, cap, &skip, waiter)
                    else {
                        break;
                    };
                    claimed
                }
            };
            exhausted = false;
            skip.push(conn.seq);
            if !self.is_eligible(&conn) {
                retired.push(conn);
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

        if !rejected.is_empty() || !retired.is_empty() || !doomed.is_empty() {
            {
                let mut storage = self.storage.lock();
                let mut empty = false;
                if let Some(bucket) = storage.by_id.get_mut(id) {
                    for conn in &retired {
                        if let Some(removed) = bucket.remove(conn) {
                            removed.pool_slot.lock().retired = true;
                            doomed.push(removed);
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
            drop((retired, rejected, doomed));
        }
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
        look: Look<'_>,
    ) -> (Snapshot<C, ID>, bool) {
        if !id.is_reusable() {
            return (Snapshot::new(), false);
        }
        let mut doomed = Doomed::new();
        let mut storage = self.storage.lock();
        let Some(bucket) = storage.by_id.get_mut(id) else {
            return (Snapshot::new(), false);
        };
        if matches!(look, Look::New) {
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
        let snapshot = self.snapshot(&mut storage, id, lanes, &mut doomed, look);
        drop(storage);
        drop(doomed);
        (snapshot, false)
    }

    /// Turn a fairly acquired total-slot permit into a handout. Reuse a
    /// connection of the request's lanes if capacity became available while
    /// waiting; otherwise return the permit for creating a connection.
    fn admit_with_permit(
        &self,
        id: &ID,
        permit: OwnedSemaphorePermit,
        input: &Extensions,
        waiter: &Waiter,
    ) -> ConnectionResult<MultiplexedConnection<C, ID>, PoolSlot> {
        let lanes = self.request_lanes(id, input);
        let mut doomed = Vec::new();
        let same_lane = if id.is_reusable() {
            self.snapshot(
                &mut self.storage.lock(),
                id,
                &lanes,
                &mut doomed,
                Look::Waiting(waiter),
            )
        } else {
            Snapshot::new()
        };
        drop(doomed);
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
        ConnectionResult::CreatePermit(PoolSlot(permit))
    }
}

impl<C, ID> Pool<C, ID> for MultiplexPool<C, ID>
where
    C: Send + Sync + ExtensionsRef + 'static,
    ID: ConnID,
{
    type Connection = MultiplexedConnection<C, ID>;
    type CreatePermit = PoolSlot;

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

        // One look for a connection with room or a pool slot. A waiting
        // checkout queues in the lanes it looks at before it looks.
        let attempt = |look: Look<'_>| -> Option<ConnectionResult<_, _>> {
            // Common case: an idle or shareable connection is listed in one of
            // the request's lanes.
            let lanes = match self.checkout_open(id, input, look.waiter()) {
                Ok(conn) => return Some(reused(conn)),
                Err(lanes) => *lanes,
            };

            // Only this id's bucket is touched under the lock; swept
            // connections close after it is released.
            let mut doomed = Vec::new();
            let (same_id, saturated_bucket) = self.snapshot_exact(id, &lanes, look);

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
                return Some(reused(conn));
            }

            let saturation = !same_id.is_empty() || saturated_bucket;

            // Claim a fresh connection slot, evicting the least-recently-used idle
            // connection (any id) if the pool is at its total capacity.
            let pool_slot = if let Ok(permit) = self.total_slots.clone().try_acquire_owned() {
                Some(PoolSlot(permit))
            } else {
                // Stale connections of other ids may hold slots: sweep them
                // out, then let their permits flow back through the semaphore
                // (to the oldest queued waiter, if any) before evicting.
                self.sweep_all(&mut self.storage.lock(), &mut doomed);
                doomed.clear();
                if let Ok(permit) = self.total_slots.clone().try_acquire_owned() {
                    Some(PoolSlot(permit))
                } else {
                    let evicted = Self::evict_lru_idle(&mut self.storage.lock());
                    match evicted {
                        Some((evicted, slot)) => {
                            drop(evicted);
                            #[cfg(feature = "opentelemetry")]
                            if let Some((metrics, attrs)) = &metrics {
                                metrics.evicted_connections.add(1, attrs);
                            }
                            // Transfer the evicted idle connection's permit without
                            // releasing it to the semaphore queue. This lets the
                            // evictor make progress without stealing a permit that
                            // was released for the oldest queued waiter.
                            slot
                        }
                        None => None,
                    }
                }
            };

            let pool_slot = pool_slot?;
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
            Some(ConnectionResult::CreatePermit(pool_slot))
        };

        // Fast path: a look without waiting.
        if let Some(result) = attempt(Look::New) {
            return Ok(result);
        }

        // Saturated: queue in the request's lanes, FIFO, and look again on
        // every wake. Keep one semaphore acquisition alive across them:
        // recreating it would requeue this checkout at the back of the
        // semaphore's FIFO admission, where a busy connection could starve it.
        let mut waiting = Waiting::new(&self.waiting, &self.notify);
        let waiter = waiting.waiter.clone();
        let mut total_slot_wait = Box::pin(self.total_slots.clone().acquire_owned());
        let mut look = Look::Register(&mut waiting);
        loop {
            // Enabled before the look, so no wake between both is lost.
            let mut notified = std::pin::pin!(self.notify.notified());
            notified.as_mut().enable();
            let seen = waiter.wakes();
            if let Some(result) = attempt(look) {
                if let ConnectionResult::Connection(conn) = &result {
                    waiting.served(&conn.inner, seen);
                }
                // A create permit leaves the capacity a wake stood for unused:
                // dropping `waiting` passes the wake on.
                return Ok(result);
            }
            // Nothing for the wakes this look answered: wait for the next one,
            // keeping the place.
            waiter.spend(seen);
            look = Look::Register(&mut waiting);

            trace!(?id, "multiplex pool: saturated, waiting for capacity");
            tokio::select! {
                _ = notified => {}
                () = waiter.woken(seen) => {}
                permit = &mut total_slot_wait => {
                    let Ok(permit) = permit else {
                        // the pool never closes its semaphore; treat as spurious
                        continue;
                    };
                    let seen = waiter.wakes();
                    let result = self.admit_with_permit(id, permit, input, &waiter);
                    match &result {
                        ConnectionResult::Connection(conn) => {
                            waiting.served(&conn.inner, seen);
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
        pool_slot: PoolSlot,
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
        let conn = Arc::new(StoredConnection {
            max_concurrency: conn.extensions().get_arc::<MaxConcurrency>(),
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
            active: AtomicUsize::new(1),
            lane_waiters: Mutex::new(None),
            waiting: self.waiting.clone(),
            notify: self.notify.clone(),
            last_idle: AtomicInstant::now(),
            pool_slot: Mutex::new(ConnectionSlot {
                permit: Some(pool_slot),
                retired: false,
            }),
            listed: AtomicBool::new(false),
            storage: Arc::downgrade(&self.storage),
            relist_fn: relist_stored,
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

/// Select a connection from `same_id` (all sharing `id`) that still has capacity
/// and admit a stream on it (see [`StoredConnection::try_create_multiplexed`]),
/// returning a ready handout. Admission locks only the chosen connection's slot.
fn select_and_admit<C: ExtensionsRef, ID: PartialEq + Debug>(
    same_id: &[(Arc<StoredConnection<C, ID>>, u64)],
    id: &ID,
    selection: MuxSelection,
    rr_cursor: &AtomicUsize,
    cap: usize,
    input: &Extensions,
) -> Option<MultiplexedConnection<C, ID>> {
    debug_assert!(same_id.iter().all(|(conn, _)| &conn.id == id), "{id:?}");
    let has_capacity = |(conn, _): &(Arc<StoredConnection<C, ID>>, u64)| {
        conn.active.load(Ordering::Relaxed) < conn.effective_capacity(cap)
    };
    let preferred = match selection {
        MuxSelection::FirstAvailable => None,
        MuxSelection::LeastLoaded => same_id
            .iter()
            .enumerate()
            .filter(|(_, entry)| has_capacity(entry))
            .min_by_key(|(_, (conn, _))| conn.active.load(Ordering::Relaxed))
            .map(|(index, _)| index),
        MuxSelection::RoundRobin => {
            let count = same_id.iter().filter(|entry| has_capacity(entry)).count();
            if count == 0 {
                return None;
            }
            let position = rr_cursor.fetch_add(1, Ordering::Relaxed) % count;
            same_id
                .iter()
                .enumerate()
                .filter(|(_, entry)| has_capacity(entry))
                .nth(position)
                .map(|(index, _)| index)
        }
    };
    // Try the preferred candidate once, then the others without allocating an
    // ordering buffer. A resource reservation is never taken for a full slot.
    for index in preferred
        .into_iter()
        .chain((0..same_id.len()).filter(|index| Some(*index) != preferred))
    {
        let entry = &same_id[index];
        if has_capacity(entry)
            && let Some(handout) = entry.0.try_create_multiplexed(entry.1, cap, input)
        {
            return Some(handout);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::pool::{
        ConnectionAdmissionPolicy, ConnectionReusePolicy, LruDropPool, PooledConnector,
    };
    use crate::client::{
        ConnectionError, ConnectionErrorDomain, ConnectionErrorKind, ConnectorService,
        EstablishedClientConnection,
    };
    use rama_core::{ServiceInput, service::service_fn};
    use rama_utils::reactive::ChangeSignal;
    use std::assert_matches;
    use std::{
        convert::Infallible,
        pin::Pin,
        sync::{LazyLock, Weak, atomic::AtomicBool},
        task::Poll,
    };

    static EMPTY_INPUT: LazyLock<Extensions> = LazyLock::new(Extensions::new);

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct TestId(u32);
    impl ConnID for TestId {
        fn is_reusable(&self) -> bool {
            self.0 != u32::MAX
        }
    }

    #[derive(Debug)]
    struct Conn {
        serial: usize,
        extensions: Extensions,
    }

    impl ExtensionsRef for Conn {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl Service<ServiceInput<()>> for Conn {
        type Output = usize;
        type Error = Infallible;

        async fn serve(&self, _: ServiceInput<()>) -> Result<Self::Output, Self::Error> {
            Ok(self.serial)
        }
    }

    impl Service<Extensions> for Conn {
        type Output = Extensions;
        type Error = Infallible;

        async fn serve(&self, input: Extensions) -> Result<Self::Output, Self::Error> {
            Ok(input)
        }
    }

    #[derive(Debug)]
    struct AdmissionState {
        limit: AtomicUsize,
        reserved: AtomicUsize,
        failed: AtomicBool,
        in_use: AtomicBool,
        changed: ChangeSignal,
        storage: Weak<Mutex<Storage<Conn, TestId>>>,
    }

    impl AdmissionState {
        fn set_limit(&self, limit: usize) {
            self.limit.store(limit, Ordering::SeqCst);
            self.changed.notify(Change::Other);
        }

        fn set_in_use(&self, in_use: bool) {
            self.in_use.store(in_use, Ordering::SeqCst);
            self.changed.notify(Change::Other);
        }
    }

    #[derive(Debug)]
    struct FakeAdmission(Arc<AdmissionState>);

    #[derive(Debug)]
    struct Reservation(Arc<AdmissionState>);

    impl Drop for Reservation {
        fn drop(&mut self) {
            self.0.reserved.fetch_sub(1, Ordering::SeqCst);
            self.0.changed.notify(Change::Freed);
        }
    }

    #[derive(Debug, Extension)]
    struct ReservationToken(Weak<Reservation>);

    impl ConnectionAdmissionPolicy for FakeAdmission {
        fn try_acquire(
            &self,
            _input: &Extensions,
        ) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
            if let Some(storage) = self.0.storage.upgrade() {
                assert!(
                    storage.try_lock().is_some(),
                    "resource provider called under storage lock"
                );
            }
            if self.0.failed.load(Ordering::SeqCst) {
                return Err(BoxError::from_static_str("admission failed"));
            }
            if self
                .0
                .reserved
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |reserved| {
                    (reserved < self.0.limit.load(Ordering::SeqCst)).then_some(reserved + 1)
                })
                .is_err()
            {
                return Ok(None);
            }
            let reservation = Arc::new(Reservation(self.0.clone()));
            let binding = ReservationToken(Arc::downgrade(&reservation));
            Ok(Some(ConnectionAdmissionLease::new(reservation, binding)))
        }

        fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
            self.0.changed.subscribe(listener);
        }

        fn in_use(&self) -> bool {
            self.0.in_use.load(Ordering::SeqCst)
        }
    }

    fn admission_connection(
        pool: &MultiplexPool<Conn, TestId>,
        limit: usize,
    ) -> (Conn, Arc<AdmissionState>) {
        let state = Arc::new(AdmissionState {
            limit: AtomicUsize::new(limit),
            reserved: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            in_use: AtomicBool::new(false),
            changed: ChangeSignal::new(),
            storage: Arc::downgrade(&pool.storage),
        });
        let conn = Conn {
            serial: 1,
            extensions: Extensions::new(),
        };
        conn.extensions
            .insert(ConnectionAdmission::new(FakeAdmission(state.clone())));
        (conn, state)
    }

    async fn new_slot(pool: &MultiplexPool<Conn, TestId>) -> PoolSlot {
        match pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap() {
            ConnectionResult::CreatePermit(permit) => permit,
            ConnectionResult::Connection(_) => panic!("expected an empty pool"),
        }
    }

    #[tokio::test]
    async fn a_freed_unit_wakes_one_waiter_and_other_changes_all() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 1);
        let held = pool
            .create(TestId(0), conn, permit, &EMPTY_INPUT)
            .await
            .unwrap();
        let mut waiters = [(); 3].map(|()| queue(&pool, &EMPTY_INPUT));
        state.changed.notify(Change::Freed);
        assert!(
            waiters[0].is_woken() && !waiters[1].is_woken() && !waiters[2].is_woken(),
            "one unit, one wake"
        );
        assert!(waiters[0].poll().is_pending(), "nothing came free");
        state.changed.notify(Change::Other);
        assert!(
            waiters.iter().all(|waiter| waiter.is_woken()),
            "an uncounted change wakes the lane"
        );
        drop((waiters, held));
        assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn admission_reserves_before_publication_and_releases_unused_handouts() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 0);
        let input = Extensions::new();
        let mut create = tokio_test::task::spawn(pool.create(TestId(0), conn, permit, &input));
        assert!(create.poll().is_pending());
        assert!(pool.storage.lock().by_id.is_empty());
        state.set_limit(1);
        assert!(create.is_woken());
        let Poll::Ready(Ok(first)) = create.poll() else {
            panic!("first credit must admit establishment")
        };
        assert_eq!(state.reserved.load(Ordering::SeqCst), 1);
        assert!(!input.contains::<ReservationToken>());
        let mut bound = input.clone();
        first.admission.as_ref().unwrap().bind(&mut bound);
        let token = bound.get_ref::<ReservationToken>().unwrap();
        assert!(token.0.upgrade().is_some());
        drop(first);
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
        assert!(token.0.upgrade().is_none());
    }

    #[tokio::test]
    async fn cloned_request_metadata_cannot_exchange_or_retain_handout_reservations() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 2);
        let shared = Extensions::new();
        let first = pool.create(TestId(0), conn, permit, &shared).await.unwrap();
        let ConnectionResult::Connection(second) =
            pool.get_conn(&TestId(0), &shared).await.unwrap()
        else {
            panic!("second reserved checkout")
        };
        assert_eq!(state.reserved.load(Ordering::SeqCst), 2);
        // Dispatch in reverse checkout order against clones of the same store.
        let second_metadata = second.serve(shared.clone()).await.unwrap();
        let first_metadata = first.serve(shared.clone()).await.unwrap();
        assert!(!shared.contains::<ReservationToken>());
        let a = &first_metadata.get_ref::<ReservationToken>().unwrap().0;
        let b = &second_metadata.get_ref::<ReservationToken>().unwrap().0;
        assert!(!Weak::ptr_eq(a, b));
        drop(first);
        assert!(
            a.upgrade().is_none(),
            "saved metadata must not own unused credit"
        );
        assert!(
            b.upgrade().is_some(),
            "other handout keeps its own reservation"
        );
        let second_again = second.serve(shared.clone()).await.unwrap();
        assert!(Weak::ptr_eq(
            b,
            &second_again.get_ref::<ReservationToken>().unwrap().0
        ));
        drop(second);
        assert!(b.upgrade().is_none());
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn admission_wakes_on_transport_credit_without_releasing_pool_handout() {
        for selection in [
            MuxSelection::FirstAvailable,
            MuxSelection::LeastLoaded,
            MuxSelection::RoundRobin,
        ] {
            let pool = MultiplexPool::try_new(32, 1)
                .unwrap()
                .with_selection(selection);
            let permit = new_slot(&pool).await;
            let (conn, state) = admission_connection(&pool, 1);
            let input = Extensions::new();
            let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
            let next_input = Extensions::new();
            let mut next = tokio_test::task::spawn(pool.get_conn(&TestId(0), &next_input));
            assert!(next.poll().is_pending());
            state.set_limit(2);
            assert!(next.is_woken());
            let Poll::Ready(Ok(ConnectionResult::Connection(second))) = next.poll() else {
                panic!("transport credit must wake saturated pool")
            };
            assert_eq!(state.reserved.load(Ordering::SeqCst), 2);
            drop((first, second));
            assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn work_outliving_its_handouts_keeps_a_connection_from_eviction() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 4);
        let input = Extensions::new();
        let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
        // An upgraded tunnel, say: the handout is gone, the connection is not idle.
        state.set_in_use(true);
        drop(first);

        let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT));
        assert!(other.poll().is_pending(), "a busy connection was evicted");
        assert!(pool.storage.lock().by_id.contains_key(&TestId(0)));

        state.set_in_use(false);
        assert!(
            other.is_woken(),
            "the end of that work must wake the waiter"
        );
        let Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) = other.poll() else {
            panic!("the now idle connection must be evicted for the waiter")
        };
        assert!(pool.storage.lock().by_id.is_empty());
    }

    #[tokio::test]
    async fn the_end_of_work_outliving_the_last_handout_is_an_eviction_chance() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 4);
        let input = Extensions::new();
        let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
        let mut leaving = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT));
        let mut staying = tokio_test::task::spawn(pool.get_conn(&TestId(2), &EMPTY_INPUT));
        assert!(leaving.poll().is_pending());
        assert!(staying.poll().is_pending());

        state.set_in_use(true);
        drop(first);
        assert!(
            !leaving.is_woken() && !staying.is_woken(),
            "still busy: nothing to evict"
        );
        drop(leaving);

        state.set_in_use(false);
        assert!(
            staying.is_woken(),
            "the connection announces the end of its work"
        );
        let Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) = staying.poll() else {
            panic!("the now idle connection must be evicted for the remaining waiter")
        };
    }

    #[tokio::test(start_paused = true)]
    async fn work_outliving_its_handouts_keeps_a_connection_from_expiring() {
        let pool = MultiplexPool::try_new(32, 1)
            .unwrap()
            .with_idle_timeout(Duration::from_micros(1));
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 4);
        let input = Extensions::new();
        let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
        state.set_in_use(true);
        drop(first);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let Ok(ConnectionResult::Connection(reused)) =
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await
        else {
            panic!("a busy connection expired as idle")
        };
        drop(reused);
        state.set_in_use(false);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_matches!(
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await,
            Ok(ConnectionResult::CreatePermit(_))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_idle_clock_restarts_when_the_pool_sees_outliving_work() {
        let pool = MultiplexPool::try_new(32, 1)
            .unwrap()
            .with_idle_timeout(Duration::from_millis(30));
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 4);
        let input = Extensions::new();
        let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
        state.set_in_use(true);
        drop(first);
        tokio::time::sleep(Duration::from_millis(40)).await;
        // A full pool sweeps every connection for another destination's request.
        let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT));
        assert!(other.poll().is_pending());
        drop(other);

        state.set_in_use(false);
        assert_matches!(
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await,
            Ok(ConnectionResult::Connection(_)),
            "work that just ended does not count as idle time"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_during_outliving_work_restarts_the_idle_clock() {
        let pool = MultiplexPool::try_new(32, 2)
            .unwrap()
            .with_idle_timeout(Duration::from_millis(30));
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 4);
        let input = Extensions::new();
        let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
        state.set_in_use(true);
        drop(first);
        // Before the timeout, a lookup that cannot use the connection still sees its work.
        state.set_limit(0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_matches!(
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await,
            Ok(ConnectionResult::CreatePermit(_))
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        state.set_in_use(false);
        state.set_limit(4);
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_matches!(
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await,
            Ok(ConnectionResult::Connection(_)),
            "idle for 5ms of a 30ms timeout"
        );
    }

    /// A connection forked from another one's metadata, a tunnel through it say, is admitted
    /// by its own policy only, never the outer connection's.
    #[tokio::test]
    async fn admission_is_the_connections_own_not_an_ancestors() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let permit = new_slot(&pool).await;
        let (outer, state) = admission_connection(&pool, 0);
        let inner = Conn {
            serial: 2,
            extensions: outer.extensions.fork(),
        };
        let input = Extensions::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            pool.create(TestId(0), inner, permit, &input),
        )
        .await
        .expect("the outer connection's admission does not apply")
        .unwrap();
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    }

    /// A saturated candidate that goes broken wakes its waiters, so they look again rather
    /// than wait for its handouts.
    #[tokio::test]
    async fn a_saturated_candidate_going_broken_wakes_its_waiters() {
        let pool = MultiplexPool::try_new(1, 1).unwrap();
        let svc = connector(pool);
        let held = connect(&svc, 0).await;
        let mut waiter = tokio_test::task::spawn(connect(&svc, 0));
        assert!(waiter.poll().is_pending());
        // Settle until it waits on nothing but the pool.
        for _ in 0..16 {
            if !waiter.is_woken() {
                break;
            }
            assert!(waiter.poll().is_pending());
        }
        assert!(!waiter.is_woken());
        held.conn
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .mark_broken();
        assert!(waiter.is_woken(), "a broken candidate woke nobody");
        assert!(
            waiter.poll().is_pending(),
            "its handout still holds the slot"
        );
        drop(held);
        assert!(waiter.is_woken());
        assert!(waiter.poll().is_ready());
    }

    #[tokio::test]
    async fn admission_failure_does_not_publish_or_leak_new_connection_slot() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 1);
        state.failed.store(true, Ordering::SeqCst);
        let error = pool
            .create(TestId(0), conn, permit, &EMPTY_INPUT)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "admission failed");
        assert!(pool.storage.lock().by_id.is_empty());
        assert_eq!(pool.total_slots.available_permits(), 1);
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn admission_cancellation_before_publication_releases_create_permit() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 0);
        let mut create =
            tokio_test::task::spawn(pool.create(TestId(0), conn, permit, &EMPTY_INPUT));
        assert!(create.poll().is_pending());
        drop(create);
        assert!(pool.storage.lock().by_id.is_empty());
        assert_eq!(pool.total_slots.available_permits(), 1);
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn pool_timeout_also_bounds_fresh_transport_admission() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let (_, state) = admission_connection(&pool, 0);
        let connector_state = state.clone();
        let inner = service_fn(move |input: ServiceInput<u32>| {
            let state = connector_state.clone();
            async move {
                let conn = Conn {
                    serial: 1,
                    extensions: Extensions::new(),
                };
                conn.extensions
                    .insert(ConnectionAdmission::new(FakeAdmission(state)));
                Ok::<_, Infallible>(EstablishedClientConnection { input, conn })
            }
        });
        let client = PooledConnector::new(
            inner,
            pool.clone(),
            id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
        )
        .with_wait_for_pool_timeout(Duration::from_secs(1));
        let error = client.connect(ServiceInput::new(0)).await.unwrap_err();
        assert_eq!(error.kind(), ConnectionErrorKind::Timeout);
        assert!(pool.storage.lock().by_id.is_empty());
        assert_eq!(pool.total_slots.available_permits(), 1);
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn admission_failure_on_cached_connection_tries_another_candidate() {
        for selection in [
            MuxSelection::FirstAvailable,
            MuxSelection::LeastLoaded,
            MuxSelection::RoundRobin,
        ] {
            let pool = MultiplexPool::try_new(32, 2)
                .unwrap()
                .with_selection(selection);
            let permit = new_slot(&pool).await;
            let (conn, state) = admission_connection(&pool, 1);
            let first = pool
                .create(TestId(0), conn, permit, &EMPTY_INPUT)
                .await
                .unwrap();
            let permit = new_slot(&pool).await;
            let second = pool
                .create(
                    TestId(0),
                    Conn {
                        serial: 2,
                        extensions: Extensions::new(),
                    },
                    permit,
                    &EMPTY_INPUT,
                )
                .await
                .unwrap();
            drop((first, second));
            state.failed.store(true, Ordering::SeqCst);
            let ConnectionResult::Connection(next) =
                pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap()
            else {
                panic!("healthy candidate must be reused")
            };
            assert_eq!(next.serve(ServiceInput::new(())).await.unwrap(), 2);
            assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn admission_returns_reserved_credit_when_connection_closes_during_reservation() {
        #[derive(Debug)]
        struct CloseDuringAdmission {
            inner: FakeAdmission,
            enabled: Arc<AtomicBool>,
            health: Arc<ConnectionHealthWatcher>,
        }

        impl ConnectionAdmissionPolicy for CloseDuringAdmission {
            fn try_acquire(
                &self,
                input: &Extensions,
            ) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
                let reservation = self.inner.try_acquire(input)?;
                if self.enabled.load(Ordering::SeqCst) {
                    self.health.mark_broken();
                }
                Ok(reservation)
            }

            fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
                self.inner.subscribe(listener);
            }

            fn in_use(&self) -> bool {
                self.inner.in_use()
            }
        }

        let pool = MultiplexPool::try_new(32, 2).unwrap();
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 2);
        let health = Arc::new(ConnectionHealthWatcher::default());
        let enabled = Arc::new(AtomicBool::new(false));
        conn.extensions.insert_arc(health.clone());
        conn.extensions
            .insert(ConnectionAdmission::new(CloseDuringAdmission {
                inner: FakeAdmission(state.clone()),
                enabled: enabled.clone(),
                health,
            }));
        let first = pool
            .create(TestId(0), conn, permit, &EMPTY_INPUT)
            .await
            .unwrap();
        enabled.store(true, Ordering::SeqCst);
        let permit = new_slot(&pool).await;
        assert_eq!(
            state.reserved.load(Ordering::SeqCst),
            1,
            "rejected reservation must be returned"
        );
        drop((permit, first));
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn admission_failure_on_only_cached_connection_returns_fresh_slot() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 1);
        drop(
            pool.create(TestId(0), conn, permit, &EMPTY_INPUT)
                .await
                .unwrap(),
        );
        state.failed.store(true, Ordering::SeqCst);
        let permit = new_slot(&pool).await;
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
        drop(permit);
        assert_eq!(pool.total_slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn concurrent_pool_checkouts_cannot_oversubscribe_transport_credit() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 4);
        let first = pool
            .create(TestId(0), conn, permit, &EMPTY_INPUT)
            .await
            .unwrap();
        let inputs: Vec<_> = (0..16).map(|_| Extensions::new()).collect();
        let mut pending: Vec<_> = inputs
            .iter()
            .map(|input| tokio_test::task::spawn(pool.get_conn(&TestId(0), input)))
            .collect();
        let mut admitted = vec![first];
        for waiter in &mut pending {
            if let Poll::Ready(Ok(ConnectionResult::Connection(conn))) = waiter.poll() {
                admitted.push(conn);
            }
        }
        assert_eq!(admitted.len(), 4);
        assert_eq!(state.reserved.load(Ordering::SeqCst), 4);
        drop(pending);
        drop(admitted);
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exclusive_pool_replaces_connection_with_exhausted_transport_credit() {
        let pool = LruDropPool::try_new(1, 1)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let state = Arc::new(AdmissionState {
            limit: AtomicUsize::new(1),
            reserved: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            in_use: AtomicBool::new(false),
            changed: ChangeSignal::new(),
            storage: Weak::new(),
        });
        let conn = Conn {
            serial: 1,
            extensions: Extensions::new(),
        };
        conn.extensions
            .insert(ConnectionAdmission::new(FakeAdmission(state.clone())));
        let ConnectionResult::CreatePermit(permit) =
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap()
        else {
            panic!("new connection required")
        };
        let input = Extensions::new();
        let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
        assert_eq!(state.reserved.load(Ordering::SeqCst), 1);
        drop(first);
        assert_eq!(state.reserved.load(Ordering::SeqCst), 0);
        state.set_limit(0);
        assert_matches!(
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap(),
            ConnectionResult::CreatePermit(_),
        );
    }

    #[derive(Default)]
    struct TestConnector {
        created: AtomicUsize,
        max_concurrency: Option<usize>,
    }

    impl<Input> Service<Input> for TestConnector
    where
        Input: Send + 'static,
    {
        type Output = EstablishedClientConnection<Conn, Input>;
        type Error = Infallible;

        async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
            let serial = self.created.fetch_add(1, Ordering::Relaxed);
            let conn = Conn {
                serial,
                extensions: Extensions::new(),
            };
            conn.extensions.insert(ConnectionHealthWatcher::default());
            if let Some(mc) = self.max_concurrency {
                conn.extensions.insert(MaxConcurrency::new(mc));
            }
            Ok(EstablishedClientConnection { input, conn })
        }
    }

    /// Like [`TestConnector`] but takes `delay` to establish each connection,
    /// so tests can park waiters while a connection is being created.
    struct SlowConnector {
        created: AtomicUsize,
        delay: Duration,
    }

    impl<Input> Service<Input> for SlowConnector
    where
        Input: Send + 'static,
    {
        type Output = EstablishedClientConnection<Conn, Input>;
        type Error = Infallible;

        async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
            tokio::time::sleep(self.delay).await;
            let serial = self.created.fetch_add(1, Ordering::Relaxed);
            let conn = Conn {
                serial,
                extensions: Extensions::new(),
            };
            conn.extensions.insert(ConnectionHealthWatcher::default());
            Ok(EstablishedClientConnection { input, conn })
        }
    }

    fn id_fn(input: &ServiceInput<u32>) -> Result<TestId, BoxError> {
        Ok(TestId(input.input))
    }

    type MuxConnector = PooledConnector<
        TestConnector,
        MultiplexPool<Conn, TestId>,
        fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
    >;

    fn connector_with(
        pool: MultiplexPool<Conn, TestId>,
        max_concurrency: Option<usize>,
    ) -> MuxConnector {
        let connector = TestConnector {
            created: AtomicUsize::new(0),
            max_concurrency,
        };
        PooledConnector::new(
            connector,
            pool,
            id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
        )
    }

    fn connector(pool: MultiplexPool<Conn, TestId>) -> MuxConnector {
        // No MaxConcurrency advertised means "no limit"
        connector_with(pool, None)
    }

    async fn connect(
        svc: &MuxConnector,
        id: u32,
    ) -> EstablishedClientConnection<MultiplexedConnection<Conn, TestId>, ServiceInput<u32>> {
        svc.connect(ServiceInput::new(id)).await.unwrap()
    }

    fn created(svc: &MuxConnector) -> usize {
        svc.inner.created.load(Ordering::Relaxed)
    }

    #[tokio::test]
    async fn non_reusable_policy_keeps_capacity_without_retaining_connections() {
        let pool = MultiplexPool::try_new(10, 1).unwrap();
        let svc = connector(pool.clone());
        let first = connect(&svc, u32::MAX).await;
        assert!(pool.storage.lock().by_id.is_empty());
        let mut waiter = tokio_test::task::spawn(pool.get_conn(&TestId(u32::MAX), &EMPTY_INPUT));
        assert!(waiter.poll().is_pending());
        drop(first);
        match waiter.poll() {
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) => {}
            other => panic!("fresh capacity must be released on drop: {other:?}"),
        }
        let second = connect(&svc, u32::MAX).await;
        assert_eq!(created(&svc), 2);
        drop(second);
        assert!(pool.storage.lock().by_id.is_empty());
        assert_eq!(pool.total_slots.available_permits(), 1);
    }

    /// Add a connection publishing the requirements `reuse` builds, as a
    /// connector would, to an empty `pool`.
    async fn create_with_reuse(
        pool: &MultiplexPool<Conn, TestId>,
        reuse: impl FnOnce(&Conn) -> ConnectionReuse,
    ) -> MultiplexedConnection<Conn, TestId> {
        let ConnectionResult::CreatePermit(permit) =
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap()
        else {
            panic!("expected an empty pool");
        };
        let conn = Conn {
            serial: 0,
            extensions: Extensions::new(),
        };
        conn.extensions.insert(ConnectionHealthWatcher::default());
        conn.extensions.insert(reuse(&conn));
        pool.create(TestId(0), conn, permit, &EMPTY_INPUT)
            .await
            .unwrap()
    }

    /// The key a request wants from connections keyed by [`KeyPolicy`].
    #[derive(Debug, Clone, Copy, Extension)]
    struct Want(u8);

    #[derive(Debug)]
    struct KeyPolicy {
        key: Option<u8>,
        class: u8,
    }

    impl ConnectionReusePolicy for KeyPolicy {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::from_bits::<Self>(self.class.into())
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            Some(ReuseKey::from_bits::<Want>(self.key?.into()))
        }

        fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
            Some(ReuseKey::from_bits::<Want>(
                input.get_ref::<Want>()?.0.into(),
            ))
        }
    }

    fn keyed(class: u8, key: u8) -> ConnectionReuse {
        ConnectionReuse::new(KeyPolicy {
            key: Some(key),
            class,
        })
    }

    fn want(key: u8) -> Extensions {
        let input = Extensions::new();
        input.insert(Want(key));
        input
    }

    /// Add a connection publishing `reuse` (none: unrestricted) under `id`.
    async fn add(
        pool: &MultiplexPool<Conn, TestId>,
        id: u32,
        reuse: Option<ConnectionReuse>,
    ) -> MultiplexedConnection<Conn, TestId> {
        let permit = PoolSlot(pool.total_slots.clone().try_acquire_owned().unwrap());
        let conn = Conn {
            serial: pool.next_seq.load(Ordering::Relaxed) as usize,
            extensions: Extensions::new(),
        };
        conn.extensions.insert(ConnectionHealthWatcher::default());
        if let Some(reuse) = reuse {
            conn.extensions.insert(reuse);
        }
        pool.create(TestId(id), conn, permit, &EMPTY_INPUT)
            .await
            .unwrap()
    }

    type Checkout<'a> = tokio_test::task::Spawn<
        Pin<
            Box<
                dyn Future<
                        Output = Result<
                            ConnectionResult<MultiplexedConnection<Conn, TestId>, PoolSlot>,
                            BoxError,
                        >,
                    > + Send
                    + 'a,
            >,
        >,
    >;

    /// A checkout of `input`, polled once so it queues if it has to wait.
    fn queue<'a>(pool: &'a MultiplexPool<Conn, TestId>, input: &'a Extensions) -> Checkout<'a> {
        let mut checkout = tokio_test::task::spawn(Box::pin(pool.get_conn(&TestId(0), input))
            as Pin<Box<dyn Future<Output = _> + Send + 'a>>);
        assert!(checkout.poll().is_pending(), "the pool is saturated");
        checkout
    }

    fn handout(checkout: &mut Checkout<'_>) -> MultiplexedConnection<Conn, TestId> {
        match checkout.poll() {
            Poll::Ready(Ok(ConnectionResult::Connection(conn))) => conn,
            other => panic!("expected a handout, got {other:?}"),
        }
    }

    /// One exclusive connection, held, in a pool that cannot dial another.
    async fn saturated() -> (
        MultiplexPool<Conn, TestId>,
        MultiplexedConnection<Conn, TestId>,
    ) {
        let pool = MultiplexPool::try_new(1, 1).unwrap();
        let held = add(&pool, 0, None).await;
        (pool, held)
    }

    #[tokio::test]
    async fn waiters_are_served_in_arrival_order() {
        let (pool, held) = saturated().await;
        let mut first = queue(&pool, &EMPTY_INPUT);
        let mut second = queue(&pool, &EMPTY_INPUT);
        let mut third = queue(&pool, &EMPTY_INPUT);
        drop(held);
        assert!(first.is_woken());
        assert!(
            !second.is_woken() && !third.is_woken(),
            "one release, one wake"
        );
        let held = handout(&mut first);
        drop(held);
        assert!(second.is_woken() && !third.is_woken());
        let held = handout(&mut second);
        drop(held);
        let held = handout(&mut third);
        drop(held);
        assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn two_released_streams_wake_two_waiters() {
        let pool = MultiplexPool::try_new(2, 1).unwrap();
        let a = add(&pool, 0, None).await;
        let ConnectionResult::Connection(b) =
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap()
        else {
            panic!("a free stream");
        };
        let mut first = queue(&pool, &EMPTY_INPUT);
        let mut second = queue(&pool, &EMPTY_INPUT);
        drop(a);
        drop(b);
        assert!(
            first.is_woken() && second.is_woken(),
            "each unit reaches its own waiter"
        );
        drop((handout(&mut first), handout(&mut second)));
        assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn newcomers_queue_behind_waiters() {
        let (pool, held) = saturated().await;
        let mut waiter = queue(&pool, &EMPTY_INPUT);
        drop(held);
        // The released stream belongs to the waiter: a newcomer queues.
        let mut newcomer = queue(&pool, &EMPTY_INPUT);
        let held = handout(&mut waiter);
        assert!(newcomer.poll().is_pending());
        drop(held);
        drop(handout(&mut newcomer));
    }

    #[tokio::test]
    async fn a_cancelled_waiter_passes_its_wake_on() {
        let (pool, held) = saturated().await;
        let first = queue(&pool, &EMPTY_INPUT);
        let mut second = queue(&pool, &EMPTY_INPUT);
        drop(held);
        assert!(first.is_woken() && !second.is_woken());
        drop(first);
        assert!(
            second.is_woken(),
            "the unused wake moves to the next waiter"
        );
        drop(handout(&mut second));
        assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn an_idle_connection_its_waiters_leave_can_be_evicted() {
        let (pool, held) = saturated().await;
        let other_input = Extensions::new();
        let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &other_input));
        assert!(other.poll().is_pending(), "nothing to evict yet");
        let same = queue(&pool, &EMPTY_INPUT);
        drop(held);
        assert!(
            same.is_woken() && !other.is_woken(),
            "spoken for: no eviction chance"
        );
        drop(same);
        assert!(
            other.is_woken(),
            "nobody waits for it now: an eviction chance"
        );
        assert!(matches!(
            other.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ));
        assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_waiter_woken_for_nothing_keeps_its_place() {
        let pool = MultiplexPool::try_new(4, 1).unwrap();
        let conn = Conn {
            serial: 0,
            extensions: Extensions::new(),
        };
        let max = Arc::new(MaxConcurrency::new(1));
        conn.extensions.insert_arc(max.clone());
        let permit = PoolSlot(pool.total_slots.clone().try_acquire_owned().unwrap());
        let held = pool
            .create(TestId(0), conn, permit, &EMPTY_INPUT)
            .await
            .unwrap();
        let mut first = queue(&pool, &EMPTY_INPUT);
        let mut second = queue(&pool, &EMPTY_INPUT);
        // A pushed change wakes the lane, but frees nothing.
        max.set(1);
        assert!(first.is_woken() && second.is_woken());
        assert!(first.poll().is_pending() && second.poll().is_pending());
        drop(held);
        assert!(
            first.is_woken() && !second.is_woken(),
            "the first in line comes first"
        );
        drop(handout(&mut first));
        drop(handout(&mut second));
    }

    #[tokio::test]
    async fn a_waiter_of_several_lanes_leaves_all_of_them() {
        let pool = MultiplexPool::try_new(1, 2).unwrap();
        let unrestricted = add(&pool, 0, None).await;
        let keyed = add(&pool, 0, Some(keyed(0, 1))).await;
        let input = want(1);
        let mut waiter = queue(&pool, &input);
        drop(keyed);
        let served = handout(&mut waiter);
        for lane in pool.storage.lock().by_id[&TestId(0)].lanes() {
            assert!(lane.waiters.is_empty(), "the served waiter left every lane");
        }
        drop((served, unrestricted));
        assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
    }

    /// Many checkouts on few exclusive connections, with pushed changes in
    /// between: every one completes, and nothing stays queued.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn waiters_never_stall_under_churn() {
        for selection in [
            MuxSelection::FirstAvailable,
            MuxSelection::LeastLoaded,
            MuxSelection::RoundRobin,
        ] {
            let pool = MultiplexPool::try_new(1, 4)
                .unwrap()
                .with_selection(selection);
            let max = Arc::new(MaxConcurrency::new(1));
            let mut tasks = Vec::new();
            for task in 0..32_u32 {
                let pool = pool.clone();
                let max = max.clone();
                tasks.push(tokio::spawn(async move {
                    for round in 0..64_u32 {
                        let handout = match pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap() {
                            ConnectionResult::Connection(handout) => handout,
                            ConnectionResult::CreatePermit(permit) => {
                                let conn = Conn {
                                    serial: 0,
                                    extensions: Extensions::new(),
                                };
                                conn.extensions.insert_arc(max.clone());
                                pool.create(TestId(0), conn, permit, &EMPTY_INPUT)
                                    .await
                                    .unwrap()
                            }
                        };
                        if (task + round) % 7 == 0 {
                            max.set(1);
                        }
                        tokio::task::yield_now().await;
                        drop(handout);
                    }
                }));
            }
            tokio::time::timeout(Duration::from_secs(30), async {
                for task in tasks {
                    task.await.unwrap();
                }
            })
            .await
            .expect("no checkout stalls");
            assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
            assert_open_matches_capacity(&pool);
        }
    }

    #[derive(Debug, Extension)]
    struct Binding;

    /// Credit that a dispatch already moved into the protocol's own count:
    /// dropping a handout returns nothing, so nothing is pushed for it.
    #[derive(Debug, Default)]
    struct Busy {
        in_use: AtomicBool,
        changed: ChangeSignal,
    }

    #[derive(Debug)]
    struct BusyAdmission(Arc<Busy>);

    impl ConnectionAdmissionPolicy for BusyAdmission {
        fn try_acquire(
            &self,
            _: &Extensions,
        ) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
            Ok(Some(ConnectionAdmissionLease::new(Arc::new(()), Binding)))
        }

        fn subscribe(&self, listener: Weak<dyn ChangeListener>) {
            self.0.changed.subscribe(listener);
        }

        fn in_use(&self) -> bool {
            self.0.in_use.load(Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn a_release_wakes_its_lane_and_not_an_eviction_waiter() {
        let pool = MultiplexPool::try_new(2, 1).unwrap();
        let permit = new_slot(&pool).await;
        let busy = Arc::new(Busy::default());
        let conn = Conn {
            serial: 0,
            extensions: Extensions::new(),
        };
        conn.extensions
            .insert(ConnectionAdmission::new(BusyAdmission(busy.clone())));
        let first = pool
            .create(TestId(0), conn, permit, &EMPTY_INPUT)
            .await
            .unwrap();
        // Work outlives the handout: the connection is not idle, so not
        // evictable, and a waiter of another id waits for it to become so.
        busy.in_use.store(true, Ordering::SeqCst);
        drop(first);
        let other_input = Extensions::new();
        let mut other = tokio_test::task::spawn(pool.get_conn(&TestId(1), &other_input));
        assert!(other.poll().is_pending());
        let ConnectionResult::Connection(a) =
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap()
        else {
            panic!("a free stream");
        };
        let ConnectionResult::Connection(b) =
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap()
        else {
            panic!("a free stream");
        };
        let mut same = queue(&pool, &EMPTY_INPUT);
        if other.is_woken() {
            assert!(other.poll().is_pending());
        }
        drop(b);
        assert!(
            same.is_woken(),
            "the freed stream wakes the waiter of its lane"
        );
        drop(handout(&mut same));
        drop((a, other));
    }

    #[tokio::test]
    async fn a_waiter_served_in_another_lane_passes_its_wake_on() {
        let pool = MultiplexPool::try_new(2, 2)
            .unwrap()
            .with_selection(MuxSelection::FirstAvailable);
        let unrestricted = add(&pool, 0, None).await;
        let keyed_conn = add(&pool, 0, Some(keyed(0, 1))).await;
        let ConnectionResult::Connection(full_unrestricted) =
            pool.get_conn(&TestId(0), &want(2)).await.unwrap()
        else {
            panic!("a free stream");
        };
        let ConnectionResult::Connection(full_keyed) =
            pool.get_conn(&TestId(0), &want(1)).await.unwrap()
        else {
            panic!("a free stream");
        };
        let (both, unrestricted_only, both_again) = (want(1), want(2), want(1));
        let mut first = queue(&pool, &both);
        let mut second = queue(&pool, &unrestricted_only);
        let mut third = queue(&pool, &both_again);
        // A keyed stream frees (waking `first`), then an unrestricted one
        // (waking `second`): `first` prefers the older unrestricted one.
        drop(full_keyed);
        drop(full_unrestricted);
        let served = handout(&mut first);
        assert!(Arc::ptr_eq(&served.inner, &unrestricted.inner));
        if second.is_woken() {
            assert!(second.poll().is_pending(), "it cannot use the keyed one");
        }
        assert!(
            third.is_woken(),
            "the keyed stream `first` left is announced to the next who can use it"
        );
        drop(handout(&mut third));
        drop((served, second, unrestricted, keyed_conn));
        assert_eq!(pool.waiting.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_capacity_raise_wakes_every_waiter() {
        let pool = MultiplexPool::try_new(10, 1).unwrap();
        let permit = new_slot(&pool).await;
        let conn = Conn {
            serial: 0,
            extensions: Extensions::new(),
        };
        let max = Arc::new(MaxConcurrency::new(1));
        conn.extensions.insert_arc(max.clone());
        let first = pool
            .create(TestId(0), conn, permit, &EMPTY_INPUT)
            .await
            .unwrap();
        let mut a = queue(&pool, &EMPTY_INPUT);
        let mut b = queue(&pool, &EMPTY_INPUT);
        max.set(3);
        assert!(a.is_woken() && b.is_woken());
        drop((handout(&mut a), handout(&mut b), first));
    }

    #[tokio::test]
    async fn rekey_fences_candidates_selected_under_the_old_lane() {
        let pool = MultiplexPool::try_new(2, 2).unwrap();
        let held = add(&pool, 0, Some(keyed(0, 1))).await;
        let lanes = pool.request_lanes(&TestId(0), &want(1));

        // The exact path: a snapshot taken before the rekey.
        let snapshot = pool.snapshot(
            &mut pool.storage.lock(),
            &TestId(0),
            &lanes,
            &mut Vec::new(),
            Look::New,
        );
        // The fast path: a claim made before the rekey.
        let claimed = pool
            .storage
            .lock()
            .by_id
            .get_mut(&TestId(0))
            .unwrap()
            .claim(&lanes, MuxSelection::FirstAvailable, 2, &[], None)
            .unwrap();

        held.rekey(keyed(0, 2));
        assert!(
            select_and_admit(
                &snapshot,
                &TestId(0),
                MuxSelection::FirstAvailable,
                &AtomicUsize::new(0),
                2,
                &want(1),
            )
            .is_none(),
            "a snapshot of the old lane admits nothing after the rekey"
        );
        assert!(
            claimed
                .conn
                .try_admit(claimed.lane_gen, 2, &want(1))
                .is_none(),
            "a claim in the old lane admits nothing after the rekey"
        );
        assert_open_matches_capacity(&pool);
        // The new lane does admit.
        let ConnectionResult::Connection(stream) =
            pool.get_conn(&TestId(0), &want(2)).await.unwrap()
        else {
            panic!("the rekeyed connection serves its new lane");
        };
        drop((stream, held));
    }

    #[tokio::test]
    async fn snapshots_of_several_lanes_keep_creation_order() {
        let pool = MultiplexPool::try_new(4, 4).unwrap();
        let held = [
            add(&pool, 0, Some(keyed(0, 1))).await,
            add(&pool, 0, None).await,
            add(&pool, 0, Some(keyed(1, 1))).await,
            add(&pool, 0, None).await,
        ];
        let lanes = pool.request_lanes(&TestId(0), &want(1));
        let snapshot = pool.snapshot(
            &mut pool.storage.lock(),
            &TestId(0),
            &lanes,
            &mut Vec::new(),
            Look::New,
        );
        let seqs: Vec<_> = snapshot.iter().map(|(conn, _)| conn.seq).collect();
        assert_eq!(seqs.len(), 4);
        assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]), "{seqs:?}");
        drop(held);
    }

    #[tokio::test]
    async fn emptied_lanes_and_classes_leave_the_bucket() {
        let pool = MultiplexPool::try_new(4, 8).unwrap();
        let mut held = Vec::new();
        for (class, key) in [(0, 1), (0, 2), (1, 1), (1, 2)] {
            held.push(add(&pool, 0, Some(keyed(class, key))).await);
        }
        held.push(add(&pool, 0, None).await);
        {
            let storage = pool.storage.lock();
            let bucket = &storage.by_id[&TestId(0)];
            assert_eq!(bucket.keyed.len(), 2);
            assert_eq!(bucket.classes.len(), 2);
        }
        let mark_broken = |index: usize| {
            held[index]
                .extensions()
                .get_ref::<ConnectionHealthWatcher>()
                .unwrap()
                .mark_broken();
        };
        // Class 0 key 1 goes; its class keeps key 2.
        mark_broken(0);
        pool.sweep_all(&mut pool.storage.lock(), &mut Vec::new());
        assert_open_matches_capacity(&pool);
        assert_eq!(
            pool.storage.lock().by_id[&TestId(0)].keyed[0].lanes.len(),
            1
        );
        // Class 0 goes as a whole.
        mark_broken(1);
        pool.sweep_all(&mut pool.storage.lock(), &mut Vec::new());
        assert_open_matches_capacity(&pool);
        {
            let storage = pool.storage.lock();
            let bucket = &storage.by_id[&TestId(0)];
            assert_eq!(bucket.keyed.len(), 1);
            assert_eq!(bucket.classes.len(), 1);
        }
        // The rest goes, and the bucket with it.
        for index in 2..5 {
            mark_broken(index);
        }
        pool.sweep_all(&mut pool.storage.lock(), &mut Vec::new());
        assert!(pool.storage.lock().by_id.is_empty());
        drop(held);
    }

    #[tokio::test]
    async fn connections_that_must_not_be_reused_are_never_stored() {
        let pool = MultiplexPool::try_new(4, 4).unwrap();
        let fresh = add(
            &pool,
            0,
            Some(ConnectionReuse::new(KeyPolicy {
                key: None,
                class: 0,
            })),
        )
        .await;
        let fresh_id = add(&pool, u32::MAX, None).await;
        assert!(pool.storage.lock().by_id.is_empty());
        // Neither does a rekey file them: one has a non-reusable id.
        fresh_id.rekey(keyed(0, 1));
        assert!(pool.storage.lock().by_id.is_empty());
        fresh.rekey(keyed(0, 1));
        assert_eq!(pool.storage.lock().by_id[&TestId(0)].conns().count(), 1);
        assert_open_matches_capacity(&pool);
        drop((fresh, fresh_id));
    }

    #[tokio::test]
    async fn rekey_lists_a_connection_with_room_in_its_new_lane() {
        let pool = MultiplexPool::try_new(4, 2).unwrap();
        let held = add(&pool, 0, Some(keyed(0, 1))).await;
        held.rekey(keyed(1, 7));
        assert_open_matches_capacity(&pool);
        let storage = pool.storage.lock();
        let lane = storage.by_id[&TestId(0)].only_lane();
        assert!(lane.open.contains_key(&held.inner.seq));
        drop(storage);
        drop(held);
    }

    #[tokio::test]
    async fn permit_wakeup_rederives_lanes_outside_storage_lock() {
        #[derive(Debug)]
        struct RejectReuse(Weak<Mutex<Storage<Conn, TestId>>>);

        impl ConnectionReusePolicy for RejectReuse {
            fn classifier(&self) -> ReuseKey {
                ReuseKey::of::<Self>()
            }

            fn connection_key(&self) -> Option<ReuseKey> {
                Some(ReuseKey::of::<Self>())
            }

            fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
                let storage = self.0.upgrade().unwrap();
                assert!(
                    storage.try_lock().is_some(),
                    "connector policy must not run under the pool lock"
                );
                None
            }
        }

        let pool = MultiplexPool::try_new(4, 2).unwrap();
        let held = create_with_reuse(&pool, |_| {
            ConnectionReuse::new(RejectReuse(Arc::downgrade(&pool.storage)))
        })
        .await;
        let permit = pool.total_slots.clone().try_acquire_owned().unwrap();
        let mut waiter = tokio_test::task::spawn(pool.get_conn(&TestId(0), &EMPTY_INPUT));
        assert!(waiter.poll().is_pending());

        // Only the total-slot semaphore wakes this waiter. Its admission path
        // must derive the request's lanes again before selecting spare capacity.
        drop(permit);
        assert!(waiter.is_woken());
        assert_matches!(
            waiter.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_))),
        );
        drop(held);
    }

    #[tokio::test]
    async fn policy_check_cannot_admit_a_connection_marked_broken_during_the_check() {
        #[derive(Debug)]
        struct CloseDuringMatch {
            health: Arc<ConnectionHealthWatcher>,
            enabled: Arc<AtomicBool>,
        }

        impl ConnectionReusePolicy for CloseDuringMatch {
            fn classifier(&self) -> ReuseKey {
                ReuseKey::of::<Self>()
            }

            fn connection_key(&self) -> Option<ReuseKey> {
                Some(ReuseKey::of::<Self>())
            }

            fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
                if !self.enabled.load(Ordering::Relaxed) {
                    return None;
                }
                self.health.mark_broken();
                Some(ReuseKey::of::<Self>())
            }
        }

        for selection in [
            MuxSelection::FirstAvailable,
            MuxSelection::LeastLoaded,
            MuxSelection::RoundRobin,
        ] {
            for after_wait in [false, true] {
                let pool = MultiplexPool::try_new(4, 2)
                    .unwrap()
                    .with_selection(selection);
                let enabled = Arc::new(AtomicBool::new(!after_wait));
                let held = create_with_reuse(&pool, |conn| {
                    ConnectionReuse::new(CloseDuringMatch {
                        health: conn
                            .extensions
                            .get_arc::<ConnectionHealthWatcher>()
                            .unwrap(),
                        enabled: enabled.clone(),
                    })
                })
                .await;
                let reserved =
                    after_wait.then(|| pool.total_slots.clone().try_acquire_owned().unwrap());
                let mut waiter = tokio_test::task::spawn(pool.get_conn(&TestId(0), &EMPTY_INPUT));
                if after_wait {
                    assert!(waiter.poll().is_pending());
                    enabled.store(true, Ordering::Relaxed);
                    drop(reserved);
                    assert!(waiter.is_woken());
                }
                assert_matches!(
                    waiter.poll(),
                    Poll::Ready(Ok(ConnectionResult::CreatePermit(_))),
                    "a close reported during policy evaluation must not yield a broken connection",
                );
                drop(held);
            }
        }
    }

    #[tokio::test]
    async fn policy_check_cannot_admit_a_snapshot_retired_during_the_check() {
        #[derive(Debug)]
        struct RetireDuringMatch {
            pool: MultiplexPool<Conn, TestId>,
            evict: bool,
        }

        impl ConnectionReusePolicy for RetireDuringMatch {
            fn classifier(&self) -> ReuseKey {
                ReuseKey::of::<Self>()
            }

            fn connection_key(&self) -> Option<ReuseKey> {
                Some(ReuseKey::of::<Self>())
            }

            fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
                if self.evict {
                    let removed = MultiplexPool::evict_lru_idle(&mut self.pool.storage.lock());
                    assert!(removed.is_some());
                    drop(removed);
                } else {
                    let mut doomed = Vec::new();
                    {
                        let mut storage = self.pool.storage.lock();
                        storage.by_id[&TestId(0)]
                            .conns()
                            .next()
                            .unwrap()
                            .conn
                            .extensions()
                            .get_ref::<ConnectionHealthWatcher>()
                            .unwrap()
                            .mark_broken();
                        self.pool.sweep_all(&mut storage, &mut doomed);
                    }
                    drop(doomed);
                }
                Some(ReuseKey::of::<Self>())
            }
        }

        for evict in [false, true] {
            let pool = MultiplexPool::try_new(4, 1).unwrap();
            let held = create_with_reuse(&pool, |_| {
                ConnectionReuse::new(RetireDuringMatch {
                    pool: pool.clone(),
                    evict,
                })
            })
            .await;
            drop(held);
            let result = pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap();
            assert_matches!(
                result,
                ConnectionResult::CreatePermit(_),
                "a retired snapshot must not bypass health or pool capacity (evict={evict})",
            );
            drop(result);
            assert_eq!(pool.total_slots.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn retired_preferred_candidate_does_not_hide_other_stream_capacity() {
        let pool = MultiplexPool::try_new(1, 2).unwrap();
        let svc = connector(pool.clone());
        let first = connect(&svc, 0).await;
        let second = connect(&svc, 0).await;
        drop((first, second));
        let mut doomed = Vec::new();
        let lanes = pool.request_lanes(&TestId(0), &EMPTY_INPUT);
        let mut snapshot = pool.snapshot(
            &mut pool.storage.lock(),
            &TestId(0),
            &lanes,
            &mut doomed,
            Look::New,
        );
        let (retired, transferred_slot) =
            MultiplexPool::evict_lru_idle(&mut pool.storage.lock()).unwrap();
        let retired_index = snapshot
            .iter()
            .position(|(conn, _)| Arc::ptr_eq(conn, &retired))
            .unwrap();
        snapshot.swap(0, retired_index);
        // Retain the transferred permit as an unrelated dial would, so it
        // cannot rescue a selection that overlooks the other idle connection.
        for selection in [MuxSelection::LeastLoaded, MuxSelection::RoundRobin] {
            let conn = select_and_admit(
                &snapshot,
                &TestId(0),
                selection,
                &AtomicUsize::new(0),
                1,
                &EMPTY_INPUT,
            )
            .expect("another compatible connection still has stream capacity");
            assert!(!Arc::ptr_eq(&conn.inner, &retired));
            drop(conn);
        }
        drop(transferred_slot);
    }

    #[tokio::test]
    async fn shares_one_connection() {
        let pool = MultiplexPool::new(NonZeroUsize::new(4).unwrap(), NonZeroUsize::new(4).unwrap());
        let svc = connector(pool);

        let mut handles = Vec::new();
        for _ in 0..4 {
            handles.push(connect(&svc, 0).await);
        }
        assert_eq!(
            created(&svc),
            1,
            "all 4 handouts should share one connection"
        );
        for h in &handles {
            assert_eq!(h.conn.serve(ServiceInput::new(())).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn dropping_a_handout_releases_its_stream_slot_immediately() {
        let pool = MultiplexPool::try_new(1, 1).unwrap();
        let svc = connector(pool.clone());
        let handout = connect(&svc, 0).await;
        let stored = Arc::clone(
            pool.storage.lock().by_id[&TestId(0)]
                .conns()
                .next()
                .unwrap(),
        );

        assert_eq!(stored.active.load(Ordering::Relaxed), 1);
        let previous_idle = stored.last_idle.as_nanos();
        tokio::time::sleep(Duration::from_millis(2)).await;
        drop(handout);
        assert_eq!(stored.active.load(Ordering::Relaxed), 0);
        assert!(stored.is_idle());
        assert!(stored.last_idle.as_nanos() > previous_idle);
    }

    #[tokio::test(start_paused = true)]
    async fn maxconcurrency_increase_wakes_waiters() {
        let pool = MultiplexPool::try_new(10, 1).unwrap();
        let svc = Arc::new(connector_with(pool, Some(1)));

        let c1 = svc.connect(ServiceInput::new(0)).await.unwrap();

        let woke = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waiter = {
            let svc = svc.clone();
            let woke = woke.clone();
            tokio::spawn(async move {
                let _h = svc.connect(ServiceInput::new(0)).await.unwrap();
                woke.store(true, Ordering::Relaxed);
            })
        };

        // The waiter parks: connection 0 is at capacity and the pool is full.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!woke.load(Ordering::Relaxed), "waiter should be parked");

        // Raise the connection's advertised capacity (as an h2 SETTINGS bump would):
        // the parked waiter must wake and admit on the now-available stream slot.
        c1.conn
            .extensions()
            .get_ref::<MaxConcurrency>()
            .unwrap()
            .set(2);

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("a MaxConcurrency increase should wake the parked waiter")
            .unwrap();
        assert!(woke.load(Ordering::Relaxed));
        // c1 is still held; the waiter admitted on the same connection, not a new one.
        assert_eq!(svc.inner.created.load(Ordering::Relaxed), 1);
    }

    /// A `MaxConcurrency` raise right after the parking poll wakes the waiter
    /// without another wake source: it queued before its check.
    #[tokio::test]
    async fn maxconcurrency_increase_wakes_manually_driven_waiter() {
        let pool = MultiplexPool::try_new(10, 1).unwrap();
        let svc = connector_with(pool.clone(), Some(1));

        // Connection A: at its advertised capacity of 1, holding the only slot.
        let c1 = svc.connect(ServiceInput::new(0u32)).await.unwrap();

        let mut waiter = tokio_test::task::spawn(pool.get_conn(&TestId(0), &EMPTY_INPUT));
        assert!(
            waiter.poll().is_pending(),
            "waiter must park: A is at capacity"
        );

        // Raise A's capacity: the connection wakes its lane's waiters.
        c1.conn
            .extensions()
            .get_ref::<MaxConcurrency>()
            .unwrap()
            .set(2);
        assert!(
            waiter.is_woken(),
            "a capacity raise must wake the parked waiter"
        );
        match waiter.poll() {
            Poll::Ready(Ok(ConnectionResult::Connection(_))) => {}
            other => panic!("waiter must admit on the raised capacity, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn maxconcurrency_zero_admits_no_streams() {
        let pool = MultiplexPool::try_new(4, 4).unwrap();
        let svc = connector_with(pool, Some(0));

        let c1 = connect(&svc, 0).await;
        assert_eq!(created(&svc), 1);
        drop(c1);

        // Connection 0 advertises `MaxConcurrency(0)`: even while idle it must not
        // admit a new stream (0 means "no streams", not clamp-to-1), so the pool
        // creates a fresh connection instead of reusing it.
        let _c2 = connect(&svc, 0).await;
        assert_eq!(
            created(&svc),
            2,
            "a connection advertising max_concurrency=0 must not admit new streams"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn new_multiplexed_connection_wakes_waiters() {
        let pool = MultiplexPool::try_new(2, 1).unwrap();
        let svc = PooledConnector::new(
            SlowConnector {
                created: AtomicUsize::new(0),
                delay: Duration::from_millis(100),
            },
            pool,
            id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
        )
        .with_wait_for_pool_timeout(Duration::from_millis(500));

        let c1 = svc.connect(ServiceInput::new(1u32)).await.unwrap();

        let waiter1 = svc.connect(ServiceInput::new(2u32));
        let waiter2 = svc.connect(ServiceInput::new(2u32));

        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(c1);

        let (r1, r2) = tokio::join!(waiter1, waiter2);
        assert!(r1.is_ok(), "first waiter should create a new connection");
        assert!(
            r2.is_ok(),
            "second waiter should reuse the spare stream slot"
        );
    }

    #[tokio::test]
    async fn new_connection_when_saturated() {
        let pool = MultiplexPool::try_new(2, 2).unwrap();
        let svc = connector(pool);

        let _c1 = connect(&svc, 0).await;
        let _c2 = connect(&svc, 0).await;
        assert_eq!(
            created(&svc),
            1,
            "connection 0 should be reused while it has room"
        );

        let c3 = connect(&svc, 0).await;
        assert_eq!(
            created(&svc),
            2,
            "a 3rd concurrent handout needs a new connection"
        );
        assert_eq!(c3.conn.serve(ServiceInput::new(())).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn stream_release_wakes_a_waiter_for_the_matching_id() {
        let pool = MultiplexPool::try_new(2, 2).unwrap();
        let svc = connector(pool.clone());

        let a1 = connect(&svc, 0).await;
        let a2 = connect(&svc, 0).await;
        let b1 = connect(&svc, 1).await;
        let b2 = connect(&svc, 1).await;
        assert_eq!(created(&svc), 2);

        // Register B first. A pool-global `notify_one` would wake this
        // incompatible waiter and strand A even though A gains capacity.
        let mut b_waiter = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT));
        assert!(b_waiter.poll().is_pending());
        let mut a_waiter = tokio_test::task::spawn(pool.get_conn(&TestId(0), &EMPTY_INPUT));
        assert!(a_waiter.poll().is_pending());

        // A remains active, so only an A waiter can use the released stream;
        // the connection is not globally evictable.
        drop(a2);
        assert!(a_waiter.is_woken(), "the matching-ID waiter must wake");
        match a_waiter.poll() {
            Poll::Ready(Ok(ConnectionResult::Connection(_))) => {}
            other => panic!("matching-ID waiter did not reuse A: {other:?}"),
        }
        assert!(b_waiter.poll().is_pending());

        drop((a1, b1, b2));
    }

    #[tokio::test]
    async fn extensions_propagate_at_establish() {
        let pool = MultiplexPool::try_new(2, 2).unwrap();
        let svc = connector(pool);

        let c = connect(&svc, 0).await;

        assert!(
            c.conn
                .extensions()
                .get_ref::<ConnectionHealthWatcher>()
                .is_some()
        );
    }

    #[tokio::test]
    async fn broken_removed_while_handles_survive() {
        let pool = MultiplexPool::try_new(2, 2).unwrap();
        let svc = connector(pool);

        let c1 = connect(&svc, 0).await;
        let c2 = connect(&svc, 0).await;
        assert_eq!(created(&svc), 1);

        // mark the shared connection broken
        c1.conn
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .mark_broken();

        // a fresh handout must not reuse the broken connection
        let c3 = connect(&svc, 0).await;
        assert_eq!(created(&svc), 2);
        assert_eq!(c3.conn.serve(ServiceInput::new(())).await.unwrap(), 1);

        // the in-flight handles still work on the (removed but alive) connection
        assert_eq!(c1.conn.serve(ServiceInput::new(())).await.unwrap(), 0);
        assert_eq!(c2.conn.serve(ServiceInput::new(())).await.unwrap(), 0);

        // once they drop, the slot frees and a new handout can be created again
        drop(c1);
        drop(c2);
        drop(c3);
        let _c4 = connect(&svc, 0).await;
        // c4 reuses connection 1 (still in storage), no new connection
        assert_eq!(created(&svc), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_eviction() {
        let pool = MultiplexPool::try_new(2, 5)
            .unwrap()
            .with_idle_timeout(Duration::from_micros(1));
        let svc = connector(pool);

        let c = connect(&svc, 0).await;
        assert_eq!(created(&svc), 1);
        drop(c);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let _c = connect(&svc, 0).await;
        assert_eq!(created(&svc), 2, "idle connection should have been evicted");
    }

    #[tokio::test]
    async fn least_loaded_selection() {
        let pool = MultiplexPool::try_new(3, 2)
            .unwrap()
            .with_selection(MuxSelection::LeastLoaded);
        let svc = connector(pool);

        let c1 = connect(&svc, 0).await;
        let _c2 = connect(&svc, 0).await;
        let _c3 = connect(&svc, 0).await;
        let _c4 = connect(&svc, 0).await;
        assert_eq!(created(&svc), 2);

        drop(c1);

        let c5 = connect(&svc, 0).await;
        assert_eq!(
            c5.conn.serve(ServiceInput::new(())).await.unwrap(),
            1,
            "least-loaded should pick connection 1 (more free streams)"
        );
    }

    #[tokio::test]
    async fn first_available_selection() {
        let pool = MultiplexPool::try_new(3, 2)
            .unwrap()
            .with_selection(MuxSelection::FirstAvailable);
        let svc = connector(pool);

        let c1 = connect(&svc, 0).await;
        let _c2 = connect(&svc, 0).await;
        let _c3 = connect(&svc, 0).await;
        let _c4 = connect(&svc, 0).await;
        assert_eq!(created(&svc), 2);

        drop(c1);

        let c5 = connect(&svc, 0).await;
        assert_eq!(
            c5.conn.serve(ServiceInput::new(())).await.unwrap(),
            0,
            "first-available should pick connection 0 (first with a free slot)"
        );
    }

    #[tokio::test]
    async fn capacity_one_is_exclusive() {
        let pool = MultiplexPool::try_new(1, 3).unwrap();
        let svc = connector(pool);

        let c1 = connect(&svc, 0).await;
        let c2 = connect(&svc, 0).await;
        let c3 = connect(&svc, 0).await;
        assert_eq!(created(&svc), 3, "capacity 1 never shares a connection");
        // each landed on a distinct connection
        assert_eq!(c1.conn.serve(ServiceInput::new(())).await.unwrap(), 0);
        assert_eq!(c2.conn.serve(ServiceInput::new(())).await.unwrap(), 1);
        assert_eq!(c3.conn.serve(ServiceInput::new(())).await.unwrap(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn saturation_waits_and_times_out() {
        let pool = MultiplexPool::try_new(1, 1).unwrap();
        let svc = connector(pool).with_wait_for_pool_timeout(Duration::from_millis(50));

        let c1 = connect(&svc, 0).await;
        // connection full, no room to create -> get_conn waits, then times out
        let error = svc
            .connect(ServiceInput::new(0u32))
            .await
            .expect_err("saturated pool should time out");
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::Timeout);

        drop(c1);
        // now a slot is free again
        let _c2 = connect(&svc, 0).await;
    }

    #[tokio::test]
    async fn capacity_from_extension() {
        // pool cap 5, but each connection advertises only 2 -> effective 2
        let pool = MultiplexPool::try_new(5, 5).unwrap();
        let svc = connector_with(pool, Some(2));

        let _c1 = connect(&svc, 0).await;
        let _c2 = connect(&svc, 0).await;
        assert_eq!(
            created(&svc),
            1,
            "two streams share the connection (its advertised capacity)"
        );

        let _c3 = connect(&svc, 0).await;
        assert_eq!(
            created(&svc),
            2,
            "a 3rd stream exceeds the advertised capacity -> new connection"
        );
    }

    #[tokio::test]
    async fn capacity_is_read_live() {
        // Connections start advertising 1, pool cap is high.
        let pool = MultiplexPool::try_new(10, 5).unwrap();
        let svc = connector_with(pool, Some(1));

        let c1 = connect(&svc, 0).await; // conn A, now at its limit of 1
        let _c2 = connect(&svc, 0).await; // A full -> conn B
        assert_eq!(created(&svc), 2);

        // Server raises A's SETTINGS_MAX_CONCURRENT_STREAMS to 3.
        c1.conn
            .extensions()
            .get_ref::<MaxConcurrency>()
            .unwrap()
            .set(3);

        // A now has spare capacity, so the next stream reuses A instead of
        // opening a new connection — proving the limit is read live.
        let _c3 = connect(&svc, 0).await;
        assert_eq!(
            created(&svc),
            2,
            "raising MaxConcurrency lets A take another stream (dynamic capacity)"
        );
    }

    #[tokio::test]
    async fn no_extension_uses_pool_cap() {
        // Without a MaxConcurrency extension there is "no limit", so the pool's
        // max_concurrent_streams governs: cap 2 -> 2 streams share one connection.
        let pool = MultiplexPool::try_new(2, 8).unwrap();
        let svc = connector_with(pool, None);

        let _c1 = connect(&svc, 0).await;
        let _c2 = connect(&svc, 0).await;
        assert_eq!(
            created(&svc),
            1,
            "two streams share one connection (pool cap 2)"
        );

        let _c3 = connect(&svc, 0).await;
        assert_eq!(
            created(&svc),
            2,
            "a 3rd stream exceeds the pool cap -> new connection"
        );
    }

    #[tokio::test]
    async fn lru_eviction_when_full() {
        let pool = MultiplexPool::try_new(1, 2).unwrap();
        let svc = connector(pool);

        // A (id 0) and B (id 1), both idle. Then touch A again so A becomes more
        // recently used than B -> B is the LRU, even though A is first in storage.
        drop(connect(&svc, 0).await);
        drop(connect(&svc, 1).await);
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(connect(&svc, 0).await); // reuse A; A.last_idle now newer than B's
        assert_eq!(created(&svc), 2);

        // Pool is full (2 connections); a new id evicts the LRU idle connection (B).
        drop(connect(&svc, 2).await);
        assert_eq!(created(&svc), 3);

        // A survived (more recently used) -> reused, no new connection. This also
        // proves we evicted the LRU (B), not the first-in-storage connection (A).
        drop(connect(&svc, 0).await);
        assert_eq!(
            created(&svc),
            3,
            "A survived: LRU evicted B, not first-in-storage A"
        );

        // B was evicted -> a new connection is created for id 1.
        drop(connect(&svc, 1).await);
        assert_eq!(created(&svc), 4, "B (LRU) was evicted");
    }

    #[tokio::test]
    async fn lru_eviction_keeps_the_freed_slot_with_the_evicting_caller() {
        let pool = MultiplexPool::try_new(1, 1).unwrap();
        let svc = connector(pool.clone());

        // Keep the only connection active while another id parks. The former
        // semaphore-based wait path queued a fair acquire at this point.
        let active = connect(&svc, 0).await;
        {
            let storage = pool.storage.lock();
            assert!(storage.by_id.contains_key(&TestId(0)));
            assert!(!storage.by_id.contains_key(&TestId(1)));
        }
        let mut parked = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT));
        assert!(parked.poll().is_pending());

        // Make connection 0 idle without polling the parked waiter. A caller
        // for id 2 must be able to evict it and immediately claim that slot.
        // A queued semaphore waiter used to steal the released permit here.
        drop(active);
        let mut evicting = tokio_test::task::spawn(pool.get_conn(&TestId(2), &EMPTY_INPUT));
        let evicting_permit = match evicting.poll() {
            Poll::Ready(Ok(ConnectionResult::CreatePermit(permit))) => permit,
            Poll::Ready(Ok(ConnectionResult::Connection(_))) => {
                panic!("different-id idle connection was unexpectedly reused")
            }
            Poll::Ready(Err(error)) => panic!("pool lookup failed: {error}"),
            std::task::Poll::Pending => {
                panic!("evicting caller lost the released slot to a parked waiter")
            }
        };

        // Once the evictor releases its directly transferred slot, the queued
        // waiter receives it through the semaphore and makes progress.
        drop(evicting_permit);
        assert!(parked.is_woken());
        match parked.poll() {
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) => {}
            other => panic!("parked waiter did not receive the released slot: {other:?}"),
        }
    }

    #[tokio::test]
    async fn total_slot_waiters_are_fifo_and_cancellation_safe() {
        let pool = MultiplexPool::<Conn, TestId>::try_new(1, 1).unwrap();
        let held = match pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap() {
            ConnectionResult::CreatePermit(permit) => permit,
            ConnectionResult::Connection(_) => panic!("empty pool unexpectedly reused a slot"),
        };

        let mut first = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT));
        assert!(first.poll().is_pending());
        let mut cancelled = tokio_test::task::spawn(pool.get_conn(&TestId(2), &EMPTY_INPUT));
        assert!(cancelled.poll().is_pending());
        let mut last = tokio_test::task::spawn(pool.get_conn(&TestId(3), &EMPTY_INPUT));
        assert!(last.poll().is_pending());
        drop(cancelled);

        // A connection-capacity notification must not cancel and requeue the
        // semaphore acquisitions. Poll newest-first to expose an accidental
        // loss of the original FIFO positions.
        pool.notify.notify_waiters();
        assert!(last.poll().is_pending());
        assert!(first.poll().is_pending());

        drop(held);
        assert!(first.is_woken());
        assert!(!last.is_woken());
        let first_permit = match first.poll() {
            Poll::Ready(Ok(ConnectionResult::CreatePermit(permit))) => permit,
            other => panic!("oldest waiter did not receive the slot first: {other:?}"),
        };
        assert!(last.poll().is_pending());

        drop(first_permit);
        assert!(last.is_woken());
        match last.poll() {
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_))) => {}
            other => panic!("remaining waiter did not progress after cancellation: {other:?}"),
        }
    }

    /// A create permit dropped by a failed connect must wake a parked waiter
    /// through the total-slot semaphore instead of stranding it until the pool
    /// timeout: nothing else notifies when a connect fails before creating.
    #[tokio::test(start_paused = true)]
    async fn failed_create_frees_slot_for_parked_waiter() {
        struct FailFirstConnector {
            attempts: AtomicUsize,
        }

        impl Service<ServiceInput<u32>> for FailFirstConnector {
            type Output = EstablishedClientConnection<Conn, ServiceInput<u32>>;
            type Error = ConnectionError;

            async fn serve(&self, input: ServiceInput<u32>) -> Result<Self::Output, Self::Error> {
                if self.attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    return Err(ConnectionError::transport(
                        BoxError::from_static_str("first connect fails"),
                        ConnectionErrorKind::Unavailable,
                    ));
                }
                Ok(EstablishedClientConnection {
                    input,
                    conn: Conn {
                        serial: 1,
                        extensions: Extensions::new(),
                    },
                })
            }
        }

        let pool = MultiplexPool::try_new(1, 1).unwrap();
        let svc = Arc::new(
            PooledConnector::new(
                FailFirstConnector {
                    attempts: AtomicUsize::new(0),
                },
                pool,
                id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
            )
            .with_wait_for_pool_timeout(Duration::from_secs(120)),
        );

        // Takes the only slot's create permit, then fails after 50ms.
        let failing = tokio::spawn({
            let svc = svc.clone();
            async move { svc.connect(ServiceInput::new(0u32)).await }
        });
        tokio::task::yield_now().await;
        // Parks: no connection to reuse and no free slot.
        let waiter = tokio::spawn({
            let svc = svc.clone();
            async move { svc.connect(ServiceInput::new(0u32)).await }
        });

        let (failed, waited) = tokio::join!(failing, waiter);
        let _error = failed.unwrap().expect_err("first connect must fail");
        waited
            .unwrap()
            .expect("the slot freed by the failed create must wake the parked waiter");
    }

    /// A waiter parked on a full pool is woken when the last handle of an
    /// already-swept (broken) connection drops and its slot frees up.
    #[tokio::test(start_paused = true)]
    async fn slot_freed_by_swept_connection_teardown_wakes_waiter() {
        let pool = MultiplexPool::try_new(1, 1).unwrap();
        let svc = Arc::new(connector(pool).with_wait_for_pool_timeout(Duration::from_secs(120)));

        let c1 = svc.connect(ServiceInput::new(0u32)).await.unwrap();
        c1.conn
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .mark_broken();

        // The waiter's own attempt sweeps the broken connection out of storage,
        // but the slot is still held by c1's live handle: it parks.
        let waiter = tokio::spawn({
            let svc = svc.clone();
            async move { svc.connect(ServiceInput::new(0u32)).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        drop(c1);

        let waited = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("waiter must be woken by the freed slot");
        waited.unwrap().unwrap();
    }

    /// Once nothing is in flight each lane's `open` index lists exactly the
    /// stored connections that have room, each once, and every stored
    /// connection knows its lane.
    fn assert_open_matches_capacity(pool: &MultiplexPool<Conn, TestId>) {
        let storage = pool.storage.lock();
        for bucket in storage.by_id.values() {
            assert!(!bucket.is_empty());
            let lanes = std::iter::once((LaneKey::Unrestricted, &bucket.unrestricted)).chain(
                bucket
                    .keyed
                    .iter()
                    .zip(bucket.classes.iter())
                    .flat_map(|(lanes, class)| {
                        lanes.lanes.iter().map(|(key, lane)| {
                            (
                                LaneKey::Keyed(Box::new(KeyedLane {
                                    class: class.clone(),
                                    key: key.clone(),
                                })),
                                lane,
                            )
                        })
                    }),
            );
            for (key, lane) in lanes {
                assert!(key == LaneKey::Unrestricted || !lane.conns.is_empty());
                for conn in &lane.conns {
                    assert_eq!(conn.lane.lock().as_ref(), Some(&key));
                    let listed = lane.open.contains_key(&conn.seq);
                    assert_eq!(listed, conn.listed.load(Ordering::Relaxed), "{}", conn.seq);
                    assert_eq!(
                        listed,
                        conn.has_capacity(pool.max_concurrent_streams),
                        "connection {} is listed iff it has room",
                        conn.seq
                    );
                }
                assert!(lane.conns.windows(2).all(|w| w[0].seq < w[1].seq));
                assert!(
                    lane.open
                        .keys()
                        .all(|seq| lane.conns.iter().any(|conn| conn.seq == *seq))
                );
            }
            assert_eq!(bucket.classes.len(), bucket.keyed.len());
            for (class, lanes) in bucket.classes.iter().zip(&bucket.keyed) {
                assert_eq!(class.classifier(), &lanes.classifier);
                assert!(!lanes.lanes.is_empty());
            }
        }
    }

    async fn serial_of(handout: &MultiplexedConnection<Conn, TestId>) -> usize {
        handout.serve(ServiceInput::new(())).await.unwrap()
    }

    #[tokio::test]
    async fn selection_walks_idle_exclusive_connections_in_creation_order() {
        for (selection, expected) in [
            (MuxSelection::FirstAvailable, [0, 0, 0, 0, 0, 0]),
            (MuxSelection::LeastLoaded, [0, 0, 0, 0, 0, 0]),
            (MuxSelection::RoundRobin, [0, 1, 2, 3, 0, 1]),
        ] {
            let pool = MultiplexPool::try_new(1, 8)
                .unwrap()
                .with_selection(selection);
            let svc = connector(pool.clone());
            let mut held = Vec::new();
            for _ in 0..4 {
                held.push(connect(&svc, 0).await);
            }
            assert_eq!(created(&svc), 4);
            // Nothing has room, so the index is empty.
            assert!(
                pool.storage.lock().by_id[&TestId(0)]
                    .only_lane()
                    .open
                    .is_empty()
            );
            drop(held);
            assert_open_matches_capacity(&pool);

            let mut serials = Vec::new();
            for _ in 0..expected.len() {
                let handout = connect(&svc, 0).await;
                serials.push(serial_of(&handout.conn).await);
            }
            assert_eq!(serials, expected, "{selection:?}");
            assert_eq!(created(&svc), 4, "idle connections are reused");
            assert_open_matches_capacity(&pool);

            // Concurrent checkouts spread over distinct connections.
            let first = connect(&svc, 0).await;
            let second = connect(&svc, 0).await;
            assert_ne!(serial_of(&first.conn).await, serial_of(&second.conn).await);
            assert_eq!(created(&svc), 4);
            drop((first, second));
            assert_open_matches_capacity(&pool);
        }
    }

    #[tokio::test]
    async fn multiplexed_connection_stays_listed_until_full() {
        let pool = MultiplexPool::try_new(3, 4).unwrap();
        let svc = connector(pool.clone());
        let first = connect(&svc, 0).await;
        let second = connect(&svc, 0).await;
        assert!(pool.storage.lock().by_id[&TestId(0)].only_lane().open.len() == 1);
        let third = connect(&svc, 0).await;
        assert!(
            pool.storage.lock().by_id[&TestId(0)]
                .only_lane()
                .open
                .is_empty(),
            "the last stream slot unlists the connection"
        );
        drop(second);
        assert_eq!(
            pool.storage.lock().by_id[&TestId(0)].only_lane().open.len(),
            1
        );
        drop((first, third));
        assert_open_matches_capacity(&pool);
        assert_eq!(created(&svc), 1);
    }

    #[tokio::test]
    async fn released_connection_is_found_again_after_its_bucket_was_swept_empty() {
        let pool = MultiplexPool::try_new(1, 2).unwrap();
        let svc = connector(pool.clone());
        let held = connect(&svc, 0).await;
        held.conn
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .mark_broken();
        let mut doomed = Vec::new();
        pool.sweep_all(&mut pool.storage.lock(), &mut doomed);
        drop(doomed);
        assert!(pool.storage.lock().by_id.is_empty());
        // Releasing a retired connection must not resurrect it.
        drop(held);
        assert!(pool.storage.lock().by_id.is_empty());
        let fresh = connect(&svc, 0).await;
        assert_eq!(created(&svc), 2);
        drop(fresh);
        assert_open_matches_capacity(&pool);
    }

    #[tokio::test]
    async fn broken_listed_connection_is_retired_when_selected() {
        let pool = MultiplexPool::try_new(1, 8).unwrap();
        let svc = connector(pool.clone());
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(connect(&svc, 0).await);
        }
        held[1]
            .conn
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .mark_broken();
        drop(held);

        // Serials 0 and 2 serve; the broken 1 sits between them and is retired
        // when selected, not handed out.
        let a = connect(&svc, 0).await;
        let b = connect(&svc, 0).await;
        assert_eq!(serial_of(&a.conn).await, 0);
        assert_eq!(serial_of(&b.conn).await, 2);
        assert_eq!(created(&svc), 3);
        drop((a, b));
        let bucket_len = pool.storage.lock().by_id[&TestId(0)].conns().count();
        assert_eq!(bucket_len, 2);
        assert_open_matches_capacity(&pool);
    }

    #[tokio::test(start_paused = true)]
    async fn cold_idle_connections_are_reaped_while_a_hot_one_serves() {
        let pool = MultiplexPool::try_new(1, 8)
            .unwrap()
            .with_idle_timeout(Duration::from_secs(4));
        let svc = connector(pool.clone());
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(connect(&svc, 0).await);
        }
        drop(held);

        // Only the earliest connection is ever selected, so the others are
        // never looked at by a checkout. The bucket's own sweep reaps them.
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(600)).await;
            let handout = connect(&svc, 0).await;
            assert_eq!(serial_of(&handout.conn).await, 0);
        }
        assert_eq!(pool.storage.lock().by_id[&TestId(0)].conns().count(), 1);
        assert_eq!(pool.total_slots.available_permits(), 7);
        assert_eq!(created(&svc), 4);
        assert_open_matches_capacity(&pool);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_checkouts_keep_the_open_index_consistent() {
        for selection in [
            MuxSelection::FirstAvailable,
            MuxSelection::LeastLoaded,
            MuxSelection::RoundRobin,
        ] {
            let pool = MultiplexPool::try_new(1, 12)
                .unwrap()
                .with_selection(selection);
            let svc = Arc::new(connector(pool.clone()));
            let mut tasks = Vec::new();
            for task in 0..32 {
                let svc = svc.clone();
                tasks.push(tokio::spawn(async move {
                    for round in 0..300 {
                        let handout = connect(&svc, 0).await;
                        if (round + task) % 3 == 0 {
                            tokio::task::yield_now().await;
                        }
                        drop(handout);
                    }
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
            // A checkout racing a release can evict the connection that just went
            // idle and dial another, so `created` may exceed the limit; what is
            // stored may not, and every slot must be accounted for.
            let storage = pool.storage.lock();
            let stored: Vec<_> = storage.by_id[&TestId(0)].conns().collect();
            assert!(stored.len() <= 12);
            assert_eq!(
                pool.total_slots.available_permits(),
                12 - stored.len(),
                "no slot leaked ({selection:?})"
            );
            for conn in stored {
                assert_eq!(conn.active.load(Ordering::Relaxed), 0);
            }
            drop(storage);
            assert_open_matches_capacity(&pool);
        }
    }

    #[test]
    fn virtual_conn_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<MultiplexedConnection<Conn, TestId>>();
        fn assert_pool<P: Pool<Conn, TestId>>() {}
        assert_pool::<MultiplexPool<Conn, TestId>>();
    }
}
