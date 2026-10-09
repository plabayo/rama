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

use super::{
    ConnID, ConnectionAdmission, ConnectionAdmissionLease, ConnectionResult, ConnectionReuse, Pool,
    PoolSlot,
};
use crate::conn::{ConnectionHealth, ConnectionHealthWatcher, MaxConcurrency};
use ahash::{HashMap, HashMapExt as _};
use parking_lot::Mutex;
use rama_core::Service;
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorExt};
use rama_core::extensions::{Extension, Extensions, ExtensionsMut, ExtensionsRef, NetExtension};
use rama_core::futures::StreamExt as _;
use rama_core::futures::stream::FuturesUnordered;
use rama_core::telemetry::tracing::trace;
use rama_utils::collections::smallvec::SmallVec;
use rama_utils::macros::generate_set_and_with;
use rama_utils::time::AtomicInstant;
use std::fmt::Debug;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::futures::OwnedNotified;
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
    max_concurrency: Option<Arc<MaxConcurrency>>,
    admission: Option<ConnectionAdmission>,
    active: AtomicUsize,
    capacity_notify: Arc<Notify>,
    notify: Arc<Notify>,
    last_idle: AtomicInstant,
    pool_slot: Mutex<ConnectionSlot>,
}

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

    /// Admit a new in-flight stream (while `active < limit`) and bind it to a
    /// [`MultiplexedConnection`] in one step, so `active` is never incremented
    /// without a handout to release it on drop. Returns `None` at capacity.
    ///
    /// Takes `&Arc<Self>` (not `&self`) since the handout needs to share the
    /// `Arc`; `&Arc<Self>` as a method receiver is still unstable.
    fn try_create_multiplexed(
        self: &Arc<Self>,
        cap: usize,
        input: &Extensions,
    ) -> Option<MultiplexedConnection<C, ID>>
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
        if slot.retired
            || broken
            || self.active.load(Ordering::Relaxed) >= self.effective_capacity(cap)
        {
            return None;
        }
        // Admission is serialized with retirement. Concurrent lease drops only
        // decrease the count, so no compare/exchange loop is needed here.
        self.active.fetch_add(1, Ordering::Relaxed);
        drop(slot);
        Some(MultiplexedConnection {
            inner: self.clone(),
            admission,
        })
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
        let prev = self.inner.active.fetch_sub(1, Ordering::Release);
        if prev == 1 {
            self.inner.last_idle.set_now();
            if self.inner.in_use_unleased() {
                // Evictable only once that work ends: every waiter subscribes to it,
                // so none depends on another one staying to pass the news on.
                self.inner.notify.notify_waiters();
            } else {
                // An idle connection is globally evictable, so a waiter for any
                // ID can make progress by claiming its pool slot.
                self.inner.notify.notify_one();
            }
        }
        // One released handout creates one unit of capacity for this exact
        // connection ID. Wake one compatible waiter without broadcasting to
        // unrelated IDs.
        self.inner.capacity_notify.notify_one();
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

/// Same-id connections in establish order: appended on create and only ever
/// removed in place, so the last one is the newest. Recency for eviction is the
/// `last_idle` timestamp, not this position, so nothing reorders on use.
type Bucket<C, ID> = Vec<Arc<StoredConnection<C, ID>>>;

/// Same-id connections copied out of storage so selection and waiter
/// registration run without holding the storage lock.
type Snapshot<C, ID> = SmallVec<[Arc<StoredConnection<C, ID>>; 4]>;

/// Connections grouped by id, so a handout only touches its own bucket and
/// the lock is never held for a scan of the whole pool.
struct Storage<C, ID> {
    by_id: HashMap<ID, Bucket<C, ID>>,
    pending: HashMap<ID, CreateEntry>,
}

impl<C, ID: ConnID> Storage<C, ID> {
    fn create_entry(&mut self, id: &ID) -> &mut CreateEntry {
        self.pending
            .entry(id.clone())
            .or_insert_with(|| CreateEntry {
                in_flight: 0,
                parked: 0,
                gate: Arc::new(Notify::new()),
            })
    }

    fn release_in_flight(&mut self, id: &ID) {
        if let Some(entry) = self.pending.get_mut(id) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
        }
        self.prune_pending(id);
    }

    fn release_parked(&mut self, id: &ID) {
        if let Some(entry) = self.pending.get_mut(id) {
            entry.parked = entry.parked.saturating_sub(1);
        }
        self.prune_pending(id);
    }

    fn prune_pending(&mut self, id: &ID) {
        if let Some(entry) = self.pending.get(id)
            && entry.in_flight == 0
            && entry.parked == 0
        {
            self.pending.remove(id);
        }
    }
}

/// Connections being established for one id, and the requests waiting for them.
///
/// Only ids that multiplex get an entry, dropped once both counts reach zero.
struct CreateEntry {
    in_flight: usize,
    parked: usize,
    gate: Arc<Notify>,
}

/// Its drop is the only thing that wakes the requests parked on this
/// connection, so it must outlive every way an establish can end.
struct CreateGuard<C, ID: ConnID> {
    storage: Arc<Mutex<Storage<C, ID>>>,
    id: ID,
    gate: Arc<Notify>,
}

impl<C, ID: ConnID> Drop for CreateGuard<C, ID> {
    fn drop(&mut self) {
        self.storage.lock().release_in_flight(&self.id);
        // Notify outside the lock: every waiter registered its subscription
        // while holding it, so none can be missed here.
        self.gate.notify_waiters();
    }
}

/// Keeps a cancelled request from leaving `parked` overstating demand. Wakes
/// nobody: one fewer waiter creates no capacity.
struct WaiterGuard<'a, C, ID: ConnID> {
    storage: Arc<Mutex<Storage<C, ID>>>,
    id: &'a ID,
}

impl<C, ID: ConnID> Drop for WaiterGuard<'_, C, ID> {
    fn drop(&mut self) {
        self.storage.lock().release_parked(self.id);
    }
}

/// Permit to establish one connection for an id, plus the registration that
/// requests parked on it are waiting for.
pub struct MuxCreatePermit<C, ID: ConnID> {
    slot: PoolSlot,
    pending: Option<CreateGuard<C, ID>>,
}

impl<C, ID: ConnID> Debug for MuxCreatePermit<C, ID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxCreatePermit")
            .field("id", &self.pending.as_ref().map(|pending| &pending.id))
            .finish()
    }
}

/// Connection pool that multiplexes concurrent users over shared
/// connections.
pub struct MultiplexPool<C, ID> {
    storage: Arc<Mutex<Storage<C, ID>>>,
    total_slots: Arc<Semaphore>,
    idle_timeout: Option<Duration>,
    max_concurrent_streams: usize,
    cold_stream_capacity: NonZeroUsize,
    selection: MuxSelection,
    rr_cursor: Arc<AtomicUsize>,
    notify: Arc<Notify>,
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
            .field("cold_stream_capacity", &self.cold_stream_capacity)
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
            cold_stream_capacity: self.cold_stream_capacity,
            selection: self.selection,
            rr_cursor: self.rr_cursor.clone(),
            notify: self.notify.clone(),
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
                pending: HashMap::new(),
            })),
            total_slots: Arc::new(Semaphore::new(max_total.get())),
            idle_timeout: None,
            max_concurrent_streams: max_concurrent_streams.get(),
            cold_stream_capacity: NonZeroUsize::MIN,
            selection: MuxSelection::default(),
            rr_cursor: Arc::new(AtomicUsize::new(0)),
            notify: Arc::new(Notify::new()),
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
        /// the given timeout. Only checked when a connection is requested.
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

    generate_set_and_with! {
        /// How many streams to assume a new connection will hold for an id that
        /// has no connection yet, so a burst against a cold id can also wait for
        /// one connection being established instead of each request establishing
        /// its own.
        ///
        /// This is a per-connection stream count, not a number of connections.
        /// `1` (the default) assumes no multiplexing and keeps every request
        /// establishing its own, which is the only safe assumption when the
        /// protocol is still unknown: expecting a shared connection and then
        /// negotiating HTTP/1 costs the whole burst a wasted handshake. Raise it
        /// when the origins are known to multiplex.
        ///
        /// Once a connection exists, what it advertises is used instead, so this
        /// only ever applies to the first requests for an id.
        pub fn cold_stream_capacity(mut self, capacity: NonZeroUsize) -> Self {
            self.cold_stream_capacity = capacity;
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

    /// Move ineligible connections out of `bucket` into `doomed`, so their
    /// sockets close once the caller has released the storage lock.
    fn sweep_bucket(&self, bucket: &mut Bucket<C, ID>, doomed: &mut Bucket<C, ID>) {
        let mut i = 0;
        while i < bucket.len() {
            if self.is_eligible(&bucket[i]) {
                i += 1;
            } else {
                bucket[i].pool_slot.lock().retired = true;
                doomed.push(bucket.remove(i));
            }
        }
    }

    /// Sweep the bucket for `id` and copy out what is left. Every handout path
    /// must go through this before selecting.
    fn snapshot(
        &self,
        storage: &mut Storage<C, ID>,
        id: &ID,
        doomed: &mut Bucket<C, ID>,
    ) -> Snapshot<C, ID> {
        let Some(bucket) = storage.by_id.get_mut(id) else {
            return Snapshot::new();
        };
        self.sweep_bucket(bucket, doomed);
        if bucket.is_empty() {
            storage.by_id.remove(id);
            return Snapshot::new();
        }
        bucket.iter().cloned().collect()
    }

    /// Sweep every bucket. Slow path only: it frees pool slots held by stale
    /// connections of other ids before falling back to LRU eviction.
    fn sweep_all(&self, storage: &mut Storage<C, ID>, doomed: &mut Bucket<C, ID>) {
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
        let (id, pos, slot) = {
            let mut candidate = None;
            let mut oldest = u64::MAX;
            for (id, bucket) in &storage.by_id {
                for (pos, conn) in bucket.iter().enumerate() {
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
                    candidate = Some((id, pos, slot));
                }
            }
            let (id, pos, mut slot) = candidate?;
            slot.retired = true;
            (id.clone(), pos, slot.permit.take())
        };
        let bucket = storage.by_id.get_mut(&id)?;
        let evicted = bucket.remove(pos);
        if bucket.is_empty() {
            storage.by_id.remove(&id);
        }
        Some((evicted, slot))
    }

    /// Subscribe to everything that could give this id capacity.
    ///
    /// Callers subscribe BEFORE checking capacity (subscribe-then-check), so a
    /// release or SETTINGS raise landing between the two cannot be lost.
    fn subscriptions(
        same_id: &Snapshot<C, ID>,
    ) -> Waits<impl Future<Output = Option<usize>> + use<C, ID>> {
        Waits {
            stream_capacity: same_id
                .iter()
                .map(|conn| {
                    let mut notified = Box::pin(conn.capacity_notify.clone().notified_owned());
                    notified.as_mut().enable();
                    notified
                })
                .collect(),
            cap_changes: same_id
                .iter()
                .filter_map(|conn| conn.max_concurrency.clone())
                .map(|mc| {
                    let mut changed = mc.watch();
                    async move { changed.changed().await }
                })
                .collect(),
            admission_changes: same_id
                .iter()
                .filter_map(|conn| conn.admission.as_ref().map(ConnectionAdmission::watch))
                // A candidate going broken is swept on the next look, which may free a slot.
                .chain(same_id.iter().filter_map(|conn| {
                    let mut changed = conn
                        .conn
                        .extensions()
                        .get_ref::<ConnectionHealthWatcher>()?
                        .watch();
                    let changed: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                        _ = changed.changed().await;
                    });
                    Some(changed)
                }))
                .collect(),
        }
    }

    /// Streams the next connection for this id is expected to hold and be able
    /// to share. 0 or 1 means it does not multiplex, so each request establishes
    /// its own connection.
    fn estimated_stream_capacity(
        &self,
        id: &ID,
        same_id: &[Arc<StoredConnection<C, ID>>],
    ) -> usize {
        if !id.is_reusable() {
            // Never retained, so none of its streams can be shared.
            return 0;
        }
        match same_id.last() {
            Some(newest) => newest.effective_capacity(self.max_concurrent_streams),
            None => self.cold_stream_capacity.get(),
        }
    }

    fn register_create(&self, id: &ID) -> CreateGuard<C, ID> {
        let gate = {
            let mut storage = self.storage.lock();
            let entry = storage.create_entry(id);
            entry.in_flight += 1;
            entry.gate.clone()
        };
        CreateGuard {
            storage: self.storage.clone(),
            id: id.clone(),
            gate,
        }
    }

    /// Decide whether this request establishes a connection for `id` or waits
    /// for one already being established.
    ///
    /// Decided and registered under one lock, or a burst would have every
    /// request conclude it is the one that should connect.
    ///
    /// A new connection frees `capacity - 1` streams for requests other than the
    /// one that established it, so counting the parked requests sizes a burst in
    /// one pass instead of one connection per round trip.
    fn register_or_park<'a>(
        &self,
        id: &'a ID,
        same_id: &Snapshot<C, ID>,
        want_cap_changes: bool,
    ) -> Establish<'a, C, ID> {
        let capacity = self.estimated_stream_capacity(id, same_id);
        if capacity <= 1 {
            return Establish::Now(None);
        }
        let mut storage = self.storage.lock();
        // Parking only ever finds an entry that already exists, so it looks the
        // id up instead of cloning it into one.
        if let Some(entry) = storage.pending.get_mut(id) {
            let allowed = (entry.parked + 1).div_ceil(capacity - 1);
            if entry.in_flight >= allowed {
                if !want_cap_changes {
                    return Establish::Retry;
                }
                entry.parked += 1;
                // Subscribe under the lock a finishing establish needs before it
                // can notify, so one landing between this check and the park
                // cannot be missed.
                let mut gate = Box::pin(entry.gate.clone().notified_owned());
                gate.as_mut().enable();
                let waiter = WaiterGuard {
                    storage: self.storage.clone(),
                    id,
                };
                drop(storage);
                trace!(
                    ?id,
                    capacity, "multiplex pool: waiting for a connection being established"
                );
                return Establish::Wait { gate, waiter };
            }
        }
        let entry = storage.create_entry(id);
        entry.in_flight += 1;
        let gate = entry.gate.clone();
        drop(storage);
        Establish::Now(Some(CreateGuard {
            storage: self.storage.clone(),
            id: id.clone(),
            gate,
        }))
    }

    /// Claim a slot for one more connection: a free one, else one freed by
    /// sweeping stale connections of any id, else the least-recently-used idle
    /// connection's.
    ///
    /// Subscribes `waits` to connections that are not evictable yet only because
    /// work outlived their handouts, before looking for a victim, so a caller
    /// that finds none is woken when one appears.
    fn claim_pool_slot<F>(
        &self,
        want_cap_changes: bool,
        waits: &mut Waits<F>,
        doomed: &mut Bucket<C, ID>,
        telemetry: &Telemetry<'_>,
    ) -> Option<PoolSlot> {
        if let Ok(permit) = self.total_slots.clone().try_acquire_owned() {
            return Some(PoolSlot(permit));
        }

        // Stale connections of other ids may hold slots: sweep them out, then
        // let their permits flow back through the semaphore (to the oldest
        // queued waiter, if any) before evicting.
        self.sweep_all(&mut self.storage.lock(), doomed);
        doomed.clear();
        if let Ok(permit) = self.total_slots.clone().try_acquire_owned() {
            return Some(PoolSlot(permit));
        }

        let mut storage = self.storage.lock();
        if want_cap_changes {
            // Subscribed before eviction looks: a connection whose handouts are
            // gone becomes evictable once its remaining work ends.
            waits.admission_changes.extend(
                storage
                    .by_id
                    .values()
                    .flatten()
                    .filter(|conn| {
                        conn.active.load(Ordering::Relaxed) == 0 && conn.in_use_unleased()
                    })
                    .filter_map(|conn| conn.admission.as_ref().map(ConnectionAdmission::watch)),
            );
        }
        let (evicted, slot) = Self::evict_lru_idle(&mut storage)?;
        drop(storage);
        drop(evicted);
        telemetry.evicted();
        // The evicted connection's permit is transferred rather than released to
        // the semaphore queue, so evicting makes progress without stealing a
        // permit that was released for the oldest queued waiter.
        slot
    }

    /// Turn a fairly acquired total-slot permit into a handout. Reuse a
    /// same-id connection if capacity became available while waiting;
    /// otherwise return the permit for creating a connection.
    fn admit_with_permit(
        &self,
        id: &ID,
        permit: OwnedSemaphorePermit,
        input: &Extensions,
    ) -> ConnectionResult<MultiplexedConnection<C, ID>, MuxCreatePermit<C, ID>> {
        let mut doomed = Vec::new();
        let mut same_id = if id.is_reusable() {
            self.snapshot(&mut self.storage.lock(), id, &mut doomed)
        } else {
            Snapshot::new()
        };
        drop(doomed);
        same_id.retain(|conn| {
            conn.conn
                .extensions()
                .get_ref::<ConnectionReuse>()
                .is_none_or(|policy| policy.matches(input))
        });
        if let Some(conn) = select_and_admit(
            &same_id,
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
            return ConnectionResult::Connection(conn);
        }
        trace!(
            ?id,
            "multiplex pool: freed slot acquired, returning create permit"
        );
        let pending =
            (self.estimated_stream_capacity(id, &same_id) > 1).then(|| self.register_create(id));
        ConnectionResult::CreatePermit(MuxCreatePermit {
            slot: PoolSlot(permit),
            pending,
        })
    }
}

/// What a checkout that found no free stream should do about connections already
/// being established for its id.
enum Establish<'a, C, ID: ConnID> {
    /// Establish one. Carries the registration when the id multiplexes, so
    /// concurrent requests can wait for it rather than establish their own.
    Now(Option<CreateGuard<C, ID>>),
    /// Enough are already being established for this burst; wait on the gate.
    Wait {
        gate: Pin<Box<OwnedNotified>>,
        waiter: WaiterGuard<'a, C, ID>,
    },
    /// Would wait, but the caller asked without subscribing first.
    Retry,
}

/// Everything a saturated checkout parks on, so a wake re-checks as soon as any
/// of it could have made room.
///
/// `cap_changes` is generic because [`Changed::changed`] is an `async fn` whose
/// future has no name: boxing it would allocate per candidate on every look.
struct Waits<F> {
    /// A stream slot released on a same-id connection.
    stream_capacity: FuturesUnordered<Pin<Box<OwnedNotified>>>,
    /// A same-id connection raising its advertised concurrency.
    cap_changes: FuturesUnordered<F>,
    /// Transport credit returning, a candidate going broken, or a connection
    /// becoming evictable. Also carries the gate of a connection being
    /// established, which a parked request is woken by.
    admission_changes: FuturesUnordered<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl<F: Future<Output = Option<usize>>> Waits<F> {
    fn empty() -> Self {
        Self {
            stream_capacity: FuturesUnordered::new(),
            cap_changes: FuturesUnordered::new(),
            admission_changes: FuturesUnordered::new(),
        }
    }

    /// Resolves once any subscription fires, and never when there are none, so
    /// the caller needs a branch of its own that can still make progress.
    async fn changed(&mut self) {
        tokio::select! {
            _ = self.stream_capacity.next(), if !self.stream_capacity.is_empty() => {}
            _ = self.cap_changes.next(), if !self.cap_changes.is_empty() => {}
            _ = self.admission_changes.next(), if !self.admission_changes.is_empty() => {}
            else => std::future::pending::<()>().await,
        }
    }
}

/// Metrics for one [`Pool::get_conn`] call, so its body carries no feature
/// gates. Without the `opentelemetry` feature every method is a no-op.
#[cfg(feature = "opentelemetry")]
struct Telemetry<'a> {
    metrics: Option<(
        &'a Arc<metrics::PoolMetrics>,
        Vec<rama_core::telemetry::opentelemetry::KeyValue>,
    )>,
    start: Instant,
}

#[cfg(feature = "opentelemetry")]
impl<'a> Telemetry<'a> {
    fn new<C, ID: ConnID>(pool: &'a MultiplexPool<C, ID>, id: &ID) -> Self {
        Self {
            metrics: pool
                .metrics
                .as_ref()
                .map(|metrics| (metrics, metrics.attributes(id))),
            start: Instant::now(),
        }
    }

    /// `coalesced` tells a reuse that waited for somebody else's connection
    /// apart from one served by a stream simply freeing up.
    fn reused(&self, active: impl FnOnce() -> usize, coalesced: bool) {
        let Some((metrics, attrs)) = &self.metrics else {
            return;
        };
        let active = active();
        if coalesced {
            metrics.coalesced_creates.add(1, attrs);
        }
        metrics.reused_connections.add(1, attrs);
        metrics.streams.add(1, attrs);
        metrics.concurrent_streams.record(active as f64, attrs);
        self.record_delay(metrics, attrs);
    }

    fn create_permit(&self, saturation: bool) {
        let Some((metrics, attrs)) = &self.metrics else {
            return;
        };
        if saturation {
            metrics.saturation_created_connections.add(1, attrs);
        }
        self.record_delay(metrics, attrs);
    }

    fn evicted(&self) {
        if let Some((metrics, attrs)) = &self.metrics {
            metrics.evicted_connections.add(1, attrs);
        }
    }

    fn record_delay(
        &self,
        metrics: &metrics::PoolMetrics,
        attrs: &[rama_core::telemetry::opentelemetry::KeyValue],
    ) {
        metrics
            .active_connection_delay_nanoseconds
            .record(self.start.elapsed().as_nanos() as f64, attrs);
    }
}

#[cfg(not(feature = "opentelemetry"))]
struct Telemetry<'a>(std::marker::PhantomData<&'a ()>);

#[cfg(not(feature = "opentelemetry"))]
#[expect(
    clippy::unused_self,
    reason = "mirrors the opentelemetry flavour so callers need no feature gates"
)]
impl<'a> Telemetry<'a> {
    fn new<C, ID: ConnID>(_pool: &'a MultiplexPool<C, ID>, _id: &ID) -> Self {
        Self(std::marker::PhantomData)
    }

    fn reused(&self, _active: impl FnOnce() -> usize, _coalesced: bool) {}

    fn create_permit(&self, _saturation: bool) {}

    fn evicted(&self) {}
}

impl<C, ID> Pool<C, ID> for MultiplexPool<C, ID>
where
    C: Send + Sync + ExtensionsRef + 'static,
    ID: ConnID,
{
    type Connection = MultiplexedConnection<C, ID>;
    type CreatePermit = MuxCreatePermit<C, ID>;

    async fn get_conn(
        &self,
        id: &ID,
        input: &Extensions,
    ) -> Result<ConnectionResult<Self::Connection, Self::CreatePermit>, BoxError> {
        let telemetry = Telemetry::new(self, id);

        // One look at the pool. On failure hands back what to wait on, plus the
        // parked registration when this request is waiting for a connection
        // somebody else is establishing. `want_cap_changes` is the
        // subscribe-then-check pass; the first look skips subscribing.
        let attempt = |want_cap_changes: bool,
                       coalesced: bool|
         -> Result<
            ConnectionResult<_, _>,
            (Waits<_>, Option<WaiterGuard<'_, C, ID>>),
        > {
            // Only this id's bucket is touched under the lock; swept
            // connections close after it is released.
            let mut doomed = Vec::new();
            let mut same_id = if id.is_reusable() {
                self.snapshot(&mut self.storage.lock(), id, &mut doomed)
            } else {
                Snapshot::new()
            };
            doomed.clear();
            same_id.retain(|conn| {
                conn.conn
                    .extensions()
                    .get_ref::<ConnectionReuse>()
                    .is_none_or(|policy| policy.matches(input))
            });

            let mut waits = if want_cap_changes {
                Self::subscriptions(&same_id)
            } else {
                Waits::empty()
            };

            if let Some(conn) = select_and_admit(
                &same_id,
                id,
                self.selection,
                &self.rr_cursor,
                self.max_concurrent_streams,
                input,
            ) {
                trace!(?id, "multiplex pool: reusing connection");
                telemetry.reused(|| conn.inner.active.load(Ordering::Relaxed), coalesced);
                return Ok(ConnectionResult::Connection(conn));
            }

            let saturation = !same_id.is_empty();

            let pending = match self.register_or_park(id, &same_id, want_cap_changes) {
                Establish::Now(pending) => pending,
                Establish::Wait { gate, waiter } => {
                    waits.admission_changes.push(gate);
                    return Err((waits, Some(waiter)));
                }
                // Registering now would count this request twice, since the
                // caller retries immediately with subscriptions.
                Establish::Retry => return Err((waits, None)),
            };

            let pool_slot =
                self.claim_pool_slot(want_cap_changes, &mut waits, &mut doomed, &telemetry);

            if let Some(pool_slot) = pool_slot {
                trace!(
                    ?id,
                    "multiplex pool: no connection with capacity, returning create permit"
                );
                telemetry.create_permit(saturation);
                return Ok(ConnectionResult::CreatePermit(MuxCreatePermit {
                    slot: pool_slot,
                    pending,
                }));
            }

            // No slot at all: give up the registration (outside the lock, which
            // the ladder above has already released) so nobody stays parked
            // waiting for a connection that is never established.
            drop(pending);
            Err((waits, None))
        };

        // Keep one semaphore acquisition alive across unrelated capacity
        // notifications. Recreating it after every wake would cancel and
        // requeue this waiter at the back, violating the semaphore's FIFO
        // admission and allowing a busy connection to starve it indefinitely.
        let mut total_slot_wait = Box::pin(self.total_slots.clone().acquire_owned());

        let mut coalesced = false;
        loop {
            // Fast path: try without registering as a waiter (no caps needed).
            if let Ok(result) = attempt(false, coalesced) {
                return Ok(result);
            }

            // Saturated. Register as a waiter, and then re-check. This order is important
            // to make sure we don't miss a notify while our check logic is running
            let mut notified = std::pin::pin!(self.notify.notified());
            notified.as_mut().enable();
            let (mut waits, waiter) = match attempt(true, coalesced) {
                Ok(result) => return Ok(result),
                Err(waits) => waits,
            };
            // A gated request must not spend a slot on the very connection it is
            // waiting for. Skipping the branch rather than dropping the permit
            // keeps the FIFO position above.
            let gated = waiter.is_some();
            // Waiting on somebody else's connection is what makes a later reuse
            // a coalesced one rather than a freed stream.
            coalesced |= gated;

            trace!(
                ?id,
                gated, "multiplex pool: saturated, waiting for capacity"
            );
            // Queue on the semaphore for FIFO total-slot admission. LRU
            // eviction transfers its slot directly, so it never releases a
            // permit that a queued waiter can take from the evicting caller.
            tokio::select! {
                _ = notified => {}
                _ = waits.changed() => {}
                permit = &mut total_slot_wait, if !gated => {
                    let Ok(permit) = permit else {
                        // the pool never closes its semaphore; treat as spurious
                        continue;
                    };
                    match self.admit_with_permit(id, permit, input) {
                        ConnectionResult::Connection(conn) => {
                            telemetry.reused(
                                || conn.inner.active.load(Ordering::Relaxed),
                                coalesced,
                            );
                            return Ok(ConnectionResult::Connection(conn));
                        }
                        ConnectionResult::CreatePermit(pool_slot) => {
                            telemetry.create_permit(false);
                            return Ok(ConnectionResult::CreatePermit(pool_slot));
                        }
                    }
                }
            }
        }
    }

    async fn create(
        &self,
        id: ID,
        conn: C,
        create_permit: MuxCreatePermit<C, ID>,
        input: &Extensions,
    ) -> Result<Self::Connection, BoxError> {
        let MuxCreatePermit {
            slot: pool_slot,
            pending,
        } = create_permit;
        // The establishing request owns the first reservation before concurrent
        // checkouts can see this connection in storage.
        let admission = match conn.extensions().self_get_ref::<ConnectionAdmission>() {
            Some(provider) => Some(provider.acquire(input).await?),
            None => None,
        };
        let reusable = id.is_reusable()
            && conn
                .extensions()
                .get_ref::<ConnectionReuse>()
                .is_none_or(ConnectionReuse::is_reusable);
        let conn = Arc::new(StoredConnection {
            max_concurrency: conn.extensions().get_arc::<MaxConcurrency>(),
            admission: conn
                .extensions()
                .self_get_ref::<ConnectionAdmission>()
                .cloned(),
            conn,
            id,
            active: AtomicUsize::new(1),
            capacity_notify: Arc::new(Notify::new()),
            notify: self.notify.clone(),
            last_idle: AtomicInstant::now(),
            pool_slot: Mutex::new(ConnectionSlot {
                permit: Some(pool_slot),
                retired: false,
            }),
        });

        trace!(id = ?conn.id, "multiplex pool: adding new connection");
        if reusable {
            self.storage
                .lock()
                .by_id
                .entry(conn.id.clone())
                .or_default()
                .push(conn.clone());
        }

        // A freshly added connection has spare capacity beyond its establishing
        // handout, so make sure to wake parked waiters. Requests parked on this
        // this connection specifically are woken by the guard, which is only
        // released once the connection they waited for is in storage.
        self.notify.notify_waiters();
        drop(pending);

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
    same_id: &[Arc<StoredConnection<C, ID>>],
    id: &ID,
    selection: MuxSelection,
    rr_cursor: &AtomicUsize,
    cap: usize,
    input: &Extensions,
) -> Option<MultiplexedConnection<C, ID>> {
    debug_assert!(same_id.iter().all(|conn| &conn.id == id), "{id:?}");
    let has_capacity = |conn: &Arc<StoredConnection<C, ID>>| {
        conn.active.load(Ordering::Relaxed) < conn.effective_capacity(cap)
    };
    let preferred = match selection {
        MuxSelection::FirstAvailable => None,
        MuxSelection::LeastLoaded => same_id
            .iter()
            .enumerate()
            .filter(|(_, conn)| has_capacity(conn))
            .min_by_key(|(_, conn)| conn.active.load(Ordering::Relaxed))
            .map(|(index, _)| index),
        MuxSelection::RoundRobin => {
            let count = same_id.iter().filter(|conn| has_capacity(conn)).count();
            if count == 0 {
                return None;
            }
            let position = rr_cursor.fetch_add(1, Ordering::Relaxed) % count;
            same_id
                .iter()
                .enumerate()
                .filter(|(_, conn)| has_capacity(conn))
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
        let conn = &same_id[index];
        if has_capacity(conn)
            && let Some(handout) = conn.try_create_multiplexed(cap, input)
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
    use std::assert_matches;
    use std::{
        convert::Infallible,
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
        changed: Arc<Notify>,
        storage: Weak<Mutex<Storage<Conn, TestId>>>,
    }

    impl AdmissionState {
        fn set_limit(&self, limit: usize) {
            self.limit.store(limit, Ordering::SeqCst);
            self.changed.notify_waiters();
        }

        fn set_in_use(&self, in_use: bool) {
            self.in_use.store(in_use, Ordering::SeqCst);
            self.changed.notify_waiters();
        }
    }

    #[derive(Debug)]
    struct FakeAdmission(Arc<AdmissionState>);

    #[derive(Debug)]
    struct Reservation(Arc<AdmissionState>);

    impl Drop for Reservation {
        fn drop(&mut self) {
            self.0.reserved.fetch_sub(1, Ordering::SeqCst);
            self.0.changed.notify_waiters();
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

        fn watch(&self) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
            let mut changed = Box::pin(self.0.changed.clone().notified_owned());
            changed.as_mut().enable();
            changed
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
            changed: Arc::new(Notify::new()),
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

    async fn new_slot(pool: &MultiplexPool<Conn, TestId>) -> MuxCreatePermit<Conn, TestId> {
        match pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap() {
            ConnectionResult::CreatePermit(permit) => permit,
            ConnectionResult::Connection(_) => panic!("expected an empty pool"),
        }
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
    async fn every_waiter_learns_of_work_outliving_the_last_handout() {
        let pool = MultiplexPool::try_new(32, 1).unwrap();
        let permit = new_slot(&pool).await;
        let (conn, state) = admission_connection(&pool, 4);
        let input = Extensions::new();
        let first = pool.create(TestId(0), conn, permit, &input).await.unwrap();
        // Both wait while the connection is leased, so neither watches its work yet.
        let mut leaving = tokio_test::task::spawn(pool.get_conn(&TestId(1), &EMPTY_INPUT));
        let mut staying = tokio_test::task::spawn(pool.get_conn(&TestId(2), &EMPTY_INPUT));
        assert!(leaving.poll().is_pending());
        assert!(staying.poll().is_pending());

        state.set_in_use(true);
        drop(first);
        assert!(leaving.is_woken() && staying.is_woken());
        assert!(leaving.poll().is_pending());
        assert!(staying.poll().is_pending());
        drop(leaving);

        state.set_in_use(false);
        assert!(
            staying.is_woken(),
            "a waiter that left took the news with it"
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

            fn watch(&self) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
                self.inner.watch()
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
            changed: Arc::new(Notify::new()),
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
        max_concurrency: Option<usize>,
    }

    impl SlowConnector {
        fn new(delay: Duration) -> Self {
            Self {
                created: AtomicUsize::new(0),
                delay,
                max_concurrency: None,
            }
        }

        fn with_max_concurrency(mut self, max_concurrency: usize) -> Self {
            self.max_concurrency = Some(max_concurrency);
            self
        }
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
            if let Some(mc) = self.max_concurrency {
                conn.extensions.insert(MaxConcurrency::new(mc));
            }
            Ok(EstablishedClientConnection { input, conn })
        }
    }

    type SlowMuxConnector = PooledConnector<
        SlowConnector,
        MultiplexPool<Conn, TestId>,
        fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
    >;

    fn slow_connector(
        pool: MultiplexPool<Conn, TestId>,
        connector: SlowConnector,
    ) -> SlowMuxConnector {
        PooledConnector::new(
            connector,
            pool,
            id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
        )
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

    #[tokio::test]
    async fn permit_wakeup_rechecks_compatibility_outside_storage_lock() {
        #[derive(Debug)]
        struct RejectReuse(Weak<Mutex<Storage<Conn, TestId>>>);

        impl ConnectionReusePolicy for RejectReuse {
            fn matches(&self, _: &Extensions) -> bool {
                let storage = self.0.upgrade().unwrap();
                assert!(
                    storage.try_lock().is_some(),
                    "connector policy must not run under the pool lock"
                );
                false
            }
        }

        let pool = MultiplexPool::try_new(4, 2).unwrap();
        let svc = connector(pool.clone());
        let held = connect(&svc, 0).await;
        held.conn
            .extensions()
            .insert(ConnectionReuse::new(RejectReuse(Arc::downgrade(
                &pool.storage,
            ))));
        let permit = pool.total_slots.clone().try_acquire_owned().unwrap();
        let mut waiter = tokio_test::task::spawn(pool.get_conn(&TestId(0), &EMPTY_INPUT));
        assert!(waiter.poll().is_pending());

        // Only the total-slot semaphore wakes this waiter. Its admission path
        // must recheck the established policy before selecting spare capacity.
        drop(permit);
        assert!(waiter.is_woken());
        assert_matches!(
            waiter.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_))),
        );
    }

    #[tokio::test]
    async fn policy_check_cannot_admit_a_connection_marked_broken_during_the_check() {
        #[derive(Debug)]
        struct CloseDuringMatch {
            health: Arc<ConnectionHealthWatcher>,
            enabled: Arc<AtomicBool>,
        }

        impl ConnectionReusePolicy for CloseDuringMatch {
            fn matches(&self, _: &Extensions) -> bool {
                if !self.enabled.load(Ordering::Relaxed) {
                    return false;
                }
                self.health.mark_broken();
                true
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
                let svc = connector(pool.clone());
                let held = connect(&svc, 0).await;
                let health = held
                    .conn
                    .extensions()
                    .get_arc::<ConnectionHealthWatcher>()
                    .unwrap();
                let enabled = Arc::new(AtomicBool::new(!after_wait));
                held.conn
                    .extensions()
                    .insert(ConnectionReuse::new(CloseDuringMatch {
                        health,
                        enabled: enabled.clone(),
                    }));
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
            fn matches(&self, _: &Extensions) -> bool {
                if self.evict {
                    let removed = MultiplexPool::evict_lru_idle(&mut self.pool.storage.lock());
                    assert!(removed.is_some());
                    drop(removed);
                } else {
                    let mut doomed = Vec::new();
                    {
                        let mut storage = self.pool.storage.lock();
                        storage.by_id[&TestId(0)][0]
                            .conn
                            .extensions()
                            .get_ref::<ConnectionHealthWatcher>()
                            .unwrap()
                            .mark_broken();
                        self.pool.sweep_all(&mut storage, &mut doomed);
                    }
                    drop(doomed);
                }
                true
            }
        }

        for evict in [false, true] {
            let pool = MultiplexPool::try_new(4, 1).unwrap();
            let svc = connector(pool.clone());
            let held = connect(&svc, 0).await;
            held.conn
                .extensions()
                .insert(ConnectionReuse::new(RetireDuringMatch {
                    pool: pool.clone(),
                    evict,
                }));
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
        let mut snapshot = pool.snapshot(&mut pool.storage.lock(), &TestId(0), &mut doomed);
        let (retired, transferred_slot) =
            MultiplexPool::evict_lru_idle(&mut pool.storage.lock()).unwrap();
        let retired_index = snapshot
            .iter()
            .position(|conn| Arc::ptr_eq(conn, &retired))
            .unwrap();
        snapshot.swap(0, retired_index);
        // Retain the transferred permit as an unrelated establish would, so it
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
        let stored = Arc::clone(&pool.storage.lock().by_id[&TestId(0)][0]);

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

    /// A `MaxConcurrency` raise must wake a parked `get_conn` with no other
    /// wake source and no scheduling slack: the waiter is driven by hand, and
    /// the raise happens right after the parking poll. The waiter subscribes
    /// to the capacity watch under the storage lock BEFORE its capacity check
    /// (subscribe-then-check), so a raise is either seen by the check or wakes
    /// the watch cursor — a raise landing in between (e.g. an h2 SETTINGS
    /// update on another thread) can never be lost.
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

        // Raise A's capacity; the watch subscription made while parking must fire.
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
        let svc = slow_connector(pool, SlowConnector::new(Duration::from_millis(100)))
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

    /// Hold every stream of the only connection for `id`, so the next checkout
    /// has to create.
    async fn saturate(
        svc: &SlowMuxConnector,
        id: u32,
        streams: usize,
    ) -> Vec<EstablishedClientConnection<MultiplexedConnection<Conn, TestId>, ServiceInput<u32>>>
    {
        let mut held = Vec::with_capacity(streams);
        for _ in 0..streams {
            held.push(svc.connect(ServiceInput::new(id)).await.unwrap());
        }
        held
    }

    #[tokio::test(start_paused = true)]
    async fn saturated_burst_shares_one_new_connection() {
        let pool = MultiplexPool::try_new(10, 10).unwrap();
        let svc = slow_connector(pool, SlowConnector::new(Duration::from_millis(100)));

        let _held = saturate(&svc, 0, 10).await;
        assert_eq!(created_slow(&svc), 1, "the first 10 streams share one conn");

        let burst = rama_core::futures::future::join_all(
            (0..8).map(|_| svc.connect(ServiceInput::new(0u32))),
        )
        .await;
        for conn in &burst {
            assert!(conn.is_ok(), "every request in the burst must be served");
        }

        assert_eq!(
            created_slow(&svc),
            2,
            "a burst on a saturated id must wait for one new connection, not open one each"
        );
    }

    /// The http/1 shape: a second connection is the only way to get concurrency.
    #[tokio::test(start_paused = true)]
    async fn capacity_one_burst_still_connects_per_request() {
        let pool = MultiplexPool::try_new(10, 10).unwrap();
        let svc = slow_connector(
            pool,
            SlowConnector::new(Duration::from_millis(100)).with_max_concurrency(1),
        );

        let _held = saturate(&svc, 0, 1).await;
        assert_eq!(created_slow(&svc), 1);

        let burst = rama_core::futures::future::join_all(
            (0..8).map(|_| svc.connect(ServiceInput::new(0u32))),
        )
        .await;
        for conn in &burst {
            assert!(conn.is_ok());
        }

        assert_eq!(
            created_slow(&svc),
            9,
            "capacity 1 cannot be shared, so every request must get its own connection"
        );
    }

    fn created_slow(svc: &SlowMuxConnector) -> usize {
        svc.inner.created.load(Ordering::Relaxed)
    }

    #[tokio::test(start_paused = true)]
    async fn burst_opens_the_capacity_deficit_in_one_pass() {
        const HANDSHAKE: Duration = Duration::from_millis(100);

        let pool = MultiplexPool::try_new(3, 10).unwrap();
        let svc = slow_connector(pool, SlowConnector::new(HANDSHAKE));

        let _held = saturate(&svc, 0, 3).await;
        assert_eq!(created_slow(&svc), 1);

        let start = tokio::time::Instant::now();
        let burst = rama_core::futures::future::join_all(
            (0..8).map(|_| svc.connect(ServiceInput::new(0u32))),
        )
        .await;
        for conn in &burst {
            assert!(conn.is_ok());
        }

        assert!(
            start.elapsed() < HANDSHAKE * 2,
            "the connections a burst needs must open together, not one handshake after another"
        );
        assert_eq!(
            created_slow(&svc),
            4,
            "8 requests over capacity 3 need 3 more connections"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cold_burst_is_not_gated_by_default() {
        let pool = MultiplexPool::try_new(10, 10).unwrap();
        let svc = slow_connector(pool, SlowConnector::new(Duration::from_millis(100)));

        let burst = rama_core::futures::future::join_all(
            (0..8).map(|_| svc.connect(ServiceInput::new(0u32))),
        )
        .await;
        for conn in &burst {
            assert!(conn.is_ok());
        }

        assert_eq!(
            created_slow(&svc),
            8,
            "without an estimate a cold id cannot be assumed to multiplex"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cold_stream_capacity_shares_a_cold_burst() {
        let pool = MultiplexPool::try_new(10, 10)
            .unwrap()
            .with_cold_stream_capacity(NonZeroUsize::new(10).unwrap());
        let svc = slow_connector(pool, SlowConnector::new(Duration::from_millis(100)));

        let burst = rama_core::futures::future::join_all(
            (0..8).map(|_| svc.connect(ServiceInput::new(0u32))),
        )
        .await;
        for conn in &burst {
            assert!(conn.is_ok());
        }

        assert_eq!(created_slow(&svc), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_advertised_zero_capacity_overrides_the_cold_estimate() {
        let pool = MultiplexPool::try_new(10, 10)
            .unwrap()
            .with_cold_stream_capacity(NonZeroUsize::new(10).unwrap());
        let svc = slow_connector(
            pool,
            SlowConnector::new(Duration::from_millis(100)).with_max_concurrency(0),
        );

        let first = svc.connect(ServiceInput::new(0u32)).await.unwrap();
        let second = svc.connect(ServiceInput::new(0u32)).await.unwrap();
        drop((first, second));

        assert_eq!(
            created_slow(&svc),
            2,
            "a zero-capacity connection cannot be shared, so the next request connects"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn failed_establish_wakes_parked_waiters() {
        struct FailingConnector {
            attempts: AtomicUsize,
        }

        impl Service<ServiceInput<u32>> for FailingConnector {
            type Output = EstablishedClientConnection<Conn, ServiceInput<u32>>;
            type Error = ConnectionError;

            async fn serve(&self, _: ServiceInput<u32>) -> Result<Self::Output, Self::Error> {
                self.attempts.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(50)).await;
                Err(ConnectionError::transport(
                    BoxError::from_static_str("connect fails"),
                    ConnectionErrorKind::Unavailable,
                ))
            }
        }

        // A reusable connection exists and is full, so the burst is gated; every
        // connect then fails, and only the guard's drop can release the waiters.
        let pool = MultiplexPool::try_new(10, 10).unwrap();
        let seed = slow_connector(pool.clone(), SlowConnector::new(Duration::ZERO));
        let _held = saturate(&seed, 0, 10).await;

        let svc = PooledConnector::new(
            FailingConnector {
                attempts: AtomicUsize::new(0),
            },
            pool,
            id_fn as fn(&ServiceInput<u32>) -> Result<TestId, BoxError>,
        )
        .with_wait_for_pool_timeout(Duration::from_secs(120));

        let burst = tokio::time::timeout(
            Duration::from_secs(5),
            rama_core::futures::future::join_all(
                (0..3).map(|_| svc.connect(ServiceInput::new(0u32))),
            ),
        )
        .await
        .expect("a failed establish must release the requests parked on it");

        for conn in &burst {
            assert!(conn.is_err(), "every request fails once the connect fails");
        }
        assert_eq!(
            svc.inner.attempts.load(Ordering::Relaxed),
            3,
            "each woken request must get to connect for itself"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_waiter_leaves_no_pending_entry() {
        let pool = MultiplexPool::try_new(10, 10).unwrap();
        let svc = slow_connector(pool.clone(), SlowConnector::new(Duration::from_millis(100)));

        let held = saturate(&svc, 0, 10).await;

        // Box::pin, not pin!: dropping the spawn must drop the future itself,
        // since that is what releases the registration under test.
        let mut establishing =
            tokio_test::task::spawn(Box::pin(svc.connect(ServiceInput::new(0u32))));
        assert!(
            establishing.poll().is_pending(),
            "the connection is still being established"
        );

        let mut parked = tokio_test::task::spawn(Box::pin(svc.connect(ServiceInput::new(0u32))));
        assert!(
            parked.poll().is_pending(),
            "parked on the pending connection"
        );
        assert_eq!(pool.storage.lock().pending[&TestId(0)].parked, 1);

        drop(parked);
        assert_eq!(
            pool.storage.lock().pending[&TestId(0)].parked,
            0,
            "a cancelled request must not keep counting as demand"
        );

        drop(establishing);
        drop(held);
        assert!(
            pool.storage.lock().pending.is_empty(),
            "nothing pending and nobody parked leaves no entry behind"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn non_reusable_id_is_never_gated() {
        let pool = MultiplexPool::try_new(10, 10)
            .unwrap()
            .with_cold_stream_capacity(NonZeroUsize::new(10).unwrap());
        let svc = slow_connector(pool, SlowConnector::new(Duration::from_millis(100)));

        let burst = rama_core::futures::future::join_all(
            (0..4).map(|_| svc.connect(ServiceInput::new(u32::MAX))),
        )
        .await;
        for conn in &burst {
            assert!(conn.is_ok());
        }

        assert_eq!(
            created_slow(&svc),
            4,
            "a connection that is never retained leaves nothing to wait for"
        );
    }

    /// A peer that lowers its advertised limit must size the next burst by the
    /// lowered value, not by what an older connection was granted.
    #[tokio::test(start_paused = true)]
    async fn a_lowered_advertised_limit_sizes_the_next_burst() {
        const HANDSHAKE: Duration = Duration::from_millis(100);

        let pool = MultiplexPool::try_new(100, 20).unwrap();
        let svc = slow_connector(pool, SlowConnector::new(HANDSHAKE).with_max_concurrency(3));

        // An older connection granted 100 streams, all of them in use.
        let first = svc.connect(ServiceInput::new(0u32)).await.unwrap();
        let advertised = |conn: &EstablishedClientConnection<
            MultiplexedConnection<Conn, TestId>,
            ServiceInput<u32>,
        >| {
            conn.conn
                .extensions()
                .get_arc::<MaxConcurrency>()
                .expect("the test connector advertises one")
        };
        advertised(&first).set(100);
        let _held = (first, saturate(&svc, 0, 99).await);

        // The origin has since dropped to 3 streams per connection.
        let newest = svc.connect(ServiceInput::new(0u32)).await.unwrap();
        assert_eq!(created_slow(&svc), 2, "the full connection forced a second");
        let before = created_slow(&svc);

        let start = tokio::time::Instant::now();
        let burst = rama_core::futures::future::join_all(
            (0..8).map(|_| svc.connect(ServiceInput::new(0u32))),
        )
        .await;
        for conn in &burst {
            assert!(conn.is_ok());
        }
        drop(newest);

        // Planning against the stale 100 would open one connection for all 8 and
        // then need further round trips; the newest limit of 3 sizes it in one.
        assert!(
            start.elapsed() < HANDSHAKE * 2,
            "a stale limit left the burst short of connections"
        );
        assert_eq!(created_slow(&svc) - before, 2);
    }

    #[test]
    fn virtual_conn_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<MultiplexedConnection<Conn, TestId>>();
        fn assert_pool<P: Pool<Conn, TestId>>() {}
        assert_pool::<MultiplexPool<Conn, TestId>>();
    }
}
