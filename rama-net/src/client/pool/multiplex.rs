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
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    max_concurrency: Option<Arc<MaxConcurrency>>,
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
    /// A connection is idle when none of its handouts are in flight.
    fn is_idle(&self) -> bool {
        self.active.load(Ordering::Relaxed) == 0
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
        let admission = match self.conn.extensions().get_ref::<ConnectionAdmission>() {
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
            // last in-flight stream released: the connection just went idle
            self.inner.last_idle.set_now();
            // An idle connection is globally evictable, so a waiter for any
            // ID can make progress by claiming its pool slot.
            self.inner.notify.notify_one();
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

type Bucket<C, ID> = Vec<Arc<StoredConnection<C, ID>>>;

/// Same-id connections copied out of storage so selection and waiter
/// registration run without holding the storage lock.
type Snapshot<C, ID> = SmallVec<[Arc<StoredConnection<C, ID>>; 4]>;

/// Connections grouped by id, so a handout only touches its own bucket and
/// the lock is never held for a scan of the whole pool.
struct Storage<C, ID> {
    by_id: HashMap<ID, Bucket<C, ID>>,
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
            })),
            total_slots: Arc::new(Semaphore::new(max_total.get())),
            idle_timeout: None,
            max_concurrent_streams: max_concurrent_streams.get(),
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
                    if !conn.is_idle() || last_idle >= oldest {
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

    /// Turn a fairly acquired total-slot permit into a handout. Reuse a
    /// same-id connection if capacity became available while waiting;
    /// otherwise return the permit for creating a connection.
    fn admit_with_permit(
        &self,
        id: &ID,
        permit: OwnedSemaphorePermit,
        input: &Extensions,
    ) -> ConnectionResult<MultiplexedConnection<C, ID>, PoolSlot> {
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

        // On success returns the connection/permit, when want_caps = true
        // and we find no connections for the given ID, return subscriptions
        // for stream-slot releases and advertised capacity changes on the
        // matching connections.
        let attempt = |want_cap_changes: bool| -> Result<
            ConnectionResult<_, _>,
            (
                FuturesUnordered<_>,
                FuturesUnordered<_>,
                FuturesUnordered<_>,
            ),
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

            // Subscribe to same-id notifications BEFORE the capacity
            // check below (subscribe-then-check), so a handout release or
            // SETTINGS raise landing between both cannot be lost.
            let stream_capacity: FuturesUnordered<_> = if want_cap_changes {
                same_id
                    .iter()
                    .map(|conn| {
                        let mut notified = Box::pin(conn.capacity_notify.clone().notified_owned());
                        notified.as_mut().enable();
                        notified
                    })
                    .collect()
            } else {
                FuturesUnordered::new()
            };
            let cap_changes: FuturesUnordered<_> = if want_cap_changes {
                same_id
                    .iter()
                    .filter_map(|conn| conn.max_concurrency.clone())
                    .map(|mc| {
                        let mut changed = mc.watch();
                        async move { changed.changed().await }
                    })
                    .collect()
            } else {
                FuturesUnordered::new()
            };

            let admission_changes: FuturesUnordered<_> = if want_cap_changes {
                same_id
                    .iter()
                    .filter_map(|conn| {
                        conn.conn
                            .extensions()
                            .get_ref::<ConnectionAdmission>()
                            .map(ConnectionAdmission::watch)
                    })
                    .collect()
            } else {
                FuturesUnordered::new()
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
                return Ok(ConnectionResult::Connection(conn));
            }

            let saturation = !same_id.is_empty();

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

            if let Some(pool_slot) = pool_slot {
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
                return Ok(ConnectionResult::CreatePermit(pool_slot));
            }

            Err((stream_capacity, cap_changes, admission_changes))
        };

        // Keep one semaphore acquisition alive across unrelated capacity
        // notifications. Recreating it after every wake would cancel and
        // requeue this waiter at the back, violating the semaphore's FIFO
        // admission and allowing a busy connection to starve it indefinitely.
        let mut total_slot_wait = Box::pin(self.total_slots.clone().acquire_owned());

        loop {
            // Fast path: try without registering as a waiter (no caps needed).
            if let Ok(result) = attempt(false) {
                return Ok(result);
            }

            // Saturated. Register as a waiter, and then re-check. This order is important
            // to make sure we don't miss a notify while our check logic is running
            let mut notified = std::pin::pin!(self.notify.notified());
            notified.as_mut().enable();
            let (mut stream_capacity, mut cap_changes, mut admission_changes) = match attempt(true)
            {
                Ok(result) => return Ok(result),
                Err(cap_changes) => cap_changes,
            };

            trace!(?id, "multiplex pool: saturated, waiting for capacity");
            // Queue on the semaphore for FIFO total-slot admission. LRU
            // eviction transfers its slot directly, so it never releases a
            // permit that a queued waiter can take from the evicting caller.
            tokio::select! {
                _ = notified => {}
                _ = stream_capacity.next(), if !stream_capacity.is_empty() => {}
                _ = cap_changes.next(), if !cap_changes.is_empty() => {}
                _ = admission_changes.next(), if !admission_changes.is_empty() => {}
                permit = &mut total_slot_wait => {
                    let Ok(permit) = permit else {
                        // the pool never closes its semaphore; treat as spurious
                        continue;
                    };
                    match self.admit_with_permit(id, permit, input) {
                        ConnectionResult::Connection(conn) => {
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
                            return Ok(ConnectionResult::Connection(conn));
                        }
                        ConnectionResult::CreatePermit(pool_slot) => {
                            #[cfg(feature = "opentelemetry")]
                            if let Some((metrics, attrs)) = &metrics {
                                metrics
                                    .active_connection_delay_nanoseconds
                                    .record(start.elapsed().as_nanos() as f64, attrs);
                            }
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
        pool_slot: PoolSlot,
        input: &Extensions,
    ) -> Result<Self::Connection, BoxError> {
        // The establishing request owns the first reservation before concurrent
        // checkouts can see this connection in storage.
        let admission = match conn.extensions().get_ref::<ConnectionAdmission>() {
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
        changed: Arc<Notify>,
        storage: Weak<Mutex<Storage<Conn, TestId>>>,
    }

    impl AdmissionState {
        fn set_limit(&self, limit: usize) {
            self.limit.store(limit, Ordering::SeqCst);
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
    }

    fn admission_connection(
        pool: &MultiplexPool<Conn, TestId>,
        limit: usize,
    ) -> (Conn, Arc<AdmissionState>) {
        let state = Arc::new(AdmissionState {
            limit: AtomicUsize::new(limit),
            reserved: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
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

    async fn new_slot(pool: &MultiplexPool<Conn, TestId>) -> PoolSlot {
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
        assert!(matches!(
            pool.get_conn(&TestId(0), &EMPTY_INPUT).await.unwrap(),
            ConnectionResult::CreatePermit(_)
        ));
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
        assert!(matches!(
            waiter.poll(),
            Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
        ));
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
                assert!(
                    matches!(
                        waiter.poll(),
                        Poll::Ready(Ok(ConnectionResult::CreatePermit(_)))
                    ),
                    "a close reported during policy evaluation must not yield a broken connection"
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
            assert!(
                matches!(result, ConnectionResult::CreatePermit(_)),
                "a retired snapshot must not bypass health or pool capacity (evict={evict})"
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

    #[test]
    fn virtual_conn_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<MultiplexedConnection<Conn, TestId>>();
        fn assert_pool<P: Pool<Conn, TestId>>() {}
        assert_pool::<MultiplexPool<Conn, TestId>>();
    }
}
