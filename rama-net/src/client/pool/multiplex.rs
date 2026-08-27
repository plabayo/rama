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

use super::{ConnID, ConnectionResult, Pool, PoolSlot};
use crate::conn::{ConnectionHealth, ConnectionHealthWatcher, MaxConcurrency};
use parking_lot::Mutex;
use rama_core::Service;
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorExt};
use rama_core::extensions::{Extension, Extensions, ExtensionsRef, NetExtension};
use rama_core::futures::StreamExt as _;
use rama_core::futures::stream::FuturesUnordered;
use rama_core::telemetry::tracing::trace;
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
    notify: Arc<Notify>,
    last_idle: AtomicInstant,
    _pool_slot: PoolSlot,
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
    ) -> Option<MultiplexedConnection<C, ID>> {
        let limit = self.effective_capacity(cap);
        let mut active = self.active.load(Ordering::Relaxed);
        loop {
            if active >= limit {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(MultiplexedConnection {
                        inner: self.clone(),
                    });
                }
                Err(found) => active = found,
            }
        }
    }
}

/// A cheap handle to a shared connection in a [`MultiplexPool`].
///
/// It implements [`Service`] by forwarding to the inner connection and counts as
/// one of the connection's in-flight streams for its lifetime, the stream is
/// released on drop.
pub struct MultiplexedConnection<C, ID> {
    inner: Arc<StoredConnection<C, ID>>,
}

impl<C, ID> Drop for MultiplexedConnection<C, ID> {
    fn drop(&mut self) {
        let prev = self.inner.active.fetch_sub(1, Ordering::Release);
        if prev == 1 {
            // last in-flight stream released: the connection just went idle
            self.inner.last_idle.set_now();
        }
        // wake any waiters so they can re-check capacity on this connection
        self.inner.notify.notify_waiters();
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
    Input: Send + 'static,
{
    type Output = C::Output;
    type Error = C::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
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

/// Connection pool that multiplexes concurrent users over shared
/// connections.
pub struct MultiplexPool<C, ID> {
    storage: Arc<Mutex<Vec<Arc<StoredConnection<C, ID>>>>>,
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
            storage: Arc::new(Mutex::new(Vec::with_capacity(max_total.get()))),
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
    /// Drop connections that are no longer eligible for handout: idle past the
    /// idle timeout, or marked broken (in-flight streams keep a broken
    /// connection alive via the outstanding handles, but it is no longer
    /// handed out). Every handout path must sweep before selecting.
    fn sweep(&self, storage: &mut Vec<Arc<StoredConnection<C, ID>>>) {
        if let Some(idle_timeout) = self.idle_timeout {
            storage.retain(|conn| {
                let drop = conn.is_idle() && conn.last_idle.elapsed() >= idle_timeout;
                if drop {
                    trace!(id = ?conn.id, "multiplex pool: dropping idle connection");
                }
                !drop
            });
        }

        storage.retain(|conn| {
            let broken = conn
                .conn
                .extensions()
                .get_ref::<ConnectionHealthWatcher>()
                .is_some_and(|watcher| watcher.health() == ConnectionHealth::Broken);
            if broken {
                trace!(id = ?conn.id, "multiplex pool: dropping broken connection");
            }
            !broken
        });
    }

    /// Turn a freshly acquired total-slot permit into a handout: prefer reusing
    /// a same-id connection that freed capacity in the meantime (dropping the
    /// permit releases the slot and wakes the next queued waiter), otherwise
    /// return the permit as a create permit.
    fn admit_with_permit(
        &self,
        id: &ID,
        permit: OwnedSemaphorePermit,
    ) -> ConnectionResult<MultiplexedConnection<C, ID>, PoolSlot> {
        let mut storage = self.storage.lock();
        self.sweep(&mut storage);
        if let Some(conn) = select_and_admit(
            &storage,
            id,
            self.selection,
            &self.rr_cursor,
            self.max_concurrent_streams,
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
    ) -> Result<ConnectionResult<Self::Connection, Self::CreatePermit>, BoxError> {
        #[cfg(feature = "opentelemetry")]
        let metrics = self
            .metrics
            .as_ref()
            .map(|metrics| (metrics, metrics.attributes(id)));
        #[cfg(feature = "opentelemetry")]
        let start = Instant::now();

        // On success returns the connection/permit, when want_caps = true
        // and we find no connections for the given ID, return a FuturesUnordered
        // set of which the futures resolve when connections for the given ID
        // have capacity changes.
        let attempt =
            |want_cap_changes: bool| -> Result<ConnectionResult<_, _>, FuturesUnordered<_>> {
                let mut storage = self.storage.lock();
                self.sweep(&mut storage);

                // Subscribe to same-id capacity changes BEFORE the capacity
                // check below (subscribe-then-check): the watch cursor only
                // observes `MaxConcurrency` raises (e.g. h2 SETTINGS) sent
                // after it was created, so subscribing after the check would
                // lose a raise landing in between, parking the waiter with no
                // wake-up.
                let cap_changes: FuturesUnordered<_> = if want_cap_changes {
                    storage
                        .iter()
                        .filter(|conn| &conn.id == id)
                        .filter_map(|conn| conn.max_concurrency.clone())
                        .map(|mc| {
                            let mut changed = mc.watch();
                            async move { changed.changed().await }
                        })
                        .collect()
                } else {
                    FuturesUnordered::new()
                };

                if let Some(conn) = select_and_admit(
                    &storage,
                    id,
                    self.selection,
                    &self.rr_cursor,
                    self.max_concurrent_streams,
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

                let saturation = storage.iter().any(|conn| &conn.id == id);

                // Claim a fresh connection slot, evicting the least-recently-used idle
                // connection (any id) if the pool is at its total capacity.
                let pool_slot = if let Ok(permit) = self.total_slots.clone().try_acquire_owned() {
                    Some(PoolSlot(permit))
                } else {
                    let lru_idle = storage
                        .iter()
                        .enumerate()
                        .filter(|(_, conn)| conn.is_idle())
                        .min_by_key(|(_, conn)| conn.last_idle.as_nanos())
                        .map(|(pos, _)| pos);
                    if let Some(pos) = lru_idle {
                        storage.remove(pos);
                        #[cfg(feature = "opentelemetry")]
                        if let Some((metrics, attrs)) = &metrics {
                            metrics.evicted_connections.add(1, attrs);
                        }
                        self.total_slots
                            .clone()
                            .try_acquire_owned()
                            .ok()
                            .map(PoolSlot)
                    } else {
                        None
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

                Err(cap_changes)
            };

        loop {
            // Fast path: try without registering as a waiter (no caps needed).
            if let Ok(result) = attempt(false) {
                return Ok(result);
            }

            // Saturated. Register as a waiter, and then re-check. This order is important
            // to make sure we don't miss a notify while our check logic is running
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let mut cap_changes = match attempt(true) {
                Ok(result) => return Ok(result),
                Err(cap_changes) => cap_changes,
            };

            trace!(?id, "multiplex pool: saturated, waiting for capacity");
            // Wake on a release/create notify, on a same-id connection's
            // capacity increase (its `MaxConcurrency` changing), or on a freed
            // total slot. The semaphore is the only wake-up for slots released
            // outside a handout drop (e.g. a failed create dropping its
            // permit), and being a real queued acquire it also cannot lose the
            // permit to the notify-before-release window of a handout drop.
            tokio::select! {
                _ = notified => {}
                _ = cap_changes.next(), if !cap_changes.is_empty() => {}
                permit = self.total_slots.clone().acquire_owned() => {
                    let Ok(permit) = permit else {
                        // the pool never closes its semaphore; treat as spurious
                        continue;
                    };
                    match self.admit_with_permit(id, permit) {
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

    async fn create(&self, id: ID, conn: C, pool_slot: PoolSlot) -> Self::Connection {
        let conn = Arc::new(StoredConnection {
            max_concurrency: conn.extensions().get_arc::<MaxConcurrency>(),
            conn,
            id,
            active: AtomicUsize::new(1),
            notify: self.notify.clone(),
            last_idle: AtomicInstant::now(),
            _pool_slot: pool_slot,
        });

        trace!(id = ?conn.id, "multiplex pool: adding new connection");
        self.storage.lock().push(conn.clone());

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

        MultiplexedConnection { inner: conn }
    }
}

/// Select a same-id connection that still has capacity and admit a stream on it
/// (see [`StoredConnection::try_create_multiplexed`]), returning a ready handout.
fn select_and_admit<C, ID: PartialEq>(
    storage: &[Arc<StoredConnection<C, ID>>],
    id: &ID,
    selection: MuxSelection,
    rr_cursor: &AtomicUsize,
    cap: usize,
) -> Option<MultiplexedConnection<C, ID>> {
    let same_id = |conn: &&Arc<StoredConnection<C, ID>>| &conn.id == id;
    let has_capacity = |conn: &&Arc<StoredConnection<C, ID>>| {
        same_id(conn) && conn.active.load(Ordering::Relaxed) < conn.effective_capacity(cap)
    };
    let create_conn = |conn: &Arc<StoredConnection<C, ID>>| conn.try_create_multiplexed(cap);

    match selection {
        // Admit on the first same-id connection that accepts a stream.
        MuxSelection::FirstAvailable => storage.iter().filter(same_id).find_map(create_conn),
        // Admit on the least-loaded (fewest active) same-id connection.
        MuxSelection::LeastLoaded => storage
            .iter()
            .filter(has_capacity)
            .min_by_key(|conn| conn.active.load(Ordering::Relaxed))
            .and_then(create_conn),
        MuxSelection::RoundRobin => {
            let count = storage.iter().filter(has_capacity).count();
            if count == 0 {
                None
            } else {
                let idx = rr_cursor.fetch_add(1, Ordering::Relaxed) % count;
                storage
                    .iter()
                    .filter(has_capacity)
                    .nth(idx)
                    .and_then(create_conn)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::PooledConnector;
    use super::*;
    use crate::client::{
        ConnectionError, ConnectionErrorDomain, ConnectionErrorKind, ConnectorService,
        EstablishedClientConnection,
    };
    use rama_core::ServiceInput;
    use std::convert::Infallible;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestId(u32);
    impl ConnID for TestId {}

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

    impl Service<()> for Conn {
        type Output = usize;
        type Error = Infallible;

        async fn serve(&self, (): ()) -> Result<Self::Output, Self::Error> {
            Ok(self.serial)
        }
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
            assert_eq!(h.conn.serve(()).await.unwrap(), 0);
        }
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

        let mut waiter = tokio_test::task::spawn(pool.get_conn(&TestId(0)));
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
            std::task::Poll::Ready(Ok(ConnectionResult::Connection(_))) => {}
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
        assert_eq!(c3.conn.serve(()).await.unwrap(), 1);
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
        assert_eq!(c3.conn.serve(()).await.unwrap(), 1);

        // the in-flight handles still work on the (removed but alive) connection
        assert_eq!(c1.conn.serve(()).await.unwrap(), 0);
        assert_eq!(c2.conn.serve(()).await.unwrap(), 0);

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
            c5.conn.serve(()).await.unwrap(),
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
            c5.conn.serve(()).await.unwrap(),
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
        assert_eq!(c1.conn.serve(()).await.unwrap(), 0);
        assert_eq!(c2.conn.serve(()).await.unwrap(), 1);
        assert_eq!(c3.conn.serve(()).await.unwrap(), 2);
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

    /// A create permit dropped by a failed connect must wake a parked waiter
    /// (through the slots semaphore) instead of stranding it until the pool
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

    /// The freed-slot admission path must apply the same broken/idle sweep as
    /// the regular attempt path: a same-id connection that broke (and gained
    /// free capacity) while a waiter was parked must not be handed out when a
    /// freed permit wakes that waiter.
    #[tokio::test]
    async fn permit_admission_sweeps_broken_connections() {
        let pool = MultiplexPool::try_new(2, 2).unwrap();
        let svc = connector(pool.clone());

        // Connection A (serial 0) for id 0, with free capacity (1 of 2), broken.
        let c_a = connect(&svc, 0).await;
        c_a.conn
            .extensions()
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .mark_broken();

        let permit = pool.total_slots.clone().try_acquire_owned().unwrap();
        match pool.admit_with_permit(&TestId(0), permit) {
            ConnectionResult::CreatePermit(_) => {}
            ConnectionResult::Connection(_) => {
                panic!("freed-slot admission handed out a broken connection")
            }
        }

        // Healthy counterpart: a same-id connection with free capacity is reused.
        let c_b = connect(&svc, 1).await;
        drop(c_a);
        let permit = pool.total_slots.clone().try_acquire_owned().unwrap();
        match pool.admit_with_permit(&TestId(1), permit) {
            ConnectionResult::Connection(conn) => {
                assert_eq!(
                    conn.serve(()).await.unwrap(),
                    c_b.conn.serve(()).await.unwrap()
                );
            }
            ConnectionResult::CreatePermit(_) => {
                panic!("healthy same-id connection with free capacity must be reused")
            }
        }
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
