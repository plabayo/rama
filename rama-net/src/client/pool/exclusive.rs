//! Exclusive single-use connection pool.
//!
//! [`LruDropPool`] hands out a [`LeasedConnection`] that the caller owns for the
//! duration of its use and that is returned to the pool on drop. Each pooled
//! connection serves a single user at a time.

use super::drain::ConnScope;
#[cfg(feature = "opentelemetry")]
use super::metrics;
use super::reuse::LaneKey;
use super::{
    ActiveSlot, ConnID, ConnectionAdmission, ConnectionAdmissionLease, ConnectionResult,
    ConnectionReuse, Pool, PoolSlot, ReuseKey,
};
use crate::address::SocketAddress;
use crate::client::ConnectionError;
use crate::conn::{ConnectionHealth, ConnectionHealthWatcher};
use crate::stream::Socket;
use lru_slab::LruSlab;
use parking_lot::Mutex;
use rama_core::Service;
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorContext, ErrorExt};
use rama_core::extensions::{Extension, Extensions, ExtensionsMut, ExtensionsRef};
use rama_core::telemetry::tracing::trace;
use rama_utils::collections::smallvec::SmallVec;
use rama_utils::{guard::DropGuard, macros::generate_set_and_with};
use std::fmt::Debug;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tokio::time::Instant;

/// [`LeasedConnection`] is a connection that is temporarily leased from a pool
///
/// It will be returned to the pool once dropped if the user didn't
/// take ownership of the connection `C` with [`LeasedConnection::into_connection()`].
/// [`LeasedConnection`]s are considered active pool connections until dropped or
/// ownership is taken of the internal connection.
pub struct LeasedConnection<C: ExtensionsRef, ID> {
    admission: Option<ConnectionAdmissionLease>,
    // Safety invariant: unless `pooled_conn_taken` is `true`, `pooled_conn`
    // holds a value that has been neither taken nor dropped.
    pooled_conn: ManuallyDrop<PooledConnection<C, ID>>,
    pooled_conn_taken: bool,
    active_slot: ActiveSlot,
    returner: ConnReturner<C, ID>,
    got_response: AtomicBool,
    failed_or_cancelled: AtomicBool,
    drop_connection_if_no_response: bool,
}

impl<C: ExtensionsRef, ID: ConnID> LeasedConnection<C, ID> {
    /// File this connection under new reuse requirements once it returns to
    /// the pool, such as an identity it authenticated after it was established.
    ///
    /// Also publishes `reuse` on the connection. Pools otherwise keep the
    /// requirements the connection was added with.
    pub fn rekey(&mut self, reuse: ConnectionReuse) {
        let pooled = &mut *self.pooled_conn;
        // Each rekey appends to the connection's extensions: none for no change.
        if pooled
            .conn
            .extensions()
            .get_ref::<ConnectionReuse>()
            .is_some_and(|filed| filed.is_same(&reuse))
        {
            return;
        }
        pooled.lane = LaneKey::of_connection(Some(&reuse)).filter(|_| pooled.id.is_reusable());
        pooled.conn.extensions().insert(reuse);
    }
}

impl<C: ExtensionsRef, ID> LeasedConnection<C, ID> {
    pub fn into_connection(mut self) -> C {
        // We cannot use ::into_inner as we still require a Drop impl as well, so
        // we assign pooled_conn_taken to true to avoid double-dropping.
        self.pooled_conn_taken = true;
        // SAFETY: `ManuallyDrop::take` requires that the slot is not used again.
        // `self` is owned here and `pooled_conn_taken` was `false` on entry (it
        // is only set here, and this consumes `self`), so by the field
        // invariant the value is live. The flag set above makes `Drop` skip the
        // slot, and nothing else reads it before `self` is dropped.
        unsafe { ManuallyDrop::take(&mut self.pooled_conn) }.conn
    }
}

impl<C: ExtensionsRef, ID> ExtensionsRef for LeasedConnection<C, ID> {
    fn extensions(&self) -> &Extensions {
        self.pooled_conn.extensions()
    }
}

/// A connection which is stored in a pool.
///
/// A ID is used to determine which connections can be used for a request.
/// This ID encodes all the details that make a connection unique/suitable for a request.
#[derive(ExtensionsRef)]
struct PooledConnection<C, ID> {
    #[extensions_ref]
    conn: C,
    id: ID,
    pool_slot: PoolSlot,
    /// On the runtime clock, as the multiplex pool's, so a paused clock drives idle expiry.
    last_used: Instant,
    /// Which requests may use the connection, `None` if it is dropped once
    /// returned. Read from [`ConnectionReuse`] once, when it is added.
    lane: Option<LaneKey>,
    /// The scope it runs in, if any: dropped once returned after its cancel.
    scope: Option<ConnScope>,
    /// Current idle slot, shared with the scope watcher. Only accessed under
    /// the storage lock; invalidated before any slot can be reused.
    idle_slot: Option<Arc<AtomicU32>>,
}

impl<C, ID> PooledConnection<C, ID> {
    /// Whether the scope it runs in is cancelled: it is never handed out again. Reads the
    /// scope, so call it outside the storage lock.
    fn observe_drain(&self) -> bool {
        self.scope.as_ref().is_some_and(ConnScope::observe)
    }

    /// Whether the scope it runs in was seen cancelled: safe under the storage lock.
    fn is_drained(&self) -> bool {
        self.scope.as_ref().is_some_and(ConnScope::is_drained)
    }
}

/// No idle slot: the connection is leased or has left the pool.
const NO_IDLE_SLOT: u32 = u32::MAX;

/// Indexed LRU storage: cancellation removes just its connection in O(1).
/// Slot numbers can be reused, so every removal invalidates the old owner's
/// shared slot before releasing the storage lock. Watchers read it under that
/// same lock, including when a connection has since been checked out/returned.
#[derive(Debug)]
struct IdleStorage<C, ID> {
    entries: LruSlab<PooledConnection<C, ID>>,
}

impl<C, ID> Default for IdleStorage<C, ID> {
    fn default() -> Self {
        Self {
            entries: LruSlab::new(),
        }
    }
}

impl<C, ID> IdleStorage<C, ID> {
    fn push_front(&mut self, conn: PooledConnection<C, ID>) {
        let index = self.entries.insert(conn);
        if let Some(slot) = &self.entries.peek(index).idle_slot {
            slot.store(index, Ordering::Relaxed);
        }
    }

    fn remove(&mut self, slot: u32) -> PooledConnection<C, ID> {
        let conn = self.entries.remove(slot);
        if let Some(slot) = &conn.idle_slot {
            slot.store(NO_IDLE_SLOT, Ordering::Relaxed);
        }
        conn
    }

    fn pop_back(&mut self) -> Option<PooledConnection<C, ID>> {
        Some(self.remove(self.entries.lru()?))
    }

    fn take_all(&mut self) -> Self {
        for (_, conn) in &self.entries {
            if let Some(slot) = &conn.idle_slot {
                slot.store(NO_IDLE_SLOT, Ordering::Relaxed);
            }
        }
        std::mem::take(self)
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = &PooledConnection<C, ID>> {
        self.entries.iter().map(|(_, conn)| conn)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len() as usize
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Connections out of the pool, dropped once the storage lock is released: a socket's
/// teardown and its scope's last reference both may run code.
type Doomed<C> = Vec<(C, Option<ConnScope>)>;

/// Connection pool that uses LRU to evict connections
///
/// A pooled connection follows the scope it runs in, the [`scope_context`] of its extensions:
/// in its graceful phase an idle connection closes at once and a leased one once returned,
/// while checkouts go on to dial new connections.
///
/// [`scope_context`]: rama_core::graceful::scope_context
pub struct LruDropPool<C, ID> {
    storage: Arc<Mutex<IdleStorage<C, ID>>>,
    retired: Arc<AtomicBool>,
    total_slots: Arc<Semaphore>,
    active_slots: Arc<Semaphore>,
    idle_timeout: Option<Duration>,
    returner: ConnReturner<C, ID>,
    reuse_strategy: ReuseStrategy,
    drop_connection_if_no_response: bool,
    #[cfg(feature = "opentelemetry")]
    metrics: Option<Arc<metrics::PoolMetrics>>,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub enum ReuseStrategy {
    #[default]
    FiFo,
    RoundRobin,
}

struct ConnReturner<C, ID> {
    weak_storage: Weak<Mutex<IdleStorage<C, ID>>>,
    retired: Arc<AtomicBool>,
}

impl<C, ID> Clone for ConnReturner<C, ID> {
    fn clone(&self) -> Self {
        Self {
            weak_storage: self.weak_storage.clone(),
            retired: self.retired.clone(),
        }
    }
}

impl<C, ID> ConnReturner<C, ID> {
    fn return_conn(&self, mut conn: PooledConnection<C, ID>) {
        if conn.lane.is_none() || self.retired.load(Ordering::Acquire) || conn.observe_drain() {
            return;
        }
        if let Some(storage) = self.weak_storage.upgrade() {
            let refused = {
                // Ensure correct ordering by locking storage before loading the
                // last used time.
                let mut storage = storage.lock();
                // Under the lock its watcher takes after setting the flag: one returned after
                // the cancel is never stored.
                if self.retired.load(Ordering::Acquire) || conn.is_drained() {
                    Some(conn)
                } else {
                    conn.last_used = Instant::now();
                    storage.push_front(conn);
                    None
                }
            };
            drop(refused);
        }
    }
}

impl<C, ID> Clone for LruDropPool<C, ID> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            retired: self.retired.clone(),
            total_slots: self.total_slots.clone(),
            active_slots: self.active_slots.clone(),
            returner: self.returner.clone(),
            idle_timeout: self.idle_timeout,
            reuse_strategy: self.reuse_strategy,
            drop_connection_if_no_response: self.drop_connection_if_no_response,
            #[cfg(feature = "opentelemetry")]
            metrics: self.metrics.clone(),
        }
    }
}

impl<C, ID> LruDropPool<C, ID> {
    pub fn try_new(max_active: usize, max_total: usize) -> Result<Self, BoxError> {
        if max_active == 0 || max_total == 0 {
            return Err(BoxError::from_static_str(
                "max_active or max_total of 0 will make this pool unusable",
            )
            .context_field("max_active", max_active)
            .context_field("max_total", max_total));
        }
        if max_active > max_total {
            return Err(BoxError::from_static_str(
                "max_active should be smaller or equal to max_total",
            )
            .context_field("max_active", max_active)
            .context_field("max_total", max_total));
        }
        if max_total > Semaphore::MAX_PERMITS {
            return Err(BoxError::from_static_str(
                "max_total should be at most tokio's Semaphore::MAX_PERMITS",
            )
            .context_field("max_total", max_total));
        }
        // Grows with the connections stored, not with the limit.
        let storage = Arc::new(Mutex::new(IdleStorage::default()));
        let weak_storage = Arc::downgrade(&storage);
        let retired = Arc::new(AtomicBool::new(false));
        Ok(Self {
            storage,
            retired: retired.clone(),
            returner: ConnReturner {
                weak_storage,
                retired,
            },
            total_slots: Arc::new(Semaphore::const_new(max_total)),
            active_slots: Arc::new(Semaphore::const_new(max_active)),
            idle_timeout: None,
            reuse_strategy: ReuseStrategy::default(),
            drop_connection_if_no_response: true,
            #[cfg(feature = "opentelemetry")]
            metrics: None,
        })
    }

    /// Retire this pool generation and close every idle connection.
    ///
    /// Connections that are currently leased are closed when returned. New
    /// acquisitions fail, including acquisitions through another clone of
    /// this pool.
    pub fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        // take, not clear: the sockets and scopes go after the lock is released
        let idle = self.storage.lock().take_all();
        drop(idle);
    }

    generate_set_and_with! {
        /// If connections have been idle for longer then the provided timeout they
        /// will be dropped and removed from the pool
        ///
        /// Note: timeout is only checked when a connection is requested from the pool,
        /// it is not something that is done periodically
        pub fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.idle_timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        pub fn reuse_strategy(mut self, strategy: ReuseStrategy) -> Self {
            self.reuse_strategy = strategy;
            self
        }
    }

    generate_set_and_with! {
        /// If enabled (the default), connections that did not receive a response
        /// will be evicted from the pool instead of being returned for reuse.
        ///
        /// This includes timeouts, cancellations, and errors.
        pub fn drop_connection_if_no_response(mut self, drop_connection_if_no_response: bool) -> Self {
            self.drop_connection_if_no_response = drop_connection_if_no_response;
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

impl<C: ExtensionsRef, ID: ConnID> LruDropPool<C, ID> {
    /// Take the most preferred stored connection of `id` whose lane serves
    /// `input`.
    ///
    /// Request keys are derived outside the storage lock, once per classifier
    /// the scan meets. Connections stay in storage meanwhile, in their place
    /// in the LRU order and visible to concurrent checkouts. Each rescan
    /// follows a newly derived classifier or a removed broken connection,
    /// which bounds the loop.
    fn take_compatible(
        &self,
        id: &ID,
        input: &Extensions,
        doomed: &mut Doomed<C>,
    ) -> Option<(u32, PooledConnection<C, ID>)> {
        if !id.is_reusable() {
            return None;
        }
        let mut wanted: SmallVec<[(ReuseKey, Option<ReuseKey>); 2]> = SmallVec::new();
        loop {
            let mut storage = self.storage.lock();
            if self.retired.load(Ordering::Acquire) {
                return None;
            }
            // The scan stops at the most preferred connection that fits, or
            // whose classifier has no derived key yet: the class to derive.
            let decide = |(index, conn): (u32, &PooledConnection<C, ID>)| {
                if &conn.id != id {
                    return None;
                }
                let keyed = match &conn.lane {
                    None => return None,
                    Some(LaneKey::Unrestricted) => return Some((index, None)),
                    Some(LaneKey::Keyed(keyed)) => keyed,
                };
                match wanted
                    .iter()
                    .find(|(derived, _)| derived == keyed.class.classifier())
                {
                    Some((_, wanted)) => {
                        (wanted.as_ref() == Some(&keyed.key)).then_some((index, None))
                    }
                    None => Some((index, Some(keyed.class.clone()))),
                }
            };
            let found = match self.reuse_strategy {
                ReuseStrategy::FiFo => storage.entries.iter().find_map(decide),
                ReuseStrategy::RoundRobin => storage.entries.iter().rev().find_map(decide),
            };
            let class = match found? {
                (index, None) => {
                    let conn = storage.remove(index);
                    drop(storage);
                    if is_broken(&conn) || conn.observe_drain() {
                        park(conn, doomed);
                        continue;
                    }
                    return Some((index, conn));
                }
                (_, Some(class)) => class,
            };
            drop(storage);
            wanted.push(class.derive(input));
        }
    }
}

fn is_broken<C: ExtensionsRef, ID>(conn: &PooledConnection<C, ID>) -> bool {
    conn.extensions()
        .get_ref::<ConnectionHealthWatcher>()
        .is_some_and(|watcher| watcher.health() == ConnectionHealth::Broken)
}

impl<C, ID> Pool<C, ID> for LruDropPool<C, ID>
where
    C: Send + ExtensionsRef + 'static,
    ID: ConnID,
{
    type Connection = LeasedConnection<C, ID>;
    type CreatePermit = (ActiveSlot, PoolSlot);

    async fn get_conn(
        &self,
        id: &ID,
        input: &Extensions,
        _deadline: Option<Instant>,
    ) -> Result<ConnectionResult<Self::Connection, Self::CreatePermit>, BoxError> {
        if self.retired.load(Ordering::Acquire) {
            return Err(BoxError::from_static_str(
                "connection pool has been retired",
            ));
        }
        #[cfg(feature = "opentelemetry")]
        let metrics = self
            .metrics
            .as_ref()
            .map(|metrics| (metrics, metrics.attributes(id)));

        #[cfg(feature = "opentelemetry")]
        let start = Instant::now();
        let active_slot = ActiveSlot(
            self.active_slots
                .clone()
                .acquire_owned()
                .await
                .context("get active pool slot")?,
        );

        #[cfg(feature = "opentelemetry")]
        if let Some((metrics, metric_attrs)) = &metrics {
            let active_connection_delay_nanoseconds = start.elapsed().as_nanos() as f64;
            metrics
                .active_connection_delay_nanoseconds
                .record(active_connection_delay_nanoseconds, metric_attrs);
        };

        // Connections leaving the pool release their slot right away, but the
        // socket itself (TLS teardown, `close(2)`) only drops once the storage
        // lock is released.
        let mut doomed: Doomed<C> = Vec::new();

        if let Some(timeout) = self.idle_timeout {
            let mut storage = self.storage.lock();
            // Returns are ordered under this lock. Walk only the expired
            // tail: removing each entry is O(1), as is keeping the live prefix.
            let now = Instant::now();
            while let Some(slot) = storage.entries.lru() {
                if now.duration_since(storage.entries.peek(slot).last_used) <= timeout {
                    break;
                }
                trace!("LRU connection pool: dropping idle connection past its timeout");
                park(storage.remove(slot), &mut doomed);
            }
        }

        // A completed logical exchange can leave native transport work alive.
        // Reserve before handing the connection out again. Exclusive pools
        // replace exhausted candidates rather than queueing behind that work.
        let reused = loop {
            let Some((idx, conn)) = self.take_compatible(id, input, &mut doomed) else {
                break None;
            };
            let admission = match conn.extensions().self_get_ref::<ConnectionAdmission>() {
                Some(provider) => match provider.try_acquire(input) {
                    Ok(Some(lease)) => Some(lease),
                    Ok(None) => {
                        park(conn, &mut doomed);
                        continue;
                    }
                    Err(error) => {
                        trace!(%error, "LRU connection pool: resource provider retired connection");
                        park(conn, &mut doomed);
                        continue;
                    }
                },
                None => None,
            };
            // Last look before the handout: the connection may have closed,
            // or its scope been cancelled, while the policy or the resource
            // provider ran.
            if is_broken(&conn) || conn.observe_drain() {
                park(conn, &mut doomed);
                continue;
            }
            break Some((idx, conn, admission));
        };
        let result = if let Some((idx, pooled_conn, admission)) = reused {
            trace!("LRU connection pool: connection #{idx} found for given id {id:?}");

            #[cfg(feature = "opentelemetry")]
            if let Some((metrics, metric_attrs)) = &metrics {
                metrics.total_connections.add(1, metric_attrs);
                metrics.reused_connections.add(1, metric_attrs);
            }

            Ok(ConnectionResult::Connection(LeasedConnection {
                admission,
                active_slot,
                pooled_conn: ManuallyDrop::new(pooled_conn),
                pooled_conn_taken: false,
                returner: self.returner.clone(),
                got_response: AtomicBool::new(false),
                failed_or_cancelled: AtomicBool::new(false),
                drop_connection_if_no_response: self.drop_connection_if_no_response,
            }))
        } else {
            let mut storage = self.storage.lock();
            if self.retired.load(Ordering::Acquire) {
                return Err(BoxError::from_static_str(
                    "connection pool has been retired",
                ));
            }
            let pool_slot = match self.total_slots.clone().try_acquire_owned() {
                Ok(permit) => Ok(PoolSlot(permit)),
                Err(err) => {
                    // By poping from back when we have no new Poolslot available we implement LRU drop policy
                    trace!(
                        error = %err,
                        "LRU connection pool: evicting lru connection (#{id:?}) to create a new one"
                    );
                    #[cfg(feature = "opentelemetry")]
                    if let Some((metrics, metric_attrs)) = &metrics {
                        metrics.evicted_connections.add(1, metric_attrs);
                    }
                    storage
                        .pop_back()
                        .context("get least recently used connection from storage")
                        .map(|evicted| {
                            // the slot transfers to the caller, the socket drops later
                            let PooledConnection {
                                pool_slot,
                                conn,
                                scope,
                                ..
                            } = evicted;
                            doomed.push((conn, scope));
                            pool_slot
                        })
                }
            };

            pool_slot.map(|pool_slot| {
                trace!(
                    "LRU connection pool: no connection for given id {id:?} found, returning create permit"
                );
                ConnectionResult::CreatePermit((active_slot, pool_slot))
            })
        };

        drop(doomed);
        result
    }

    fn abandon(&self, _create_permit: Self::CreatePermit, _error: &ConnectionError) {}

    async fn create(
        &self,
        id: ID,
        conn: C,
        permit: Self::CreatePermit,
        input: &Extensions,
    ) -> Result<Self::Connection, BoxError> {
        let admission = match conn.extensions().self_get_ref::<ConnectionAdmission>() {
            Some(provider) => Some(provider.acquire(input).await?),
            None => None,
        };
        trace!("adding new connection (w/ id {id:?}) to pool");
        let (active_slot, pool_slot) = permit;

        #[cfg(feature = "opentelemetry")]
        if let Some(metrics) = &self.metrics.as_ref() {
            let metric_attrs = metrics.attributes(&id);
            metrics.total_connections.add(1, &metric_attrs);
            metrics.created_connections.add(1, &metric_attrs);
        }

        let reuse = conn.extensions().get_ref::<ConnectionReuse>();
        let lane = LaneKey::of_connection(reuse).filter(|_| id.is_reusable());
        let (scope, watcher) = ConnScope::of(conn.extensions()).unzip();
        let idle_slot = watcher.map(|watcher| {
            let slot = Arc::new(AtomicU32::new(NO_IDLE_SLOT));
            let watched_slot = slot.clone();
            let storage = Arc::downgrade(&self.storage);
            watcher.spawn(move || drain_idle(&storage, &watched_slot));
            slot
        });

        Ok(LeasedConnection {
            admission,
            active_slot,
            returner: self.returner.clone(),
            pooled_conn: ManuallyDrop::new(PooledConnection {
                lane,
                id,
                conn,
                pool_slot,
                last_used: Instant::now(),
                scope,
                idle_slot,
            }),
            pooled_conn_taken: false,
            got_response: AtomicBool::new(false),
            failed_or_cancelled: AtomicBool::new(false),
            drop_connection_if_no_response: self.drop_connection_if_no_response,
        })
    }
}

/// Close this watcher's idle connection; a leased one is dropped on return.
fn drain_idle<C, ID>(storage: &Weak<Mutex<IdleStorage<C, ID>>>, slot: &AtomicU32) {
    let Some(storage) = storage.upgrade() else {
        return;
    };
    let doomed = {
        let mut storage = storage.lock();
        let slot = slot.load(Ordering::Relaxed);
        let conn = (slot != NO_IDLE_SLOT).then(|| storage.remove(slot));
        // A fully drained pool should not retain its high-water allocation.
        // Ordinary checkout/return keeps its allocation for reuse.
        let empty = storage.entries.is_empty().then(|| storage.take_all());
        (conn, empty)
    };
    // Socket and scope destruction may run user code, including pool reentry.
    drop(doomed);
}

/// Free a discarded connection's pool slot now and park the connection and its scope
/// for dropping outside the storage lock.
fn park<C, ID>(pooled_conn: PooledConnection<C, ID>, doomed: &mut Doomed<C>) {
    let PooledConnection {
        conn,
        pool_slot,
        scope,
        ..
    } = pooled_conn;
    drop(pool_slot);
    doomed.push((conn, scope));
}

impl<C: Debug, ID: Debug> Debug for PooledConnection<C, ID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledConnection")
            .field("conn", &self.conn)
            .field("id", &self.id)
            .field("pool_slot", &self.pool_slot)
            .finish()
    }
}

impl<C, ID> Debug for LeasedConnection<C, ID>
where
    C: Debug + ExtensionsRef,
    ID: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeasedConnection")
            .field("pooled_conn", self.pooled_conn.deref())
            .field("active_slot", &self.active_slot)
            .finish()
    }
}

impl<C: ExtensionsRef, ID> Deref for LeasedConnection<C, ID> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.pooled_conn.conn
    }
}

impl<C: ExtensionsRef, ID> DerefMut for LeasedConnection<C, ID> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.pooled_conn.conn
    }
}

impl<C: ExtensionsRef, ID> AsRef<C> for LeasedConnection<C, ID> {
    fn as_ref(&self) -> &C {
        self
    }
}

impl<C: ExtensionsRef, ID> AsMut<C> for LeasedConnection<C, ID> {
    fn as_mut(&mut self) -> &mut C {
        self
    }
}

impl<C: ExtensionsRef, ID> Drop for LeasedConnection<C, ID> {
    fn drop(&mut self) {
        self.admission.take();
        if !self.pooled_conn_taken {
            if self.drop_connection_if_no_response
                && (!self.got_response.load(Ordering::Relaxed)
                    || self.failed_or_cancelled.load(Ordering::Relaxed))
            {
                trace!(
                    "LRU connection pool: dropping connection with no response or a failed request"
                );
                // SAFETY: `ManuallyDrop::drop` requires a live value that is not
                // used again. `pooled_conn_taken` is `false` (checked above), so
                // by the field invariant the value is live, and this `drop`
                // returns right after without touching the slot.
                unsafe { ManuallyDrop::drop(&mut self.pooled_conn) };
                return;
            }
            if let Some(watcher) = self.extensions().get_ref::<ConnectionHealthWatcher>()
                && watcher.health() == ConnectionHealth::Broken
            {
                trace!("LRU connection pool: dropping pooled connection that was marked as failed");

                // SAFETY: as in the branch above: `pooled_conn_taken` is `false`,
                // so the value is live (field invariant), and the slot is not
                // used after this call.
                unsafe { ManuallyDrop::drop(&mut self.pooled_conn) };
            } else {
                trace!("LRU connection pool: returning pooled connection back to pool");

                // SAFETY: `ManuallyDrop::take` requires that the slot is not used
                // again. `pooled_conn_taken` is `false`, so the value is live
                // (field invariant); this is the only branch that runs, and the
                // slot is not touched after the move.
                let pooled_conn = unsafe { ManuallyDrop::take(&mut self.pooled_conn) };
                self.returner.return_conn(pooled_conn);
            }
        }
    }
}

// We want to be able to use LeasedConnection as a transparent wrapper around our connection.
// To achieve that we conditially implement all traits that are used by our Connectors

impl<C, ID> Socket for LeasedConnection<C, ID>
where
    ID: Send + Sync + 'static,
    C: Socket + ExtensionsRef,
{
    fn local_addr(&self) -> std::io::Result<SocketAddress> {
        self.as_ref().local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddress> {
        self.as_ref().peer_addr()
    }
}

#[warn(clippy::missing_trait_methods)]
impl<C, ID> AsyncWrite for LeasedConnection<C, ID>
where
    C: AsyncWrite + Unpin + ExtensionsRef,
    ID: Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(self.deref_mut().as_mut()).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(self.deref_mut().as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(self.deref_mut().as_mut()).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.deref().is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(self.deref_mut().as_mut()).poll_write_vectored(cx, bufs)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<C, ID> AsyncRead for LeasedConnection<C, ID>
where
    C: AsyncRead + Unpin + ExtensionsRef,
    ID: Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(self.deref_mut().as_mut()).poll_read(cx, buf)
    }
}

impl<Input, C, ID> Service<Input> for LeasedConnection<C, ID>
where
    ID: Send + Sync + Debug + 'static,
    C: Service<Input> + ExtensionsRef,
    Input: ExtensionsMut + Send + 'static,
{
    type Output = C::Output;
    type Error = C::Error;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        if let Some(admission) = &self.admission {
            admission.bind(input.extensions_mut());
        }

        // Failure is sticky for the whole lease. A later successful call must
        // not make a connection reusable after another concurrent or earlier
        // call failed or was cancelled.
        let failed_or_cancelled = &self.failed_or_cancelled;
        let mut failure_guard = DropGuard::new(move || {
            failed_or_cancelled.store(true, Ordering::Relaxed);
        });
        let result = self.as_ref().serve(input).await;
        if result.is_ok() {
            self.got_response.store(true, Ordering::Relaxed);
            failure_guard.disarm();
        }
        result
    }
}

/// Helper needed so we can implement debug for LruDropPool
///
/// Implementing debug_list and debug_struct at the same time is not
/// possible, so we have to split it up
struct StorageDebugHelper<'a, C, ID: Debug> {
    storage: &'a IdleStorage<C, ID>,
}

impl<'a, C, ID: Debug> Debug for StorageDebugHelper<'a, C, ID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.storage.iter().map(|item| &item.id))
            .finish()
    }
}

impl<C, ID: Debug> Debug for LruDropPool<C, ID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut builder = f.debug_struct("LruDropPool");

        // Don't block on this, it's only for debugging
        match self.storage.try_lock() {
            Some(guard) => {
                let storage_debugger = StorageDebugHelper { storage: &*guard };
                builder.field("storage", &storage_debugger);
            }
            None => {
                builder.field("storage", &"Mutex(locked)");
            }
        };

        builder
            .field("total_slots", &self.total_slots)
            .field("active_slots", &self.active_slots)
            .field("idle_timeout", &self.idle_timeout)
            .field("reuse_strategy", &self.reuse_strategy)
            .finish()
    }
}

impl<C, ID> Extension for LruDropPool<C, ID>
where
    C: Send + 'static,
    ID: Send + Sync + Debug + 'static,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::pool::{ConnectionAdmissionPolicy, ConnectionReusePolicy};
    use crate::client::pool::{PooledConnector, ReqToConnID};
    use crate::client::{ConnectorService, EstablishedClientConnection};
    use rama_core::ServiceInput;
    use rama_core::extensions::ExtensionsRef;
    use rama_core::graceful::{Cause, Scope, WeakScope, attach_scope};
    use rama_core::{Service, extensions::Extensions};
    use rama_utils::reactive::ChangeListener;
    use std::assert_matches;
    use std::sync::{Barrier, Weak, atomic::AtomicBool};
    use std::{
        convert::Infallible,
        sync::atomic::{AtomicI16, AtomicUsize, Ordering},
        task::{Context, Poll},
    };
    use tokio::{
        sync::{oneshot, oneshot::error::TryRecvError, watch},
        time::timeout,
    };
    use tokio_test::assert_ok;

    #[test]
    fn a_limit_past_a_semaphores_permits_is_refused() {
        // An error, not a panic.
        LruDropPool::<(), u32>::try_new(1, Semaphore::MAX_PERMITS + 1).unwrap_err();
        drop(LruDropPool::<(), u32>::try_new(1, Semaphore::MAX_PERMITS).unwrap());
    }

    struct TestService {
        pub created_connection: AtomicI16,
    }

    impl Default for TestService {
        fn default() -> Self {
            Self {
                created_connection: AtomicI16::new(0),
            }
        }
    }

    #[derive(Debug, ExtensionsRef)]
    struct Conn {
        items: Vec<u32>,
        extensions: Extensions,
    }

    impl Conn {
        fn new() -> Self {
            Self {
                items: vec![],
                extensions: Extensions::new(),
            }
        }
    }

    impl Service<ServiceInput<(bool, Duration)>> for Conn {
        type Output = ();
        type Error = BoxError;

        async fn serve(
            &self,
            input: ServiceInput<(bool, Duration)>,
        ) -> Result<Self::Output, Self::Error> {
            let (should_error, delay) = input.input;
            tokio::time::sleep(delay).await;
            if should_error {
                Err(BoxError::from_static_str("request failed"))
            } else {
                Ok(())
            }
        }
    }

    impl Deref for Conn {
        type Target = Vec<u32>;

        fn deref(&self) -> &Self::Target {
            &self.items
        }
    }

    impl DerefMut for Conn {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.items
        }
    }

    impl<Input> Service<Input> for TestService
    where
        Input: Send + 'static,
    {
        type Output = EstablishedClientConnection<Conn, Input>;
        type Error = Infallible;

        async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
            self.created_connection.fetch_add(1, Ordering::Relaxed);
            Ok(EstablishedClientConnection {
                input,
                conn: Conn::new(),
            })
        }
    }

    #[derive(Clone)]
    /// [`StringInputLengthID`] will map inputs of type ServiceInput<String>, to usize id representing their
    /// chars length. In practise this will mean that inputs of the same char length will be
    /// able to reuse the same connections
    struct StringInputLengthID;

    impl ReqToConnID<ServiceInput<String>> for StringInputLengthID {
        type ID = usize;

        fn id(&self, input: &ServiceInput<String>) -> Result<Self::ID, BoxError> {
            Ok(input.input.chars().count())
        }
    }

    impl ConnID for usize {}
    impl ConnID for () {}

    #[tokio::test]
    async fn non_reusable_policy_drops_a_successful_connection() {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        struct Fresh;
        impl ConnID for Fresh {
            fn is_reusable(&self) -> bool {
                false
            }
        }
        let pool: LruDropPool<InnerService, Fresh> = LruDropPool::try_new(1, 1).unwrap();
        let ConnectionResult::CreatePermit(permit) = pool
            .get_conn(&Fresh, &Extensions::new(), None)
            .await
            .unwrap()
        else {
            panic!("non-reusable policy must acquire a fresh connection");
        };
        let connection = pool
            .create(Fresh, InnerService::default(), permit, &Extensions::new())
            .await
            .unwrap();
        connection.serve(ServiceInput::new(false)).await.unwrap();
        drop(connection);
        assert!(pool.storage.lock().is_empty());
        assert_eq!(pool.total_slots.available_permits(), 1);
    }

    /// Keyed by `key`; while armed, a derivation waits twice at `gate`, so
    /// another thread acts while the checkout derives its key.
    #[derive(Debug)]
    struct GatedPolicy {
        key: u8,
        armed: Arc<AtomicBool>,
        gate: Arc<Barrier>,
    }

    #[derive(Debug, Clone, Copy, Extension)]
    struct Want(u8);

    impl ConnectionReusePolicy for GatedPolicy {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            Some(ReuseKey::from_bits::<Want>(self.key.into()))
        }

        fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
            if self.armed.swap(false, Ordering::SeqCst) {
                self.gate.wait();
                self.gate.wait();
            }
            Some(ReuseKey::from_bits::<Want>(
                input.get_ref::<Want>()?.0.into(),
            ))
        }
    }

    struct Gate {
        armed: Arc<AtomicBool>,
        gate: Arc<Barrier>,
    }

    impl Gate {
        fn new() -> Self {
            Self {
                armed: Arc::new(AtomicBool::new(false)),
                gate: Arc::new(Barrier::new(2)),
            }
        }

        fn conn(&self, key: u8) -> Conn {
            let conn = Conn::new();
            conn.extensions.insert(ConnectionHealthWatcher::default());
            conn.extensions.insert(ConnectionReuse::new(GatedPolicy {
                key,
                armed: self.armed.clone(),
                gate: self.gate.clone(),
            }));
            conn
        }

        /// Run `during` on another thread while the next derivation waits.
        fn during(&self, during: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
            self.armed.store(true, Ordering::SeqCst);
            let gate = self.gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                during();
                gate.wait();
            })
        }
    }

    fn want(key: u8) -> Extensions {
        let input = Extensions::new();
        input.insert(Want(key));
        input
    }

    async fn add(pool: &LruDropPool<Conn, usize>, conn: Conn) -> LeasedConnection<Conn, usize> {
        let ConnectionResult::CreatePermit(permit) =
            pool.get_conn(&0, &Extensions::new(), None).await.unwrap()
        else {
            panic!("all previous connections are leased");
        };
        pool.create(0, conn, permit, &Extensions::new())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn storage_keeps_its_lru_order_while_a_checkout_derives() {
        let gate = Gate::new();
        let pool = LruDropPool::try_new(3, 3)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let x = add(&pool, gate.conn(1)).await;
        let y = add(&pool, gate.conn(3)).await;
        drop(x);
        // Y returns while a checkout for key 2 derives its key against X.
        let returner = gate.during(move || drop(y));
        assert_matches!(
            pool.get_conn(&0, &want(2), None).await.unwrap(),
            ConnectionResult::CreatePermit(_),
        );
        returner.join().unwrap();
        let storage = pool.storage.lock();
        assert_eq!(storage.len(), 2);
        assert!(
            storage
                .iter()
                .zip(storage.iter().skip(1))
                .all(|(newer, older)| newer.last_used >= older.last_used),
            "storage stays most recently used first"
        );
    }

    #[tokio::test]
    async fn a_connection_closed_while_its_key_is_derived_is_not_handed_out() {
        let gate = Gate::new();
        let pool = LruDropPool::try_new(1, 1)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let conn = gate.conn(1);
        let health = conn
            .extensions
            .get_arc::<ConnectionHealthWatcher>()
            .unwrap();
        drop(add(&pool, conn).await);
        let closer = gate.during(move || health.mark_broken());
        let result = pool.get_conn(&0, &want(1), None).await.unwrap();
        closer.join().unwrap();
        assert_matches!(result, ConnectionResult::CreatePermit(_));
    }

    #[tokio::test]
    async fn a_connection_closed_during_admission_is_not_handed_out() {
        #[derive(Debug, Extension)]
        struct Binding;

        #[derive(Debug)]
        struct CloseOnAdmission {
            armed: Arc<AtomicBool>,
            health: Arc<ConnectionHealthWatcher>,
        }

        impl ConnectionAdmissionPolicy for CloseOnAdmission {
            fn try_acquire(
                &self,
                _: &Extensions,
            ) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
                if self.armed.load(Ordering::SeqCst) {
                    self.health.mark_broken();
                }
                Ok(Some(ConnectionAdmissionLease::new(Arc::new(()), Binding)))
            }

            fn subscribe(&self, _: Weak<dyn ChangeListener>) {}

            fn in_use(&self) -> bool {
                false
            }
        }

        let pool = LruDropPool::try_new(1, 1)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let conn = Conn::new();
        let health = Arc::new(ConnectionHealthWatcher::default());
        let armed = Arc::new(AtomicBool::new(false));
        conn.extensions.insert_arc(health.clone());
        conn.extensions
            .insert(ConnectionAdmission::new(CloseOnAdmission {
                armed: armed.clone(),
                health,
            }));
        drop(add(&pool, conn).await);
        armed.store(true, Ordering::SeqCst);
        assert_matches!(
            pool.get_conn(&0, &Extensions::new(), None).await.unwrap(),
            ConnectionResult::CreatePermit(_),
        );
    }

    #[tokio::test]
    async fn rekey_never_files_a_connection_of_a_non_reusable_id() {
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        struct Fresh;
        impl ConnID for Fresh {
            fn is_reusable(&self) -> bool {
                false
            }
        }
        let pool = LruDropPool::try_new(1, 1)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let ConnectionResult::CreatePermit(permit) = pool
            .get_conn(&Fresh, &Extensions::new(), None)
            .await
            .unwrap()
        else {
            panic!("a non-reusable id always establishes");
        };
        let mut conn = pool
            .create(Fresh, Conn::new(), permit, &Extensions::new())
            .await
            .unwrap();
        conn.rekey(ConnectionReuse::new(GatedPolicy {
            key: 1,
            armed: Arc::new(AtomicBool::new(false)),
            gate: Arc::new(Barrier::new(1)),
        }));
        drop(conn);
        assert!(pool.storage.lock().is_empty());
    }

    #[tokio::test]
    async fn reuse_policy_runs_outside_exclusive_storage_lock() {
        #[derive(Debug)]
        struct LockProbe(Weak<Mutex<IdleStorage<Conn, usize>>>);

        impl ConnectionReusePolicy for LockProbe {
            fn classifier(&self) -> ReuseKey {
                ReuseKey::of::<Self>()
            }

            fn connection_key(&self) -> Option<ReuseKey> {
                Some(ReuseKey::of::<Self>())
            }

            fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
                let storage = self.0.upgrade().unwrap();
                assert!(
                    storage.try_lock_for(Duration::from_secs(1)).is_some(),
                    "connector policy must not run under the pool lock"
                );
                Some(ReuseKey::of::<Self>())
            }
        }

        let pool = LruDropPool::try_new(1, 1)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let input = Extensions::new();
        let ConnectionResult::CreatePermit(permit) = pool.get_conn(&0, &input, None).await.unwrap()
        else {
            panic!("empty pool must allow creation");
        };
        let conn = Conn::new();
        conn.extensions
            .insert(ConnectionReuse::new(LockProbe(Arc::downgrade(
                &pool.storage,
            ))));
        drop(
            pool.create(0, conn, permit, &Extensions::new())
                .await
                .unwrap(),
        );
        assert_matches!(
            pool.get_conn(&0, &input, None).await.unwrap(),
            ConnectionResult::Connection(_),
        );
    }

    #[tokio::test]
    async fn retirement_during_policy_check_cannot_return_connection_or_permit() {
        #[derive(Debug)]
        struct RetireOnMatch(LruDropPool<Conn, usize>);

        impl ConnectionReusePolicy for RetireOnMatch {
            fn classifier(&self) -> ReuseKey {
                ReuseKey::of::<Self>()
            }

            fn connection_key(&self) -> Option<ReuseKey> {
                Some(ReuseKey::of::<Self>())
            }

            fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
                self.0.retire();
                Some(ReuseKey::of::<Self>())
            }
        }

        let pool = LruDropPool::try_new(1, 1)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let input = Extensions::new();
        let ConnectionResult::CreatePermit(permit) = pool.get_conn(&0, &input, None).await.unwrap()
        else {
            panic!("empty pool must allow creation");
        };
        let conn = Conn::new();
        conn.extensions
            .insert(ConnectionReuse::new(RetireOnMatch(pool.clone())));
        drop(
            pool.create(0, conn, permit, &Extensions::new())
                .await
                .unwrap(),
        );
        pool.get_conn(&0, &input, None).await.unwrap_err();
        assert_eq!(pool.total_slots.available_permits(), 1);
        assert_eq!(pool.active_slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn test_should_reuse_connections() {
        let pool = LruDropPool::try_new(5, 10)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        // We use a closure here to maps all requests to `()` id, this will result in all connections being shared and the pool
        // acting like like a global connection pool (eg database connection pool where all connections can be used).
        let svc = PooledConnector::new(
            TestService::default(),
            pool,
            |__req: &ServiceInput<String>| Ok(()),
        );

        let iterations = 10;
        for _i in 0..iterations {
            let _conn = svc.connect(ServiceInput::new(String::new())).await.unwrap();
        }

        let created_connection = svc.inner.created_connection.load(Ordering::Relaxed);
        assert_eq!(created_connection, 1);
    }

    #[tokio::test]
    async fn test_conn_id_to_separate() {
        let pool = LruDropPool::try_new(5, 10)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let svc = PooledConnector::new(TestService::default(), pool, StringInputLengthID {});

        {
            let mut conn = svc
                .connect(ServiceInput::new(String::from("a")))
                .await
                .unwrap()
                .conn;

            conn.push(1);
            assert_eq!(conn.as_ref().deref(), &vec![1]);
            assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 1);
        }

        // Should reuse the same connections
        {
            let mut conn = svc
                .connect(ServiceInput::new(String::from("B")))
                .await
                .unwrap()
                .conn;

            conn.push(2);
            assert_eq!(conn.as_ref().deref(), &vec![1, 2]);
            assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 1);
        }

        // Should make a new one
        {
            let mut conn = svc
                .connect(ServiceInput::new(String::from("aa")))
                .await
                .unwrap()
                .conn;

            conn.push(3);
            assert_eq!(conn.as_ref().deref(), &vec![3]);
            assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 2);
        }

        // Should reuse
        {
            let mut conn = svc
                .connect(ServiceInput::new(String::from("bb")))
                .await
                .unwrap()
                .conn;

            conn.push(4);
            assert_eq!(conn.as_ref().deref(), &vec![3, 4]);
            assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 2);
        }
    }

    #[tokio::test]
    async fn test_pool_max_size() {
        let pool = LruDropPool::try_new(1, 1)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let svc = PooledConnector::new(TestService::default(), pool, StringInputLengthID {})
            .with_wait_for_pool_timeout(Duration::from_millis(50));

        let conn1 = svc
            .connect(ServiceInput::new(String::from("a")))
            .await
            .unwrap();

        let conn2 = svc.connect(ServiceInput::new(String::from("a"))).await;
        let _error = conn2.unwrap_err();

        drop(conn1);
        let _conn3 = svc
            .connect(ServiceInput::new(String::from("aaa")))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn retired_pool_closes_idle_and_rejects_returned_connections() {
        let pool = LruDropPool::try_new(2, 2)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let svc =
            PooledConnector::new(TestService::default(), pool.clone(), StringInputLengthID {});

        let idle = svc
            .connect(ServiceInput::new(String::from("a")))
            .await
            .unwrap()
            .conn;
        drop(idle);
        let active = svc
            .connect(ServiceInput::new(String::from("bb")))
            .await
            .unwrap()
            .conn;
        assert_eq!(pool.storage.lock().len(), 1);

        pool.retire();
        assert!(pool.storage.lock().is_empty());
        drop(active);
        assert!(pool.storage.lock().is_empty());
        match svc.connect(ServiceInput::new(String::from("ccc"))).await {
            Err(_) => {}
            Ok(_) => panic!("a retired pool accepted a new acquisition"),
        }
    }

    #[derive(Default)]
    struct TestConnector {
        pub created_connection: AtomicI16,
    }

    impl<Input> Service<Input> for TestConnector
    where
        Input: Send + 'static,
    {
        type Output = EstablishedClientConnection<InnerService, Input>;
        type Error = Infallible;

        async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
            let conn = InnerService::default();

            conn.extensions().insert(ConnectionHealthWatcher::default());

            self.created_connection.fetch_add(1, Ordering::Relaxed);
            Ok(EstablishedClientConnection { input, conn })
        }
    }

    #[derive(Default, Debug, ExtensionsRef)]
    struct InnerService {
        should_error: Arc<AtomicBool>,
        extensions: Extensions,
    }

    impl Service<ServiceInput<bool>> for InnerService {
        type Output = ();
        type Error = BoxError;

        async fn serve(&self, input: ServiceInput<bool>) -> Result<Self::Output, Self::Error> {
            let should_error = input.input;
            // Once this service is broken it will stay in this state, similar to a closed tcp connection
            if should_error {
                self.extensions
                    .get_ref::<ConnectionHealthWatcher>()
                    .unwrap()
                    .mark_broken();
                self.should_error.store(true, Ordering::Relaxed);
            }

            if self.should_error.load(Ordering::Relaxed) {
                Err(BoxError::from_static_str("service is in broken state"))
            } else {
                Ok(())
            }
        }
    }

    impl Service<ServiceInput<Duration>> for InnerService {
        type Output = ();
        type Error = BoxError;

        async fn serve(&self, input: ServiceInput<Duration>) -> Result<Self::Output, Self::Error> {
            tokio::time::sleep(input.input).await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_cancellated_fut_should_drop_connection_by_default() {
        let pool = LruDropPool::try_new(1, 1).unwrap();
        let svc = PooledConnector::new(TestConnector::default(), pool, StringInputLengthID {});

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();
        assert_ok!(conn.conn.serve(ServiceInput::new(false)).await);
        drop(conn);
        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 1);

        // Get the (reused) connection, start a slow request, and cancel it via timeout
        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();
        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 1);

        let timeout_result = tokio::time::timeout(
            Duration::from_millis(10),
            conn.conn.serve(ServiceInput::new(Duration::from_secs(60))),
        )
        .await;

        assert!(timeout_result.is_err(), "should have timed out");
        drop(conn);

        // Next connection must be a fresh one: the cancelled one should not have been returned
        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();
        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 2);
        assert_ok!(conn.conn.serve(ServiceInput::new(false)).await);
    }

    #[tokio::test]
    async fn test_cancellated_fut_should_not_drop_connection_if_this_is_disabled() {
        let pool = LruDropPool::try_new(1, 1)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let svc = PooledConnector::new(TestConnector::default(), pool, StringInputLengthID {});

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();
        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 1);

        let timeout_result = tokio::time::timeout(
            Duration::from_millis(10),
            conn.conn.serve(ServiceInput::new(Duration::from_secs(60))),
        )
        .await;
        assert!(timeout_result.is_err(), "should have timed out");
        drop(conn);

        // With drop_connection_if_no_response disabled, the connection should be returned to the pool
        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();
        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 1);
        assert_ok!(conn.conn.serve(ServiceInput::new(false)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_request_stays_sticky_after_concurrent_success() {
        let pool = LruDropPool::try_new(1, 1).unwrap();
        let svc = PooledConnector::new(TestService::default(), pool, StringInputLengthID {});

        let conn = svc.connect(ServiceInput::new(String::new())).await.unwrap();

        // The failure resolves first and the success resolves last. The old
        // last-writer-wins flag therefore returned this lease to the pool.
        let (failed, succeeded) = tokio::join!(
            conn.conn
                .serve(ServiceInput::new((true, Duration::from_millis(10)))),
            conn.conn
                .serve(ServiceInput::new((false, Duration::from_millis(20)))),
        );
        failed.unwrap_err();
        assert_ok!(succeeded);
        drop(conn);

        let _fresh = svc.connect(ServiceInput::new(String::new())).await.unwrap();
        assert_eq!(
            svc.inner.created_connection.load(Ordering::Relaxed),
            2,
            "any failed request must poison the lease despite a later response"
        );
    }

    #[tokio::test]
    async fn test_dont_return_broken_connections_to_pool() {
        let pool = LruDropPool::try_new(1, 1).unwrap();
        let svc = PooledConnector::new(TestConnector::default(), pool, StringInputLengthID {});

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();

        let result = conn.conn.serve(ServiceInput::new(false)).await;
        assert_ok!(result);
        let result = conn.conn.serve(ServiceInput::new(true)).await;
        let _error = result.unwrap_err();

        // this dropped connection should not return to the pool, otherwise it will be permanently broken
        drop(conn);

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();

        let result = conn.conn.serve(ServiceInput::new(false)).await;
        assert_ok!(result);

        // this connection is not broken so it should return to the pool
        drop(conn);

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();

        let result = conn.conn.serve(ServiceInput::new(false)).await;
        assert_ok!(result);

        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_pool_drops_broken_connections_in_get_conn() {
        let pool = LruDropPool::try_new(1, 1).unwrap();
        let svc = PooledConnector::new(TestConnector::default(), pool, StringInputLengthID {});

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();

        let result = conn.conn.serve(ServiceInput::new(false)).await;
        assert_ok!(result);

        // This dropped connection should return to the pool, since it's not broken yet
        let conn_extensions = conn.conn.extensions().clone();
        drop(conn);

        // Break connection -> eg go-away / tcp connection dropped by remote...
        // Normally the connection would edit this in extensions but since we don't have ownership here
        // we just clone the extensions and edit it like this
        conn_extensions
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .mark_broken();

        // We should get a new working connection here since health check has detect that the stored one was broken
        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();

        let result = conn.conn.serve(ServiceInput::new(false)).await;
        assert_ok!(result);

        // This connection is not broken so it should return to the pool
        drop(conn);

        // And we should be able to reuse it
        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();

        let result = conn.conn.serve(ServiceInput::new(false)).await;
        assert_ok!(result);

        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn drop_idle_connections() {
        let pool = LruDropPool::try_new(5, 10)
            .unwrap()
            .with_idle_timeout(Duration::from_secs(90))
            .with_drop_connection_if_no_response(false);

        let svc = PooledConnector::new(TestService::default(), pool, StringInputLengthID {});

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap()
            .conn;

        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 1);
        drop(conn);

        // Idle time is read from the runtime clock: advancing the paused clock expires it.
        tokio::time::advance(Duration::from_secs(89)).await;
        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap()
            .conn;
        assert_eq!(
            svc.inner.created_connection.load(Ordering::Relaxed),
            1,
            "idle for less than the timeout"
        );
        drop(conn);

        tokio::time::advance(Duration::from_secs(91)).await;
        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap()
            .conn;
        assert_eq!(
            svc.inner.created_connection.load(Ordering::Relaxed),
            2,
            "idle past the timeout"
        );
        drop(conn);
    }

    #[tokio::test]
    async fn fifo_reuse() {
        test_reuse(ReuseStrategy::FiFo, 1).await;
    }

    #[tokio::test]
    async fn round_robin_reuse() {
        test_reuse(ReuseStrategy::RoundRobin, 0).await;
    }

    async fn test_reuse(strategy: ReuseStrategy, expected: u32) {
        let pool = LruDropPool::try_new(5, 10)
            .unwrap()
            .with_reuse_strategy(strategy)
            .with_drop_connection_if_no_response(false);

        let svc = PooledConnector::new(TestService::default(), pool, |_: &ServiceInput<()>| Ok(()));

        // Open two concurrent connections and drop them.
        let mut conns = Vec::new();
        for i in 0..2 {
            let mut conn = svc.connect(ServiceInput::new(())).await.unwrap().conn;
            conn.pooled_conn.conn.push(i);
            conns.push(conn);
        }

        drop(conns);

        // We should now have two connections with the same key in the pool,
        // from most to least recently used. ([conn2, conn1]). Requesting
        // another connection should return the first or last one depending on
        // the reuse policy.
        let conn = svc.connect(ServiceInput::new(())).await.unwrap().conn;

        assert_eq!(conn.pooled_conn.conn[0], expected);
    }

    /// Bounds every wait of the draining tests.
    const LIMIT: Duration = Duration::from_secs(10);

    /// Dropped with the connection whose extensions hold it.
    #[derive(Debug, Extension)]
    struct Closes {
        _signal: oneshot::Sender<()>,
    }

    /// Counts the connections dropped, through the one whose extensions hold it.
    #[derive(Debug, Extension)]
    struct Counted(watch::Sender<usize>);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.send_modify(|dropped| *dropped += 1);
        }
    }

    /// A connection running in `scope` (none: in no scope), and what tells it closed.
    fn conn_in(scope: Option<&Scope>) -> (Conn, oneshot::Receiver<()>) {
        let conn = Conn::new();
        if let Some(scope) = scope {
            attach_scope(conn.extensions(), scope);
        }
        let (signal, closed) = oneshot::channel();
        conn.extensions().insert(Closes { _signal: signal });
        (conn, closed)
    }

    fn is_closed(closed: &mut oneshot::Receiver<()>) -> bool {
        matches!(closed.try_recv(), Err(TryRecvError::Closed))
    }

    async fn closes(closed: &mut oneshot::Receiver<()>) {
        timeout(LIMIT, closed)
            .await
            .expect("the connection closes")
            .unwrap_err();
    }

    /// Wait until no watcher, the only tasks these tests spawn, is left.
    async fn watchers_end() {
        let metrics = tokio::runtime::Handle::current().metrics();
        timeout(LIMIT, async {
            while metrics.num_alive_tasks() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("every watcher ends");
    }

    fn draining_pool(max: usize) -> LruDropPool<Conn, usize> {
        LruDropPool::try_new(max, max)
            .unwrap()
            .with_drop_connection_if_no_response(false)
    }

    /// A signal that never completes and runs `0` once dropped, as a scope drops it on its
    /// cancel.
    struct OnDrop(Option<Box<dyn FnOnce() + Send>>);

    impl Future for OnDrop {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    impl Drop for OnDrop {
        fn drop(&mut self) {
            if let Some(on_drop) = self.0.take() {
                on_drop();
            }
        }
    }

    #[tokio::test]
    async fn a_scope_cancelled_by_its_deadline_is_observed_outside_the_storage_lock() {
        let pool = draining_pool(1);
        let storage = pool.storage.clone();
        let lock_was_free = Arc::new(AtomicBool::new(false));
        let observed = lock_was_free.clone();
        let scope = Scope::new().with_signal(OnDrop(Some(Box::new(move || {
            observed.store(storage.try_lock().is_some(), Ordering::SeqCst);
        }))));
        let (conn, mut closed) = conn_in(Some(&scope));
        let held = add(&pool, conn).await;
        let scope = scope.with_deadline(Instant::now());
        drop(held);
        assert!(lock_was_free.load(Ordering::SeqCst));
        assert!(is_closed(&mut closed));
        assert!(pool.storage.lock().is_empty());
        drop(scope);
        watchers_end().await;
    }

    #[tokio::test]
    async fn a_signal_dropped_on_a_returns_deadline_can_retire_the_pool() {
        let pool = draining_pool(1);
        let retiring = pool.clone();
        let scope = Scope::new().with_signal(OnDrop(Some(Box::new(move || retiring.retire()))));
        let (conn, mut closed) = conn_in(Some(&scope));
        let held = add(&pool, conn).await;
        let scope = scope.with_deadline(Instant::now());
        // On its own thread: a deadlock fails the test instead of hanging it.
        let (done, returned) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(held);
            let _sent = done.send(());
        });
        returned
            .recv_timeout(LIMIT)
            .expect("the return completes while the signal retires the pool");
        assert!(is_closed(&mut closed));
        assert!(pool.retired.load(Ordering::Acquire));
        drop(scope);
        watchers_end().await;
    }

    #[tokio::test]
    async fn cancelling_a_large_idle_pool_releases_every_slot() {
        const CONNECTIONS: usize = 8192;
        let pool = draining_pool(CONNECTIONS);
        let scope = Scope::new();
        let (counter, mut dropped) = watch::channel(0_usize);
        let mut held = Vec::with_capacity(CONNECTIONS);
        for _ in 0..CONNECTIONS {
            let (conn, _) = conn_in(Some(&scope));
            conn.extensions().insert(Counted(counter.clone()));
            held.push(add(&pool, conn).await);
        }
        drop(held);
        assert_eq!(pool.storage.lock().len(), CONNECTIONS);
        scope.cancel(Cause::Owner);
        timeout(LIMIT, dropped.wait_for(|n| *n == CONNECTIONS))
            .await
            .unwrap()
            .unwrap();
        assert!(pool.storage.lock().is_empty());
        assert_eq!(pool.total_slots.available_permits(), CONNECTIONS);
        assert_eq!(pool.storage.lock().entries.capacity(), 0);
        watchers_end().await;
    }

    #[tokio::test]
    async fn cancellation_tracks_a_connection_returned_to_a_different_slot() {
        let pool = draining_pool(2);
        let scope = Scope::new();
        let (conn, mut closed) = conn_in(Some(&scope));
        let held = add(&pool, conn).await;
        let watched_slot = held.pooled_conn.idle_slot.clone().unwrap();
        drop(held);
        let original_slot = watched_slot.load(Ordering::Relaxed);
        let ConnectionResult::Connection(held) =
            pool.get_conn(&0, &Extensions::new(), None).await.unwrap()
        else {
            panic!("reuse the scoped connection");
        };
        assert_eq!(watched_slot.load(Ordering::Relaxed), NO_IDLE_SLOT);
        let (other, mut other_closed) = conn_in(None);
        drop(add(&pool, other).await);
        // The other connection reused the old slot. Returning the original
        // connection must publish its new slot before its watcher runs.
        drop(held);
        assert_ne!(watched_slot.load(Ordering::Relaxed), original_slot);
        scope.cancel(Cause::Owner);
        closes(&mut closed).await;
        watchers_end().await;
        assert!(!is_closed(&mut other_closed));
        assert_eq!(pool.storage.lock().len(), 1);
    }

    #[tokio::test]
    async fn a_late_drain_cannot_remove_a_replacement_connection() {
        let pool = draining_pool(1);
        let scope = Scope::new();
        let (conn, mut closed) = conn_in(Some(&scope));
        let held = add(&pool, conn).await;
        let old_slot = held.pooled_conn.idle_slot.clone().unwrap();
        drop(held);
        // A different id evicts the original; the new connection reuses its slot.
        let ConnectionResult::CreatePermit(permit) =
            pool.get_conn(&1, &Extensions::new(), None).await.unwrap()
        else {
            panic!("another id needs a new connection");
        };
        assert!(is_closed(&mut closed));
        let (other, mut other_closed) = conn_in(None);
        drop(
            pool.create(1, other, permit, &Extensions::new())
                .await
                .unwrap(),
        );
        drain_idle(&Arc::downgrade(&pool.storage), &old_slot);
        assert!(!is_closed(&mut other_closed));
        assert_eq!(pool.storage.lock().len(), 1);
        watchers_end().await;
    }

    #[tokio::test]
    async fn a_late_drain_after_retirement_has_no_idle_slot() {
        let pool = draining_pool(1);
        let scope = Scope::new();
        let (conn, mut closed) = conn_in(Some(&scope));
        let held = add(&pool, conn).await;
        let slot = held.pooled_conn.idle_slot.clone().unwrap();
        drop(held);
        pool.retire();
        assert!(is_closed(&mut closed));
        drain_idle(&Arc::downgrade(&pool.storage), &slot);
        assert_eq!(slot.load(Ordering::Relaxed), NO_IDLE_SLOT);
        watchers_end().await;
    }

    #[tokio::test]
    async fn idle_connection_closes_once_its_scope_is_cancelled() {
        let pool = draining_pool(2);
        let scope = Scope::new();
        let (conn, mut closed) = conn_in(Some(&scope));
        drop(add(&pool, conn).await);
        assert_eq!(pool.storage.lock().len(), 1);

        scope.cancel(Cause::Owner);
        closes(&mut closed).await;
        assert!(pool.storage.lock().is_empty());
        assert_eq!(pool.total_slots.available_permits(), 2);
        watchers_end().await;
    }

    #[tokio::test]
    async fn leased_connection_closes_once_returned_after_its_scope_is_cancelled() {
        let pool = draining_pool(2);
        let scope = Scope::new();
        let (conn, mut closed) = conn_in(Some(&scope));
        let leased = add(&pool, conn).await;

        scope.cancel(Cause::Owner);
        watchers_end().await;
        assert!(!is_closed(&mut closed), "a leased connection keeps serving");
        drop(leased);
        assert!(is_closed(&mut closed));
        assert!(pool.storage.lock().is_empty());
        assert_eq!(pool.total_slots.available_permits(), 2);
    }

    #[tokio::test]
    async fn checkout_right_after_the_cancel_dials_instead_of_reusing() {
        let pool = draining_pool(2);
        let scope = Scope::new();
        let (conn, mut closed) = conn_in(Some(&scope));
        drop(add(&pool, conn).await);

        // Before the watcher ran: the checkout itself refuses the connection.
        scope.cancel(Cause::Owner);
        let result = pool.get_conn(&0, &Extensions::new(), None).await.unwrap();
        assert_matches!(result, ConnectionResult::CreatePermit(_));
        assert!(is_closed(&mut closed));
        watchers_end().await;
    }

    #[tokio::test]
    async fn connection_made_in_a_cancelled_scope_serves_its_checkout_and_closes() {
        let pool = draining_pool(2);
        let scope = Scope::new();
        scope.cancel(Cause::Owner);
        let (conn, mut closed) = conn_in(Some(&scope));
        let leased = add(&pool, conn).await;
        leased
            .serve(ServiceInput::new((false, Duration::ZERO)))
            .await
            .unwrap();
        // Another checkout meanwhile dials its own.
        let (other, mut other_closed) = conn_in(Some(&scope));
        let other = add(&pool, other).await;

        drop(leased);
        assert!(is_closed(&mut closed));
        drop(other);
        assert!(is_closed(&mut other_closed));
        assert!(pool.storage.lock().is_empty());
        assert_eq!(pool.total_slots.available_permits(), 2);
        watchers_end().await;
    }

    #[tokio::test]
    async fn connection_outside_the_cancelled_scope_is_kept() {
        let pool = draining_pool(2);
        let scope = Scope::new();
        let (scoped, mut scoped_closed) = conn_in(Some(&scope));
        let (unscoped, mut unscoped_closed) = conn_in(None);
        let scoped = add(&pool, scoped).await;
        let unscoped = add(&pool, unscoped).await;
        drop((scoped, unscoped));

        scope.cancel(Cause::Owner);
        closes(&mut scoped_closed).await;
        watchers_end().await;
        assert!(!is_closed(&mut unscoped_closed));
        assert_eq!(pool.storage.lock().len(), 1);
        let result = pool.get_conn(&0, &Extensions::new(), None).await.unwrap();
        assert_matches!(result, ConnectionResult::Connection(_));
    }

    #[tokio::test]
    async fn watcher_ends_with_its_connection() {
        let pool = draining_pool(1);
        let scope = Scope::new();
        let (conn, mut closed) = conn_in(Some(&scope));
        drop(add(&pool, conn).await);
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            1
        );

        // Evicted for a checkout of another id, before any cancel.
        let result = pool.get_conn(&1, &Extensions::new(), None).await.unwrap();
        assert_matches!(result, ConnectionResult::CreatePermit(_));
        assert!(is_closed(&mut closed));
        watchers_end().await;
        scope.cancel(Cause::Owner);
    }

    /// Cancels its scope once armed, as the checkout that admits it looks.
    #[derive(Debug)]
    struct CancelOnAdmission {
        armed: Arc<AtomicBool>,
        scope: WeakScope,
    }

    #[derive(Debug, Extension)]
    struct Binding;

    impl ConnectionAdmissionPolicy for CancelOnAdmission {
        fn try_acquire(
            &self,
            _: &Extensions,
        ) -> Result<Option<ConnectionAdmissionLease>, BoxError> {
            if self.armed.load(Ordering::SeqCst) {
                self.scope.cancel(Cause::Owner);
            }
            Ok(Some(ConnectionAdmissionLease::new(Arc::new(()), Binding)))
        }

        fn subscribe(&self, _: Weak<dyn ChangeListener>) {}

        fn in_use(&self) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn connection_whose_scope_is_cancelled_during_admission_is_not_handed_out() {
        let pool = draining_pool(1);
        let scope = Scope::new();
        let (conn, mut closed) = conn_in(Some(&scope));
        let armed = Arc::new(AtomicBool::new(false));
        conn.extensions
            .insert(ConnectionAdmission::new(CancelOnAdmission {
                armed: armed.clone(),
                scope: scope.clone_weak(),
            }));
        drop(add(&pool, conn).await);
        armed.store(true, Ordering::SeqCst);
        let result = pool.get_conn(&0, &Extensions::new(), None).await.unwrap();
        assert_matches!(result, ConnectionResult::CreatePermit(_));
        assert!(is_closed(&mut closed));
        watchers_end().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_checkouts_never_reuse_a_connection_after_its_cancel() {
        const TASKS: usize = 8;
        const ROUNDS: usize = 64;
        let pool = draining_pool(TASKS);
        let scope = Scope::new();
        let created = Arc::new(AtomicUsize::new(0));
        let (counter, mut dropped) = watch::channel(0_usize);

        let workers: Vec<_> = (0..TASKS)
            .map(|task| {
                let (pool, scope, created, counter) = (
                    pool.clone(),
                    scope.clone(),
                    created.clone(),
                    counter.clone(),
                );
                tokio::spawn(async move {
                    for round in 0..ROUNDS {
                        if task == 0 && round == ROUNDS / 2 {
                            scope.cancel(Cause::Owner);
                        }
                        // Observed before the checkout starts: it must not reuse.
                        let cancelled = scope.is_cancelled();
                        let input = Extensions::new();
                        let checkout = pool.get_conn(&0, &input, None);
                        let leased = match timeout(LIMIT, checkout).await.unwrap().unwrap() {
                            ConnectionResult::Connection(leased) => {
                                assert!(!cancelled, "reused after the cancel");
                                leased
                            }
                            ConnectionResult::CreatePermit(permit) => {
                                created.fetch_add(1, Ordering::SeqCst);
                                let (conn, _closed) = conn_in(Some(&scope));
                                conn.extensions().insert(Counted(counter.clone()));
                                timeout(LIMIT, pool.create(0, conn, permit, &input))
                                    .await
                                    .unwrap()
                                    .unwrap()
                            }
                        };
                        tokio::task::yield_now().await;
                        drop(leased);
                    }
                })
            })
            .collect();
        for worker in workers {
            timeout(LIMIT, worker).await.unwrap().unwrap();
        }

        let created = created.load(Ordering::SeqCst);
        assert!(
            created < TASKS * ROUNDS,
            "connections were reused before the cancel"
        );
        timeout(LIMIT, dropped.wait_for(|dropped| *dropped == created))
            .await
            .expect("every connection closes")
            .unwrap();
        assert!(pool.storage.lock().is_empty());
        assert_eq!(pool.total_slots.available_permits(), TASKS);
    }
}
