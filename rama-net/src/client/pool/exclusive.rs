//! Exclusive single-use connection pool.
//!
//! [`LruDropPool`] hands out a [`LeasedConnection`] that the caller owns for the
//! duration of its use and that is returned to the pool on drop. Each pooled
//! connection serves a single user at a time.

#[cfg(feature = "opentelemetry")]
use super::metrics;
use super::{ActiveSlot, ConnID, ConnectionResult, Pool, PoolSlot};
use crate::address::SocketAddress;
use crate::conn::{ConnectionHealth, ConnectionHealthWatcher};
use crate::stream::Socket;
use parking_lot::Mutex;
use rama_core::Service;
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorContext, ErrorExt};
use rama_core::extensions::{Extension, Extensions, ExtensionsRef};
use rama_core::telemetry::tracing::trace;
use rama_utils::macros::generate_set_and_with;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;

/// [`LeasedConnection`] is a connection that is temporarily leased from a pool
///
/// It will be returned to the pool once dropped if the user didn't
/// take ownership of the connection `C` with [`LeasedConnection::into_connection()`].
/// [`LeasedConnection`]s are considered active pool connections until dropped or
/// ownership is taken of the internal connection.
pub struct LeasedConnection<C: ExtensionsRef, ID> {
    pooled_conn: ManuallyDrop<PooledConnection<C, ID>>,
    pooled_conn_taken: bool,
    active_slot: ActiveSlot,
    returner: ConnReturner<C, ID>,
    got_response: AtomicBool,
    drop_connection_if_no_response: bool,
}

impl<C: ExtensionsRef, ID> LeasedConnection<C, ID> {
    pub fn into_connection(mut self) -> C {
        // We cannot use ::into_inner as we still require a Drop impl as well, so
        // we assign pooled_conn_taken to true to avoid double-dropping.
        self.pooled_conn_taken = true;
        // SAFETY: value is only dropped in `Self::Drop`, and value is only taken
        // here if we move out of leased drop.
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
struct PooledConnection<C, ID> {
    conn: C,
    id: ID,
    pool_slot: PoolSlot,
    last_used: Instant,
}

impl<C: ExtensionsRef, ID> ExtensionsRef for PooledConnection<C, ID> {
    fn extensions(&self) -> &Extensions {
        self.conn.extensions()
    }
}

/// Connection pool that uses LRU to evict connections
pub struct LruDropPool<C, ID> {
    storage: Arc<Mutex<VecDeque<PooledConnection<C, ID>>>>,
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
    weak_storage: Weak<Mutex<VecDeque<PooledConnection<C, ID>>>>,
}

impl<C, ID> Clone for ConnReturner<C, ID> {
    fn clone(&self) -> Self {
        Self {
            weak_storage: self.weak_storage.clone(),
        }
    }
}

impl<C, ID> ConnReturner<C, ID> {
    fn return_conn(&self, mut conn: PooledConnection<C, ID>) {
        if let Some(storage) = self.weak_storage.upgrade() {
            // Ensure correct ordering by locking storage before loading the
            // last used time.
            let mut storage = storage.lock();
            conn.last_used = Instant::now();
            storage.push_front(conn);
        }
    }
}

impl<C, ID> Clone for LruDropPool<C, ID> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
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
        let storage = Arc::new(Mutex::new(VecDeque::with_capacity(max_total)));
        let weak_storage = Arc::downgrade(&storage);
        Ok(Self {
            storage,
            returner: ConnReturner { weak_storage },
            total_slots: Arc::new(Semaphore::const_new(max_total)),
            active_slots: Arc::new(Semaphore::const_new(max_active)),
            idle_timeout: None,
            reuse_strategy: ReuseStrategy::default(),
            drop_connection_if_no_response: true,
            #[cfg(feature = "opentelemetry")]
            metrics: None,
        })
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
    ) -> Result<ConnectionResult<Self::Connection, Self::CreatePermit>, BoxError> {
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

        let mut storage = self.storage.lock();

        if let Some(timeout) = self.idle_timeout {
            // Since new connections are always returned to the front of the
            // queue, they are ordered from most to least recently used. To
            // provide a stable predicate, we load `now` once and use it for all
            // comparisons, rather than using `conn.last_used.elapsed()`, which
            // would use an updated "current" time for every comparison. The
            // `partition_point` method performs a binary search to find the
            // index of the first element for which the predicate returns false,
            // i.e. the first connection past the idle timeout. All connections
            // from that index onwards are timed out and can be dropped.
            let now = Instant::now();
            let idx = storage.partition_point(|conn| now.duration_since(conn.last_used) <= timeout);
            if idx < storage.len() {
                trace!(
                    "LRU connection pool: idle timeout was triggered, dropping connections with index {idx:?} and later"
                );
                storage.drain(idx..);
            }
        }

        let mut get_conn = || loop {
            let idx = match self.reuse_strategy {
                ReuseStrategy::FiFo => storage.iter().position(|stored| &stored.id == id)?,
                ReuseStrategy::RoundRobin => storage.iter().rposition(|stored| &stored.id == id)?,
            };

            let pooled_conn = storage.remove(idx)?;

            // This will make sure we skip and drop broken connections
            if let Some(watcher) = pooled_conn
                .extensions()
                .get_ref::<ConnectionHealthWatcher>()
                && watcher.health() == ConnectionHealth::Broken
            {
                continue;
            }

            return Some((idx, pooled_conn));
        };

        if let Some((idx, pooled_conn)) = get_conn() {
            trace!("LRU connection pool: connection #{idx} found for given id {id:?}");

            #[cfg(feature = "opentelemetry")]
            if let Some((metrics, metric_attrs)) = &metrics {
                metrics.total_connections.add(1, metric_attrs);
                metrics.reused_connections.add(1, metric_attrs);
            }

            return Ok(ConnectionResult::Connection(LeasedConnection {
                active_slot,
                pooled_conn: ManuallyDrop::new(pooled_conn),
                pooled_conn_taken: false,
                returner: self.returner.clone(),
                got_response: AtomicBool::new(false),
                drop_connection_if_no_response: self.drop_connection_if_no_response,
            }));
        }

        let pool_slot = match self.total_slots.clone().try_acquire_owned() {
            Ok(permit) => PoolSlot(permit),
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
                    .context("get least recently used connection from storage")?
                    .pool_slot
            }
        };

        trace!(
            "LRU connection pool: no connection for given id {id:?} found, returning create permit"
        );
        Ok(ConnectionResult::CreatePermit((active_slot, pool_slot)))
    }

    async fn create(&self, id: ID, conn: C, permit: Self::CreatePermit) -> Self::Connection {
        trace!("adding new connection (w/ id {id:?}) to pool");
        let (active_slot, pool_slot) = permit;

        #[cfg(feature = "opentelemetry")]
        if let Some(metrics) = &self.metrics.as_ref() {
            let metric_attrs = metrics.attributes(&id);
            metrics.total_connections.add(1, &metric_attrs);
            metrics.created_connections.add(1, &metric_attrs);
        }

        LeasedConnection {
            active_slot,
            returner: self.returner.clone(),
            pooled_conn: ManuallyDrop::new(PooledConnection {
                id,
                conn,
                pool_slot,
                last_used: Instant::now(),
            }),
            pooled_conn_taken: false,
            got_response: AtomicBool::new(false),
            drop_connection_if_no_response: self.drop_connection_if_no_response,
        }
    }
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
        if !self.pooled_conn_taken {
            if self.drop_connection_if_no_response && !self.got_response.load(Ordering::Relaxed) {
                trace!("LRU connection pool: dropping connection that didn't receive a response");
                unsafe { ManuallyDrop::drop(&mut self.pooled_conn) };
                return;
            }
            if let Some(watcher) = self.extensions().get_ref::<ConnectionHealthWatcher>()
                && watcher.health() == ConnectionHealth::Broken
            {
                trace!("LRU connection pool: dropping pooled connection that was marked as failed");

                // SAFETY: pooled_conn_taken is false,
                // indicating we didn't move ownership yet by
                // using Self::into_inner, and we are neither
                // returning it as is done in the other (else)
                // branch only.
                unsafe { ManuallyDrop::drop(&mut self.pooled_conn) };
            } else {
                trace!("LRU connection pool: returning pooled connection back to pool");

                // SAFETY: pooled_conn_taken is false,
                // indicating we didn't move ownership yet by
                // using Self::into_inner, and neither do we drop it as that is only
                // done in the 'truth' variant of this if-else branching
                // as can be seen above.
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
    Input: Send + 'static,
{
    type Output = C::Output;
    type Error = C::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        self.got_response.store(false, Ordering::Relaxed);
        let result = self.as_ref().serve(input).await;
        if result.is_ok() {
            self.got_response.store(true, Ordering::Relaxed);
        }
        result
    }
}

/// Helper needed so we can implement debug for LruDropPool
///
/// Implementing debug_list and debug_struct at the same time is not
/// possible, so we have to split it up
struct StorageDebugHelper<'a, C, ID: Debug> {
    deque: &'a VecDeque<PooledConnection<C, ID>>,
}

impl<'a, C, ID: Debug> Debug for StorageDebugHelper<'a, C, ID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.deque.iter().map(|item| &item.id))
            .finish()
    }
}

impl<C, ID: Debug> Debug for LruDropPool<C, ID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut builder = f.debug_struct("LruDropPool");

        // Dont block on this, its only for debugging
        match self.storage.try_lock() {
            Some(guard) => {
                let storage_debugger = StorageDebugHelper { deque: &*guard };
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
    C: Send + Sync + 'static,
    ID: Send + Sync + Debug + 'static,
{
}
#[cfg(test)]
mod tests {
    use super::super::{PooledConnector, ReqToConnID};
    use super::*;
    use crate::client::{ConnectorService, EstablishedClientConnection};
    use rama_core::ServiceInput;
    use rama_core::extensions::ExtensionsRef;
    use rama_core::{Service, extensions::Extensions};
    use std::sync::atomic::AtomicBool;
    use std::{
        convert::Infallible,
        sync::atomic::{AtomicI16, Ordering},
    };
    use tokio_test::{assert_err, assert_ok};

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

    #[derive(Debug)]
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

    impl ExtensionsRef for Conn {
        fn extensions(&self) -> &Extensions {
            &self.extensions
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
        assert_err!(conn2);

        drop(conn1);
        let _conn3 = svc
            .connect(ServiceInput::new(String::from("aaa")))
            .await
            .unwrap();
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

    #[derive(Default, Debug)]
    struct InnerService {
        should_error: Arc<AtomicBool>,
        extensions: Extensions,
    }

    impl ExtensionsRef for InnerService {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl Service<bool> for InnerService {
        type Output = ();
        type Error = BoxError;

        async fn serve(&self, should_error: bool) -> Result<Self::Output, Self::Error> {
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

    impl Service<Duration> for InnerService {
        type Output = ();
        type Error = BoxError;

        async fn serve(&self, delay: Duration) -> Result<Self::Output, Self::Error> {
            tokio::time::sleep(delay).await;
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
        assert_ok!(conn.conn.serve(false).await);
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
            conn.conn.serve(Duration::from_secs(60)),
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
        assert_ok!(conn.conn.serve(false).await);
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
            conn.conn.serve(Duration::from_secs(60)),
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
        assert_ok!(conn.conn.serve(false).await);
    }

    #[tokio::test]
    async fn test_dont_return_broken_connections_to_pool() {
        let pool = LruDropPool::try_new(1, 1).unwrap();
        let svc = PooledConnector::new(TestConnector::default(), pool, StringInputLengthID {});

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();

        let result = conn.conn.serve(false).await;
        assert_ok!(result);
        let result = conn.conn.serve(true).await;
        assert_err!(result);

        // this dropped connection should not return to the pool, otherwise it will be permanently broken
        drop(conn);

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();

        let result = conn.conn.serve(false).await;
        assert_ok!(result);

        // this connection is not broken so it should return to the pool
        drop(conn);

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();

        let result = conn.conn.serve(false).await;
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

        let result = conn.conn.serve(false).await;
        assert_ok!(result);

        // This dropped connection should return to the pool, since it's not broken yet
        let conn_extensions = conn.conn.extensions().clone();
        drop(conn);

        // Break connection -> eg go-away / tcp connection dropped by remote...
        // Normally the connection would edit this in extensions but since we dont have ownership here
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

        let result = conn.conn.serve(false).await;
        assert_ok!(result);

        // This connection is not broken so it should return to the pool
        drop(conn);

        // And we should be able to reuse it
        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap();

        let result = conn.conn.serve(false).await;
        assert_ok!(result);

        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn drop_idle_connections() {
        let pool = LruDropPool::try_new(5, 10)
            .unwrap()
            .with_idle_timeout(Duration::from_micros(1))
            .with_drop_connection_if_no_response(false);

        let svc = PooledConnector::new(TestService::default(), pool, StringInputLengthID {});

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap()
            .conn;

        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 1);
        drop(conn);
        // Need for this to consistently work in ci, we only need this sleep here
        // because we have a very very short idle timeout, this is never the problem
        // if we use realistic values
        tokio::time::sleep(Duration::from_millis(100)).await;

        let conn = svc
            .connect(ServiceInput::new(String::from("")))
            .await
            .unwrap()
            .conn;

        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 2);
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
}
