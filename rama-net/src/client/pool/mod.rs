use super::conn::{ConnectorService, EstablishedClientConnection};
use crate::stream::Socket;
use parking_lot::Mutex;
use rama_core::error::{BoxError, ErrorContext, OpaqueError};
use rama_core::telemetry::tracing::trace;
use rama_core::{Context, Layer, Service};
use rama_utils::macros::generate_set_and_with;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use std::{future::Future, net::SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "opentelemetry")]
pub mod metrics;

/// [`PoolStorage`] implements the storage part of a connection pool. This storage
/// also decides which connection it returns for a given ID or when the caller asks to
/// remove one, this results in the storage deciding which mode we use for connection
/// reuse and dropping (eg FIFO for reuse and LRU for dropping conn when pool is full)
pub trait Pool<C, ID>: Send + Sync + 'static {
    type Connection: Send;
    type CreatePermit: Send;

    /// Get a connection from the pool, if no connection is found a [`Pool::CreatePermit`] is returned
    ///
    /// A [`Pool::CreatePermit`] is needed to add a new connection to the pool. Depending on how
    /// the [`Pool::CreatePermit`] is used a pool can implement policies for max connection and max
    /// total connections.
    fn get_conn(
        &self,
        id: &ID,
    ) -> impl Future<
        Output = Result<ConnectionResult<Self::Connection, Self::CreatePermit>, OpaqueError>,
    > + Send;

    /// Create/add a new connection to the pool
    ///
    /// To be able to a connection to the pool you need a [`Pool::CreatePermit`], depending on
    /// how the pool implements this you might need to call [`Pool::get_conn`] to get this first.
    fn create(
        &self,
        id: ID,
        conn: C,
        create_permit: Self::CreatePermit,
    ) -> impl Future<Output = Self::Connection> + Send;
}

/// Result returned by a successful call to [`Pool::get_conn`]
pub enum ConnectionResult<C, P> {
    /// Connection which matches given ID and is ready to be used
    Connection(C),
    /// If no connection is found for the given ID a [`Pool::CreatePermit`]
    /// is returned. This permit can be used to create/add a new connection to the pool.
    CreatePermit(P),
}

impl<C: Debug, P: Debug> Debug for ConnectionResult<C, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(arg0) => f.debug_tuple("Connection").field(arg0).finish(),
            Self::CreatePermit(arg0) => f.debug_tuple("CreatePermit").field(arg0).finish(),
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Connection pool that doesn't store connections and has no limits.
///
/// Basically this pool operates like there would be no connection pooling.
/// Can be used in places where were we work with a [`PooledConnector`], but
/// don't want connection pooling to happen.
pub struct NoPool;

impl<C, ID> Pool<C, ID> for NoPool
where
    C: Send + 'static,
    ID: Clone + Send + Sync + PartialEq + 'static,
{
    type Connection = C;
    type CreatePermit = ();

    async fn get_conn(
        &self,
        _id: &ID,
    ) -> Result<ConnectionResult<Self::Connection, Self::CreatePermit>, OpaqueError> {
        Ok(ConnectionResult::CreatePermit(()))
    }

    async fn create(&self, _id: ID, conn: C, _permit: Self::CreatePermit) -> Self::Connection {
        conn
    }
}

/// [`LeasedConnection`] is a connection that is temporarily leased from a pool
///
/// It will be returned to the pool once dropped if the user didn't
/// take ownership of the connection `C` with [`LeasedConnection::into_connection()`].
/// [`LeasedConnection`]s are considered active pool connections until dropped or
/// ownership is taken of the internal connection.
pub struct LeasedConnection<C, ID> {
    pooled_conn: Option<PooledConnection<C, ID>>,
    active_slot: ActiveSlot,
    returner: ConnReturner<C, ID>,
    failed: AtomicBool,
}

impl<C, ID> LeasedConnection<C, ID> {
    pub fn into_connection(mut self) -> C {
        self.pooled_conn.take().expect("only None after drop").conn
    }

    pub fn mark_as_failed(&self) {
        self.failed
            .store(true, std::sync::atomic::Ordering::Relaxed);
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

#[deprecated = "use LruDropPool instead"]
pub type FiFoReuseLruDropPool<C, ID> = LruDropPool<C, ID>;

/// Connection pool that uses LRU to evict connections
pub struct LruDropPool<C, ID> {
    storage: Arc<Mutex<VecDeque<PooledConnection<C, ID>>>>,
    total_slots: Arc<Semaphore>,
    active_slots: Arc<Semaphore>,
    idle_timeout: Option<Duration>,
    returner: ConnReturner<C, ID>,
    reuse_strategy: ReuseStrategy,
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

impl ReuseStrategy {
    fn get_conn<C, ID: PartialEq>(
        self,
        storage: &mut VecDeque<PooledConnection<C, ID>>,
        id: &ID,
    ) -> Option<(usize, PooledConnection<C, ID>)> {
        let idx = match self {
            Self::FiFo => storage.iter().position(|stored| &stored.id == id)?,
            Self::RoundRobin => storage.iter().rposition(|stored| &stored.id == id)?,
        };

        let pooled_conn = storage.remove(idx)?;
        Some((idx, pooled_conn))
    }
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
            #[cfg(feature = "opentelemetry")]
            metrics: self.metrics.clone(),
        }
    }
}

impl<C, ID> LruDropPool<C, ID> {
    pub fn new(max_active: usize, max_total: usize) -> Result<Self, OpaqueError> {
        if max_active == 0 || max_total == 0 {
            return Err(OpaqueError::from_display(
                "max_active or max_total of 0 will make this pool unusable",
            ));
        }
        if max_active > max_total {
            return Err(OpaqueError::from_display(
                "max_active should be smaller or equal to max_total",
            ));
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

    #[cfg(feature = "opentelemetry")]
    generate_set_and_with! {
        pub fn metrics(mut self, metrics: Option<Arc<metrics::PoolMetrics>>) -> Self {
            self.metrics = metrics;
            self
        }
    }
}

impl<C, ID> Pool<C, ID> for LruDropPool<C, ID>
where
    C: Send + 'static,
    ID: ConnID,
{
    type Connection = LeasedConnection<C, ID>;
    type CreatePermit = (ActiveSlot, PoolSlot);

    async fn get_conn(
        &self,
        id: &ID,
    ) -> Result<ConnectionResult<Self::Connection, Self::CreatePermit>, OpaqueError> {
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

        if let Some((idx, pooled_conn)) = self.reuse_strategy.get_conn(&mut storage, id) {
            trace!("LRU connection pool: connection #{idx} found for given id {id:?}");

            #[cfg(feature = "opentelemetry")]
            if let Some((metrics, metric_attrs)) = &metrics {
                metrics.total_connections.add(1, metric_attrs);
                metrics.reused_connections.add(1, metric_attrs);
                metrics
                    .reused_connection_pos
                    .record(idx as u64, metric_attrs);
            }

            return Ok(ConnectionResult::Connection(LeasedConnection {
                active_slot,
                pooled_conn: Some(pooled_conn),
                returner: self.returner.clone(),
                failed: AtomicBool::new(false),
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
            failed: false.into(),
            pooled_conn: Some(PooledConnection {
                id,
                conn,
                pool_slot,
                last_used: Instant::now(),
            }),
        }
    }
}

#[expect(dead_code)]
#[derive(Debug)]
/// Active slot is able to actively use a connection to make requests.
/// They are used to track 'active' connections inside the pool
pub struct ActiveSlot(OwnedSemaphorePermit);

#[expect(dead_code)]
#[derive(Debug)]
/// Pool slot is needed to add a connection to the pool. Poolslots have
/// a one to one mapping to connections inside the pool, and are used
/// to track the 'total' connections inside the pool
pub struct PoolSlot(OwnedSemaphorePermit);

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
    C: Debug,
    ID: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeasedConnection")
            .field("pooled_conn", &self.pooled_conn)
            .field("active_slot", &self.active_slot)
            .finish()
    }
}

impl<C, ID> Deref for LeasedConnection<C, ID> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self
            .pooled_conn
            .as_ref()
            .expect("only None after drop")
            .conn
    }
}

impl<C, ID> DerefMut for LeasedConnection<C, ID> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self
            .pooled_conn
            .as_mut()
            .expect("only None after drop")
            .conn
    }
}

impl<C, ID> AsRef<C> for LeasedConnection<C, ID> {
    fn as_ref(&self) -> &C {
        self
    }
}

impl<C, ID> AsMut<C> for LeasedConnection<C, ID> {
    fn as_mut(&mut self) -> &mut C {
        self
    }
}

impl<C, ID> Drop for LeasedConnection<C, ID> {
    fn drop(&mut self) {
        if let Some(pooled_conn) = self.pooled_conn.take() {
            if self.failed.load(std::sync::atomic::Ordering::Relaxed) {
                trace!("LRU connection pool: dropping pooled connection that was marked as failed");
            } else {
                trace!("LRU connection pool: returning pooled connection back to pool");
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
    C: Socket,
{
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.as_ref().local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.as_ref().peer_addr()
    }
}

impl<C, ID> AsyncWrite for LeasedConnection<C, ID>
where
    C: AsyncWrite + Unpin,
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

impl<C, ID> AsyncRead for LeasedConnection<C, ID>
where
    C: AsyncRead + Unpin,
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

impl<State, Request, C, ID> Service<State, Request> for LeasedConnection<C, ID>
where
    ID: Send + Sync + Debug + 'static,
    C: Service<State, Request>,
    Request: Send + 'static,
    State: Send + Sync + 'static,
{
    type Response = C::Response;
    type Error = C::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let result = self.as_ref().serve(ctx, req).await;
        if result.is_err() {
            let id = &self.pooled_conn.as_ref().expect("msg").id;
            trace!(
                "LRU connection pool: detected error result, marking connection w/ id {id:?} as failed"
            );
            self.mark_as_failed();
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

/// [`ReqToConnID`] is used to convert a `Request` to a connection ID. These IDs
/// are not unique and multiple connections can have the same ID. IDs are used
/// to filter which connections can be used for a specific Request in a way that
/// is independent of what a Request is.
pub trait ReqToConnID<State, Request>: Sized + Clone + Send + Sync + 'static {
    type ID: ConnID;

    fn id(&self, ctx: &Context<State>, request: &Request) -> Result<Self::ID, OpaqueError>;
}

/// [`ConnID`] is used to identify a connection in a connection pool. These IDs
/// are not unique and multiple connections can have the same ID. IDs are used
/// to filter which connections can be used for a specific Request in a way that
/// is independent of what a Request is.
pub trait ConnID: Send + Sync + PartialEq + Clone + Debug + 'static {
    #[cfg(feature = "opentelemetry")]
    /// Returns a list of attributes to add to metrics generated by the
    /// connection pool.
    fn attributes(&self) -> impl Iterator<Item = rama_core::telemetry::opentelemetry::KeyValue> {
        std::iter::empty()
    }
}

impl<State, Request, ID, F> ReqToConnID<State, Request> for F
where
    F: Fn(&Context<State>, &Request) -> Result<ID, OpaqueError> + Clone + Send + Sync + 'static,
    ID: ConnID,
{
    type ID = ID;

    fn id(&self, ctx: &Context<State>, request: &Request) -> Result<Self::ID, OpaqueError> {
        self(ctx, request)
    }
}

pub struct PooledConnector<S, P, R> {
    inner: S,
    pool: P,
    req_to_conn_id: R,
    wait_for_pool_timeout: Option<Duration>,
}

impl<S, P, R> PooledConnector<S, P, R> {
    pub fn new(inner: S, pool: P, req_to_conn_id: R) -> Self {
        Self {
            inner,
            pool,
            req_to_conn_id,
            wait_for_pool_timeout: None,
        }
    }

    generate_set_and_with!(
        /// Set timeout after which requesting a connection from the pool will timeout
        ///
        /// If no timeout is specified there will be no limit, this could be dangerous
        /// depending on how many users are waiting for a connection
        pub fn wait_for_pool_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.wait_for_pool_timeout = timeout;
            self
        }
    );
}

impl<State, Request, S, P, R> Service<State, Request> for PooledConnector<S, P, R>
where
    S: ConnectorService<State, Request, Connection: Send, Error: Send + 'static>,
    State: Send + Sync + 'static,
    Request: Send + 'static,
    P: Pool<S::Connection, R::ID>,
    R: ReqToConnID<State, Request>,
{
    type Response = EstablishedClientConnection<P::Connection, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let conn_id = self.req_to_conn_id.id(&ctx, &req)?;

        // Try to get connection from pool, if no connection is found, we will have to create a new
        // one using the returned create permit
        let create_permit = {
            let pool = if let Some(pool) = ctx.get::<P>() {
                trace!("pooled connector: using pool from ctx");
                pool
            } else {
                trace!("pooled connector: using pool from connector");
                &self.pool
            };

            let pool_result = if let Some(duration) = self.wait_for_pool_timeout {
                timeout(duration, pool.get_conn(&conn_id))
                    .await
                    .map_err(|err|{
                        trace!("pooled connector: timeout triggered while waiting for a connection (/w conn id: {conn_id:?}) from pool");
                        OpaqueError::from_std(err)
                    })?
            } else {
                pool.get_conn(&conn_id).await
            };

            match pool_result? {
                ConnectionResult::Connection(c) => {
                    trace!(
                        "pooled connector: got connection (w/ conn id: {conn_id:?}) from pool, returning"
                    );
                    return Ok(EstablishedClientConnection { ctx, conn: c, req });
                }
                ConnectionResult::CreatePermit(permit) => {
                    trace!(
                        "pooled connector: no connection (w/ conn id: {conn_id:?}) found, received permit to create a new one"
                    );
                    permit
                }
            }
        };

        let EstablishedClientConnection { ctx, req, conn } =
            self.inner.connect(ctx, req).await.map_err(Into::into)?;

        trace!("pooled connector: returning new pooled connection (w/ conn id: {conn_id:?}");
        let pool = ctx.get::<P>().unwrap_or(&self.pool);
        let conn = pool.create(conn_id, conn, create_permit).await;
        Ok(EstablishedClientConnection { ctx, req, conn })
    }
}

pub struct PooledConnectorLayer<P, R> {
    pool: P,
    req_to_conn_id: R,
    wait_for_pool_timeout: Option<Duration>,
}

impl<P, R> PooledConnectorLayer<P, R> {
    pub fn new(pool: P, req_to_conn_id: R) -> Self {
        Self {
            pool,
            req_to_conn_id,
            wait_for_pool_timeout: None,
        }
    }

    generate_set_and_with!(
        /// Set timeout after which requesting a connection from the pool will timeout
        ///
        /// If no timeout is specified there will be no limit, this could be dangerous
        /// depending on how many users are waiting for a connection
        pub fn wait_for_pool_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.wait_for_pool_timeout = timeout;
            self
        }
    );
}

impl<S, P: Clone, R: Clone> Layer<S> for PooledConnectorLayer<P, R> {
    type Service = PooledConnector<S, P, R>;

    fn layer(&self, inner: S) -> Self::Service {
        PooledConnector::new(inner, self.pool.clone(), self.req_to_conn_id.clone())
            .maybe_with_wait_for_pool_timeout(self.wait_for_pool_timeout)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        PooledConnector::new(inner, self.pool, self.req_to_conn_id)
            .maybe_with_wait_for_pool_timeout(self.wait_for_pool_timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::EstablishedClientConnection;
    use rama_core::{Context, Service};
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

    impl<State, Request> Service<State, Request> for TestService
    where
        State: Clone + Send + Sync + 'static,
        Request: Send + 'static,
    {
        type Response = EstablishedClientConnection<Vec<u32>, State, Request>;
        type Error = Infallible;

        async fn serve(
            &self,
            ctx: Context<State>,
            req: Request,
        ) -> Result<Self::Response, Self::Error> {
            let conn = vec![];
            self.created_connection.fetch_add(1, Ordering::Relaxed);
            Ok(EstablishedClientConnection { ctx, req, conn })
        }
    }

    #[derive(Clone)]
    /// [`StringRequestLengthID`] will map Requests of type String, to usize id representing their
    /// chars length. In practise this will mean that Requests of the same char length will be
    /// able to reuse the same connections
    struct StringRequestLengthID;

    impl<State> ReqToConnID<State, String> for StringRequestLengthID {
        type ID = usize;

        fn id(&self, _ctx: &Context<State>, req: &String) -> Result<Self::ID, OpaqueError> {
            Ok(req.chars().count())
        }
    }

    impl ConnID for usize {}
    impl ConnID for () {}

    #[tokio::test]
    async fn test_should_reuse_connections() {
        let pool = LruDropPool::new(5, 10).unwrap();
        // We use a closure here to maps all requests to `()` id, this will result in all connections being shared and the pool
        // acting like like a global connection pool (eg database connection pool where all connections can be used).
        let svc = PooledConnector::new(
            TestService::default(),
            pool,
            |_ctx: &Context<()>, _req: &String| Ok(()),
        );

        let iterations = 10;
        for _i in 0..iterations {
            let _conn = svc
                .connect(Context::default(), String::new())
                .await
                .unwrap();
        }

        let created_connection = svc.inner.created_connection.load(Ordering::Relaxed);
        assert_eq!(created_connection, 1);
    }

    #[tokio::test]
    async fn test_conn_id_to_separate() {
        let pool = LruDropPool::new(5, 10).unwrap();
        let svc = PooledConnector::new(TestService::default(), pool, StringRequestLengthID {});

        {
            let mut conn = svc
                .connect(Context::default(), String::from("a"))
                .await
                .unwrap()
                .conn;

            conn.push(1);
            assert_eq!(conn.as_ref(), &vec![1]);
            assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 1);
        }

        // Should reuse the same connections
        {
            let mut conn = svc
                .connect(Context::default(), String::from("B"))
                .await
                .unwrap()
                .conn;

            conn.push(2);
            assert_eq!(conn.as_ref(), &vec![1, 2]);
            assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 1);
        }

        // Should make a new one
        {
            let mut conn = svc
                .connect(Context::default(), String::from("aa"))
                .await
                .unwrap()
                .conn;

            conn.push(3);
            assert_eq!(conn.as_ref(), &vec![3]);
            assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 2);
        }

        // Should reuse
        {
            let mut conn = svc
                .connect(Context::default(), String::from("bb"))
                .await
                .unwrap()
                .conn;

            conn.push(4);
            assert_eq!(conn.as_ref(), &vec![3, 4]);
            assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 2);
        }
    }

    #[tokio::test]
    async fn test_pool_max_size() {
        let pool = LruDropPool::new(1, 1).unwrap();
        let svc = PooledConnector::new(TestService::default(), pool, StringRequestLengthID {})
            .with_wait_for_pool_timeout(Duration::from_millis(50));

        let conn1 = svc
            .connect(Context::default(), String::from("a"))
            .await
            .unwrap();

        let conn2 = svc.connect(Context::default(), String::from("a")).await;
        assert_err!(conn2);

        drop(conn1);
        let _conn3 = svc
            .connect(Context::default(), String::from("aaa"))
            .await
            .unwrap();
    }

    #[derive(Default)]
    struct TestConnector {
        pub created_connection: AtomicI16,
    }

    impl<State, Request> Service<State, Request> for TestConnector
    where
        State: Clone + Send + Sync + 'static,
        Request: Send + 'static,
    {
        type Response = EstablishedClientConnection<InnerService, State, Request>;
        type Error = Infallible;

        async fn serve(
            &self,
            ctx: Context<State>,
            req: Request,
        ) -> Result<Self::Response, Self::Error> {
            let conn = InnerService::default();
            self.created_connection.fetch_add(1, Ordering::Relaxed);
            Ok(EstablishedClientConnection { ctx, req, conn })
        }
    }

    #[derive(Default, Debug)]
    struct InnerService {
        should_error: AtomicBool,
    }

    impl<State> Service<State, bool> for InnerService
    where
        State: Clone + Send + Sync + 'static,
    {
        type Response = ();
        type Error = OpaqueError;

        async fn serve(
            &self,
            _ctx: Context<State>,
            should_error: bool,
        ) -> Result<Self::Response, Self::Error> {
            // Once this service is broken it will stay in this state, similar to a closed tcp connection
            if should_error {
                self.should_error.store(true, Ordering::Relaxed);
            }

            if self.should_error.load(Ordering::Relaxed) {
                Err(OpaqueError::from_display("service is in broken state"))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_dont_return_broken_connections_to_pool() {
        let pool = LruDropPool::new(1, 1).unwrap();
        let svc = PooledConnector::new(TestConnector::default(), pool, StringRequestLengthID {});

        let conn = svc
            .connect(Context::default(), String::from(""))
            .await
            .unwrap();

        let result = conn.conn.serve(Context::default(), false).await;
        assert_ok!(result);
        let result = conn.conn.serve(Context::default(), true).await;
        assert_err!(result);

        // this dropped connection should not return to the pool, otherwise it will be permanently broken
        drop(conn);

        let conn = svc
            .connect(Context::default(), String::from(""))
            .await
            .unwrap();

        let result = conn.conn.serve(Context::default(), false).await;
        assert_ok!(result);

        // this connection is not broken so it should return to the pool
        drop(conn);

        let conn = svc
            .connect(Context::default(), String::from(""))
            .await
            .unwrap();

        let result = conn.conn.serve(Context::default(), false).await;
        assert_ok!(result);

        assert_eq!(svc.inner.created_connection.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn drop_idle_connections() {
        let pool = LruDropPool::new(5, 10)
            .unwrap()
            .with_idle_timeout(Duration::from_micros(1));

        let svc = PooledConnector::new(TestService::default(), pool, StringRequestLengthID {});

        let conn = svc
            .connect(Context::default(), String::from(""))
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
            .connect(Context::default(), String::from(""))
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
        let pool = LruDropPool::new(5, 10)
            .unwrap()
            .with_reuse_strategy(strategy);

        let svc =
            PooledConnector::new(
                TestService::default(),
                pool,
                |_: &Context<_>, _: &()| Ok(()),
            );

        // Open two concurrent connections and drop them.
        let mut conns = Vec::new();
        for i in 0..2 {
            let mut conn = svc.connect(Context::default(), ()).await.unwrap().conn;
            conn.pooled_conn.as_mut().unwrap().conn.push(i);
            conns.push(conn);
        }

        drop(conns);

        // We should now have two connections with the same key in the pool,
        // from most to least recently used. ([conn2, conn1]). Requesting
        // another connection should return the first or last one depending on
        // the reuse policy.
        let conn = svc.connect(Context::default(), ()).await.unwrap().conn;

        assert_eq!(conn.pooled_conn.as_ref().unwrap().conn[0], expected);
    }
}
