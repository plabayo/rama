use super::conn::{ConnectorService, EstablishedClientConnection};
use crate::stream::Socket;
use parking_lot::Mutex;
use rama_core::error::{BoxError, ErrorContext, OpaqueError};
use rama_core::{Context, Layer, Service};
use rama_utils::macros::generate_field_setters;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::{Arc, Weak};
use std::time::Duration;
use std::{future::Future, net::SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

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
    returner: Weak<dyn Fn(PooledConnection<C, ID>) + Send + Sync>,
}

impl<C, ID> LeasedConnection<C, ID> {
    pub fn into_connection(mut self) -> C {
        self.pooled_conn.take().expect("only None after drop").conn
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
}

/// Connection pool that uses FiFo for reuse and LRU to evict connections
pub struct FiFoReuseLruDropPool<C, ID> {
    storage: Arc<Mutex<VecDeque<PooledConnection<C, ID>>>>,
    total_slots: Arc<Semaphore>,
    active_slots: Arc<Semaphore>,
    returner: OnceLock<Arc<dyn Fn(PooledConnection<C, ID>) + Send + Sync>>,
}

impl<C, ID> Clone for FiFoReuseLruDropPool<C, ID> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            total_slots: self.total_slots.clone(),
            active_slots: self.active_slots.clone(),
            returner: self.returner.clone(),
        }
    }
}

impl<C, ID> FiFoReuseLruDropPool<C, ID> {
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
        Ok(Self {
            storage,
            returner: OnceLock::new(),
            total_slots: Arc::new(Semaphore::const_new(max_total)),
            active_slots: Arc::new(Semaphore::const_new(max_active)),
        })
    }
}

impl<C, ID> FiFoReuseLruDropPool<C, ID>
where
    C: Send + 'static,
    ID: Send + 'static,
{
    /// Create returner here instead of in [`FiFoReuseLruDropPool::new`] so we dont have to enforce trait
    /// bounds there, this makes working with a pool a lot more ergonomic
    fn returner(&self) -> Weak<dyn Fn(PooledConnection<C, ID>) + Send + Sync> {
        let returner = self.returner.get_or_init(|| {
            let weak_storage = Arc::downgrade(&self.storage);
            Arc::new(move |conn| {
                if let Some(storage) = weak_storage.upgrade() {
                    storage.lock().push_front(conn)
                }
            })
        });

        Arc::downgrade(returner)
    }
}

impl<C, ID> Pool<C, ID> for FiFoReuseLruDropPool<C, ID>
where
    C: Send + 'static,
    ID: Clone + Send + Sync + PartialEq + 'static,
{
    type Connection = LeasedConnection<C, ID>;
    type CreatePermit = (ActiveSlot, PoolSlot);

    async fn get_conn(
        &self,
        id: &ID,
    ) -> Result<ConnectionResult<Self::Connection, Self::CreatePermit>, OpaqueError> {
        let active_slot = ActiveSlot(
            self.active_slots
                .clone()
                .acquire_owned()
                .await
                .context("get active pool slot")?,
        );

        let mut storage = self.storage.lock();
        let pooled_conn = {
            storage
                .iter()
                .position(|stored| &stored.id == id)
                .and_then(|idx| storage.remove(idx))
        };

        if let Some(pooled_conn) = pooled_conn {
            return Ok(ConnectionResult::Connection(LeasedConnection {
                active_slot,
                pooled_conn: Some(pooled_conn),
                returner: self.returner(),
            }));
        }

        let pool_slot = match self.total_slots.clone().try_acquire_owned() {
            Ok(permit) => PoolSlot(permit),
            Err(_) => {
                // By poping from back when we have no new Poolslot available we implement LRU drop policy
                storage
                    .pop_back()
                    .context("get least recently used connection from storage")?
                    .pool_slot
            }
        };

        Ok(ConnectionResult::CreatePermit((active_slot, pool_slot)))
    }

    async fn create(&self, id: ID, conn: C, permit: Self::CreatePermit) -> Self::Connection {
        let (active_slot, pool_slot) = permit;
        LeasedConnection {
            active_slot,
            returner: self.returner(),
            pooled_conn: Some(PooledConnection {
                id,
                conn,
                pool_slot,
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
        if let Some(returner) = self.returner.upgrade() {
            if let Some(pooled_conn) = self.pooled_conn.take() {
                (returner)(pooled_conn);
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
    ID: Send + Sync + 'static,
    C: Service<State, Request>,
{
    type Response = C::Response;
    type Error = C::Error;

    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.as_ref().serve(ctx, req)
    }
}

impl<C, ID: Debug> Debug for FiFoReuseLruDropPool<C, ID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.storage.lock().iter().map(|item| &item.id))
            .finish()
    }
}

/// [`ReqToConnID`] is used to convert a `Request` to a connection ID. These IDs are
/// not unique and multiple connections can have the same ID. IDs are used to filter
/// which connections can be used for a specific Request in a way that is indepent of
/// what a Request is.
pub trait ReqToConnID<State, Request>: Sized + Clone + Send + Sync + 'static {
    type ID: Send + Sync + PartialEq + Clone + 'static;

    fn id(&self, ctx: &Context<State>, request: &Request) -> Result<Self::ID, OpaqueError>;
}

impl<State, Request, ID, F> ReqToConnID<State, Request> for F
where
    F: Fn(&Context<State>, &Request) -> Result<ID, OpaqueError> + Clone + Send + Sync + 'static,
    ID: Send + Sync + PartialEq + Clone + 'static,
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
    pub fn new(inner: S, pool: P, req_to_conn_id: R) -> PooledConnector<S, P, R> {
        PooledConnector {
            inner,
            pool,
            req_to_conn_id,
            wait_for_pool_timeout: None,
        }
    }

    generate_field_setters!(wait_for_pool_timeout, Duration);
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
            let pool = ctx.get::<P>().unwrap_or(&self.pool);

            let pool_result = if let Some(duration) = self.wait_for_pool_timeout {
                timeout(duration, pool.get_conn(&conn_id))
                    .await
                    .map_err(OpaqueError::from_std)?
            } else {
                pool.get_conn(&conn_id).await
            };

            match pool_result? {
                ConnectionResult::Connection(c) => {
                    return Ok(EstablishedClientConnection { ctx, conn: c, req });
                }
                ConnectionResult::CreatePermit(permit) => permit,
            }
        };

        let EstablishedClientConnection { ctx, req, conn } =
            self.inner.connect(ctx, req).await.map_err(Into::into)?;

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

    generate_field_setters!(wait_for_pool_timeout, Duration);
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

#[cfg(feature = "http")]
pub mod http {
    use std::time::Duration;

    use super::{FiFoReuseLruDropPool, PooledConnector, ReqToConnID};
    use crate::{Protocol, address::Authority, client::pool::OpaqueError, http::RequestContext};
    use rama_core::Context;
    use rama_http_types::Request;

    #[derive(Clone, Debug, Default)]
    #[non_exhaustive]
    /// [`BasicHttpConnIdentifier`] can be used together with a [`super::Pool`] to create a basic http connection pool
    pub struct BasicHttpConnIdentifier;

    pub type BasicHttpConId = (Protocol, Authority);

    impl<State, Body> ReqToConnID<State, Request<Body>> for BasicHttpConnIdentifier {
        type ID = BasicHttpConId;

        fn id(&self, ctx: &Context<State>, req: &Request<Body>) -> Result<Self::ID, OpaqueError> {
            let req_ctx = match ctx.get::<RequestContext>() {
                Some(ctx) => ctx,
                None => &RequestContext::try_from((ctx, req))?,
            };

            Ok((req_ctx.protocol.clone(), req_ctx.authority.clone()))
        }
    }

    pub struct HttpPooledConnectorBuilder {
        max_total: usize,
        max_active: usize,
        wait_for_pool_timeout: Option<Duration>,
    }

    impl Default for HttpPooledConnectorBuilder {
        fn default() -> Self {
            Self {
                max_total: 100,
                max_active: 20,
                wait_for_pool_timeout: None,
            }
        }
    }

    impl HttpPooledConnectorBuilder {
        pub fn new() -> Self {
            Self::default()
        }

        /// Set the max amount of connections that this connection pool will contain
        ///
        /// This is the sum of active connections and idle connections. When this limit
        /// is hit idle connections will be replaced with new ones.
        pub fn max_total(mut self, max: usize) -> Self {
            self.max_total = max;
            self
        }

        /// Set the max amount of connections that can actively be used
        ///
        /// Requesting a connection from the pool will block until the pool
        /// is below max capacity again.
        pub fn max_active(mut self, max: usize) -> Self {
            self.max_active = max;
            self
        }

        /// When a pool is operating at max active capacity wait for this duration
        /// before the connector raises a timeout error
        pub fn with_wait_for_pool_timeout(mut self, duration: Duration) -> Self {
            self.wait_for_pool_timeout = Some(duration);
            self
        }

        pub fn maybe_with_wait_for_pool_timeout(mut self, duration: Option<Duration>) -> Self {
            self.wait_for_pool_timeout = duration;
            self
        }

        pub fn build<C, S>(
            self,
            inner: S,
        ) -> Result<
            PooledConnector<S, FiFoReuseLruDropPool<C, BasicHttpConId>, BasicHttpConnIdentifier>,
            OpaqueError,
        > {
            let pool = FiFoReuseLruDropPool::new(self.max_active, self.max_total)?;
            Ok(PooledConnector::new(inner, pool, BasicHttpConnIdentifier)
                .maybe_with_wait_for_pool_timeout(self.wait_for_pool_timeout))
        }
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
    use tokio_test::assert_err;

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

    #[tokio::test]
    async fn test_should_reuse_connections() {
        let pool = FiFoReuseLruDropPool::new(5, 10).unwrap();
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
        let pool = FiFoReuseLruDropPool::new(5, 10).unwrap();
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
        let pool = FiFoReuseLruDropPool::new(1, 1).unwrap();
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
}
