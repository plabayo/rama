use super::conn::{ConnectorService, EstablishedClientConnection};
use crate::stream::Socket;
use parking_lot::Mutex;
use rama_core::error::{BoxError, ErrorContext, OpaqueError};
use rama_core::{Context, Service};
use rama_utils::macros::{impl_deref, nz};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::num::NonZeroU16;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;
use std::{future::Future, net::SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

#[expect(dead_code)]
#[derive(Debug)]
/// Active slot is able to actively use a connection to make requests.
/// They are used to track 'active' connections inside the pool
struct ActiveSlot(OwnedSemaphorePermit);

#[expect(dead_code)]
#[derive(Debug)]
/// Pool slot is needed to add a connection to the pool. Poolslots have
/// a one to one mapping to connections inside the pool, and are used
/// to track the 'total' connections inside the pool
struct PoolSlot(OwnedSemaphorePermit);

/// A connection which is stored in a pool. A hash is used to determine
/// which connections can be used for a request. This hash encodes
/// all the details that make a connection unique/suitable for a request.
struct PooledConnection<C, ConnId> {
    /// Actual raw connection that is stored in pool
    conn: C,
    /// ID is not unique but is used to group connections that can be used for the same request
    id: ConnId,
    /// Slot this connection takes up in the pool
    slot: PoolSlot,
}

impl<C: Debug, ConnId: Debug> Debug for PooledConnection<C, ConnId> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledConnection")
            .field("conn", &self.conn)
            .field("id", &self.id)
            .field("slot", &self.slot)
            .finish()
    }
}

/// [`LeasedConnection`] is a connection that is temporarily leased from
/// a pool and that will be returned to the pool once dropped if user didn't
/// take ownership of the connection `C` with [`LeasedConnection::conn_to_owned()`].
/// [`LeasedConnection`]s are considered active pool connections until dropped or
/// ownership is taken of the internal connection.
pub struct LeasedConnection<C, ConnId> {
    pooled_conn: Option<PooledConnection<C, ConnId>>,
    /// Weak reference to pool so we can return connections on drop
    pool: Weak<PoolInner<C, ConnId>>,
    _slot: ActiveSlot,
}

impl<C: Debug, ConnId: Debug> Debug for LeasedConnection<C, ConnId> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeasedConnection")
            .field("pooled_conn", &self.pooled_conn)
            .field("pool", &self.pool)
            .field("_slot", &self._slot)
            .finish()
    }
}

impl<C, ConnId> LeasedConnection<C, ConnId> {
    /// Take ownership of the internal connection. This will remove it from the pool.
    pub fn take(mut self) -> C {
        let conn = self.pooled_conn.take().expect("only None after drop").conn;
        conn
    }
}

impl<C, ConnId> Deref for LeasedConnection<C, ConnId> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self
            .pooled_conn
            .as_ref()
            .expect("only None after drop")
            .conn
    }
}

impl<C, ConnId> DerefMut for LeasedConnection<C, ConnId> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self
            .pooled_conn
            .as_mut()
            .expect("only None after drop")
            .conn
    }
}

impl<C, ConnId> AsRef<C> for LeasedConnection<C, ConnId> {
    fn as_ref(&self) -> &C {
        self
    }
}

impl<C, ConnId> AsMut<C> for LeasedConnection<C, ConnId> {
    fn as_mut(&mut self) -> &mut C {
        self
    }
}

impl<C, ConnId> Drop for LeasedConnection<C, ConnId> {
    fn drop(&mut self) {
        if let (Some(pool), Some(pooled_conn)) = (self.pool.upgrade(), self.pooled_conn.take()) {
            pool.return_pooled_conn(pooled_conn);
        }
    }
}

// We want to be able to use LeasedConnection as a transparent wrapper around our connection.
// To achieve that we conditially implement all traits that are used by our Connectors

impl<C: Socket, ConnId: Sync + Send + 'static> Socket for LeasedConnection<C, ConnId> {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.as_ref().local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.as_ref().peer_addr()
    }
}

impl<C: AsyncWrite + Unpin, ConnId: Unpin> AsyncWrite for LeasedConnection<C, ConnId> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        // let x = self.deref_mut().deref_mut();
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
}

impl<C: AsyncRead + Unpin, R: Unpin> AsyncRead for LeasedConnection<C, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(self.deref_mut().as_mut()).poll_read(cx, buf)
    }
}

impl<State, Request, C: Service<State, Request>, ConnId: Send + Sync + 'static>
    Service<State, Request> for LeasedConnection<C, ConnId>
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

struct PoolInner<C, ConnId> {
    total_slots: Arc<Semaphore>,
    active_slots: Arc<Semaphore>,
    connections: Mutex<ConnectionStore<C, ConnId>>,
    // TODO support different modes, right now use LIFO to get connection
    // and LRU to evict. In other words we always insert in front, start
    // searching in front and always drop the back if needed.
}

impl<C, ConnId> PoolInner<C, ConnId> {
    fn return_pooled_conn(&self, conn: PooledConnection<C, ConnId>) {
        self.connections.lock().push_front(conn);
    }
}

impl<C, ConnId: Debug> Debug for PoolInner<C, ConnId> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolInner")
            .field("total_slots", &self.total_slots)
            .field("active_slots", &self.active_slots)
            .field("connections", &self.connections.lock())
            .finish()
    }
}

/// Connections are stored here. Wrapper around VecDeque so we can implement
/// proper debug printing
struct ConnectionStore<C, ConnId>(VecDeque<PooledConnection<C, ConnId>>);
impl_deref!(ConnectionStore<C, ConnId>: VecDeque<PooledConnection<C, ConnId>>);

impl<C, ConnId> ConnectionStore<C, ConnId> {
    fn new(capacity: usize) -> Self {
        Self(VecDeque::with_capacity(capacity))
    }
}

impl<C, ConnId: Debug> Debug for ConnectionStore<C, ConnId> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.iter().map(|item| &item.id))
            .finish()
    }
}

#[derive(Clone)]
/// Connection pool which can be used to store and reuse existing connection.
/// This struct can be copied and passed around as needed
pub struct Pool<C, ConnId> {
    inner: Arc<PoolInner<C, ConnId>>,
}

impl<C, ConnId: Debug> Debug for Pool<C, ConnId> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool").field("inner", &self.inner).finish()
    }
}

impl<C, ConnId: Clone + PartialEq> Default for Pool<C, ConnId> {
    fn default() -> Self {
        Self::new(nz!(10), nz!(20)).unwrap()
    }
}

/// Return type of [`Pool::get_connection_or_create_cb()`] to support advanced use cases
pub enum GetConnectionOrCreate<C, F, ConnId>
where
    F: FnOnce(C) -> LeasedConnection<C, ConnId>,
{
    /// Connection was found in pool for given hash and is ready to be used
    LeasedConnection(LeasedConnection<C, ConnId>),
    /// Pool doesn't have connection for hash but instead returns a function
    /// which should be called by the external user to put a new connection
    /// inside the pool. This fn also instantly returns a [`LeasedConnection`]
    /// that is ready to be used
    AddConnection(F),
}

impl<C, ConnId: Clone + PartialEq> Pool<C, ConnId> {
    pub fn new(max_active: NonZeroU16, max_total: NonZeroU16) -> Result<Self, OpaqueError> {
        if max_active > max_total {
            return Err(OpaqueError::from_display(
                "max_active should be <= then max_total connection",
            ));
        }
        let max_total: usize = Into::<u16>::into(max_total).into();
        Ok(Self {
            inner: Arc::new(PoolInner {
                total_slots: Arc::new(Semaphore::new(max_total)),
                active_slots: Arc::new(Semaphore::new(Into::<u16>::into(max_active).into())),
                connections: Mutex::new(ConnectionStore::new(max_total)),
            }),
        })
    }

    /// Get connection or create a new using provided async fn if we don't find one inside pool
    pub async fn get_connection_or_create<F, Fut>(
        &self,
        id: &ConnId,
        create_conn: F,
    ) -> Result<LeasedConnection<C, ConnId>, OpaqueError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<C, OpaqueError>>,
    {
        match self.get_connection_or_create_cb(id).await? {
            GetConnectionOrCreate::LeasedConnection(leased_connection) => Ok(leased_connection),
            GetConnectionOrCreate::AddConnection(add) => {
                let conn = create_conn().await?;
                Ok(add(conn))
            }
        }
    }

    /// Get connection from pool or return fn to add a new one. See [`GetConnectionOrCreate`] for more info
    pub async fn get_connection_or_create_cb(
        &self,
        id: &ConnId,
    ) -> Result<
        GetConnectionOrCreate<C, impl FnOnce(C) -> LeasedConnection<C, ConnId>, ConnId>,
        OpaqueError,
    > {
        let active_permit = self
            .inner
            .active_slots
            .clone()
            .acquire_owned()
            .await
            .context("failed to acquire active slot permit")?;

        let active_slot = ActiveSlot(active_permit);
        let pool = Arc::<PoolInner<C, ConnId>>::downgrade(&self.inner);

        // Check if we can reuse stored connection
        let pooled_conn = {
            let mut connections = self.inner.connections.lock();
            connections
                .iter()
                .position(|stored| &stored.id == id)
                .map(|idx| connections.remove(idx))
                .flatten()
        };

        if pooled_conn.is_some() {
            let leased_conn = LeasedConnection {
                _slot: active_slot,
                pooled_conn,
                pool,
            };
            return Ok(GetConnectionOrCreate::LeasedConnection(leased_conn));
        };

        // If we have an active slot we should always be able to get a pool slot. Unless our pool
        // is totally full, and in that case we just need to drop one connection and use that slot instead
        let pool_slot = match self.inner.total_slots.clone().try_acquire_owned() {
            Ok(pool_permit) => PoolSlot(pool_permit),
            Err(_) => {
                let pooled_conn = self.inner.connections.lock().pop_back().context(
                    "connections vec cannot be empty if total slots doesn't have permit available",
                )?;
                pooled_conn.slot
            }
        };

        Ok(GetConnectionOrCreate::AddConnection(move |conn: C| {
            LeasedConnection {
                _slot: active_slot,
                pool,
                pooled_conn: Some(PooledConnection {
                    conn,
                    id: id.clone(),
                    slot: pool_slot,
                }),
            }
        }))
    }
}

/// [`ReqToConnId`] is used to convert a `Request` to a connection ID. These IDs are
/// not unique and multiple connections can have the same ID. IDs are used to filter
/// which connections can be used for a specific Request in a way that is indepent of
/// what a Request is.
pub trait ReqToConnId<Request>: Sized + Send + Sync + 'static
where
    Request: Send + 'static,
{
    type ConnId: Send + Sync + PartialEq + Clone + 'static;

    fn id(&self, request: Request) -> (Request, Self::ConnId);
}

impl<Request, ConnId, F> ReqToConnId<Request> for F
where
    F: Fn(Request) -> (Request, ConnId) + Send + Sync + 'static,
    Request: Send + 'static,
    ConnId: Send + Sync + PartialEq + Clone + 'static,
{
    type ConnId = ConnId;

    fn id(&self, request: Request) -> (Request, Self::ConnId) {
        self(request)
    }
}

/// [`PooledConnector`] is a connector that will keep connections around in a local pool
/// so they can be reused later. If no connections are available for a specifc `id`
/// it will create a new one.
pub struct PooledConnector<S, C, Request: Send + 'static, R: ReqToConnId<Request>> {
    inner: S,
    pool: Pool<C, R::ConnId>,
    req_to_conn_id: R,
    wait_for_pool_timeout: Option<Duration>,
}

impl<S, C, Request: Send + 'static, R: ReqToConnId<Request>> PooledConnector<S, C, Request, R> {
    pub fn new(
        inner: S,
        pool: Pool<C, R::ConnId>,
        req_to_conn_id: R,
    ) -> PooledConnector<S, C, Request, R> {
        PooledConnector {
            inner,
            pool,
            req_to_conn_id,
            wait_for_pool_timeout: None,
        }
    }

    pub fn with_wait_for_pool_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.wait_for_pool_timeout = timeout;
        self
    }
}

impl<State, Request, S, R> Service<State, Request> for PooledConnector<S, S::Connection, Request, R>
where
    S: ConnectorService<State, Request, Connection: Send, Error: Send + Sync + 'static>,
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
    R: ReqToConnId<Request>,
{
    type Response =
        EstablishedClientConnection<LeasedConnection<S::Connection, R::ConnId>, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let (req, conn_id) = self.req_to_conn_id.id(req);

        let pool_result = if let Some(duration) = self.wait_for_pool_timeout {
            timeout(duration, self.pool.get_connection_or_create_cb(&conn_id))
                .await
                .map_err(|err| OpaqueError::from_std(err))?
        } else {
            self.pool.get_connection_or_create_cb(&conn_id).await
        }?;

        let (ctx, req, leased_conn) = match pool_result {
            GetConnectionOrCreate::LeasedConnection(leased_conn) => (ctx, req, leased_conn),
            GetConnectionOrCreate::AddConnection(cb) => {
                let EstablishedClientConnection { ctx, req, conn } =
                    self.inner.connect(ctx, req).await.map_err(Into::into)?;
                let leased_conn = cb(conn);
                (ctx, req, leased_conn)
            }
        };

        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: leased_conn,
        })
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

    /// [`StringRequestLengthID`] will map Requests of type String, to usize id representing their
    /// chars length. In practise this will mean that Requests of the same char length will be
    /// able to reuse the same connections
    struct StringRequestLengthID;

    impl ReqToConnId<String> for StringRequestLengthID {
        type ConnId = usize;

        fn id(&self, req: String) -> (String, Self::ConnId) {
            let count = req.chars().count();
            return (req, count);
        }
    }

    #[tokio::test]
    async fn test_should_reuse_connections() {
        let pool = Pool::default();
        // We use a closure here to maps all requests to `()` id, this will result in all connections being shared and the pool
        // acting like like a global connection pool (eg database connection pool where all connections can be used).
        let svc = PooledConnector::new(TestService::default(), pool, |req| (req, ()));

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
    async fn test_hashing_to_separate() {
        let pool = Pool::default();
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
        let pool = Pool::new(nz!(1), nz!(1)).unwrap();
        let svc = PooledConnector::new(TestService::default(), pool, StringRequestLengthID {})
            .with_wait_for_pool_timeout(Some(Duration::from_millis(50)));

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
