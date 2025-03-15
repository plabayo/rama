use super::conn::{ConnectorService, EstablishedClientConnection};
use crate::stream::Socket;
use parking_lot::Mutex;
use rama_core::error::{BoxError, ErrorContext, OpaqueError};
use rama_core::{Context, Service};
use rama_utils::macros::{generate_field_setters, nz};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::num::NonZeroU16;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::{future::Future, net::SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tracing::trace;

/// [`PoolStorage`] implements the storage part of a connection pool. This storage
/// also decides which connection it returns for a given ID or when the caller asks to
/// remove one, this results in the storage deciding which mode we use for connection
/// reuse and dropping (eg FIFO for reuse and LRU for dropping conn when pool is full)
pub trait PoolStorage: Sized + Send + Sync + 'static {
    type ConnID: PartialEq + Clone + Send + Sync + 'static;
    type Connection: Send;

    /// Initialize [`PoolStorage`] with the given capacity. Implementer of this trait
    /// can still decide if it will immedialty create storage of the given capacity,
    /// or do it in a custom way (eg grow storage dynamically as needed)
    fn new(capacity: NonZeroU16) -> Self;

    /// Add connection to pool storage
    fn add_connection(&self, conn: PooledConnection<Self::Connection, Self::ConnID>);

    /// Get a connection from this pool that is a match for the given [`Self::ConnID`].
    /// Depending how connections are sorted and matched on ID, one can implement different
    /// queue modes for connection reuse
    fn get_connection(
        &self,
        id: &Self::ConnID,
    ) -> Option<PooledConnection<Self::Connection, Self::ConnID>>;

    /// Get a connection from the pool with the intent to drop/replace it. This method will be used
    /// by the pool in case it is full and it wants to replace an old connection with a new one.
    /// By choosing which connection to return here one can implement different modes for connection
    /// dropping/replacing
    fn get_connection_to_drop(
        &self,
    ) -> Result<PooledConnection<Self::Connection, Self::ConnID>, OpaqueError>;
}

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

/// A connection which is stored in a pool. A ConnID is used to determine
/// which connections can be used for a request. This ConnID encodes
/// all the details that make a connection unique/suitable for a request.
pub struct PooledConnection<C, ConnID> {
    /// Actual raw connection that is stored in pool
    conn: C,
    /// ID is not unique but is used to group connections that can be used for the same request
    id: ConnID,
    /// Slot this connection takes up in the pool
    slot: PoolSlot,
}

impl<C: Debug, ConnID: Debug> Debug for PooledConnection<C, ConnID> {
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
pub struct LeasedConnection<C, ConnID> {
    /// Option so we can ownership during drop and return the [`PooledConnection`]
    /// back to the pool
    pooled_conn: Option<PooledConnection<C, ConnID>>,
    /// Fn that can be used to return the [`PooledConnection`] back to the pool
    returner: Arc<dyn Fn(PooledConnection<C, ConnID>) + Send + Sync>,
    /// Active slot this [`LeasedConnection`] is using from the pool
    _slot: ActiveSlot,
}

impl<C, ConnID> Debug for LeasedConnection<C, ConnID>
where
    C: Debug,
    ConnID: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeasedConnection")
            .field("pooled_conn", &self.pooled_conn)
            .field("_slot", &self._slot)
            .finish()
    }
}

impl<C, ConnID> LeasedConnection<C, ConnID> {
    /// Take ownership of the internal connection. This will remove it from the pool.
    pub fn take(mut self) -> C {
        self.pooled_conn.take().expect("only None after drop").conn
    }
}

impl<C, ConnID> Deref for LeasedConnection<C, ConnID> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self
            .pooled_conn
            .as_ref()
            .expect("only None after drop")
            .conn
    }
}

impl<C, ConnID> DerefMut for LeasedConnection<C, ConnID> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self
            .pooled_conn
            .as_mut()
            .expect("only None after drop")
            .conn
    }
}

impl<C, ConnID> AsRef<C> for LeasedConnection<C, ConnID> {
    fn as_ref(&self) -> &C {
        self
    }
}

impl<C, ConnID> AsMut<C> for LeasedConnection<C, ConnID> {
    fn as_mut(&mut self) -> &mut C {
        self
    }
}

impl<C, ConnID> Drop for LeasedConnection<C, ConnID> {
    fn drop(&mut self) {
        if let Some(pooled_conn) = self.pooled_conn.take() {
            (self.returner)(pooled_conn);
            // pool.return_pooled_conn(pooled_conn);
        }
    }
}

// We want to be able to use LeasedConnection as a transparent wrapper around our connection.
// To achieve that we conditially implement all traits that are used by our Connectors

impl<C, ConnID> Socket for LeasedConnection<C, ConnID>
where
    ConnID: Send + Sync + 'static,
    C: Socket,
{
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.as_ref().local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.as_ref().peer_addr()
    }
}

impl<C, ConnID> AsyncWrite for LeasedConnection<C, ConnID>
where
    C: AsyncWrite + Unpin,
    ConnID: Unpin,
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

impl<C, ConnID> AsyncRead for LeasedConnection<C, ConnID>
where
    C: AsyncRead + Unpin,
    ConnID: Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(self.deref_mut().as_mut()).poll_read(cx, buf)
    }
}

impl<State, Request, C, ConnID> Service<State, Request> for LeasedConnection<C, ConnID>
where
    ConnID: Send + Sync + 'static,
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

struct PoolInner<S> {
    total_slots: Arc<Semaphore>,
    active_slots: Arc<Semaphore>,
    storage: S,
}

impl<S: Debug> Debug for PoolInner<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolInner")
            .field("total_slots", &self.total_slots)
            .field("active_slots", &self.active_slots)
            .field("storage", &self.storage)
            .finish()
    }
}

/// Storage for connection pool that uses FIFO to reuse open connections and LRU to drop/replace
/// connections when the pool is at max capacity.
pub struct ConnStoreFiFoReuseLruDrop<C, ConnID>(Arc<Mutex<VecDeque<PooledConnection<C, ConnID>>>>);

impl<C, ConnID> PoolStorage for ConnStoreFiFoReuseLruDrop<C, ConnID>
where
    C: Send + 'static,
    ConnID: PartialEq + Clone + Send + Sync + 'static,
{
    type ConnID = ConnID;

    type Connection = C;

    fn new(capacity: NonZeroU16) -> Self {
        Self(Arc::new(Mutex::new(VecDeque::with_capacity(
            Into::<u16>::into(capacity).into(),
        ))))
    }

    fn add_connection(&self, conn: PooledConnection<Self::Connection, Self::ConnID>) {
        trace!("adding connection back to pool");
        self.0.lock().push_front(conn);
    }

    fn get_connection(
        &self,
        id: &Self::ConnID,
    ) -> Option<PooledConnection<Self::Connection, Self::ConnID>> {
        trace!("getting connection from pool");
        let mut connections = self.0.lock();
        connections
            .iter()
            .position(|stored| &stored.id == id)
            .map(|idx| connections.remove(idx))
            .flatten()
    }

    fn get_connection_to_drop(
        &self,
    ) -> Result<PooledConnection<Self::Connection, Self::ConnID>, OpaqueError> {
        trace!("getting connection to drop from pool");
        self.0.lock().pop_back().context("None, this function should only be called when pool is full, in which case this should always return a connection")
    }
}

impl<C, ConnID: Debug> Debug for ConnStoreFiFoReuseLruDrop<C, ConnID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.lock().iter().map(|item| &item.id))
            .finish()
    }
}

/// Connection pool which can be used to store and reuse existing connection.
/// This struct can be copied and passed around as needed
pub struct Pool<S> {
    inner: Arc<PoolInner<S>>,
}

impl<S> Clone for Pool<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S: Debug> Debug for Pool<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool").field("inner", &self.inner).finish()
    }
}

impl<C, ConnID> Default for Pool<ConnStoreFiFoReuseLruDrop<C, ConnID>>
where
    C: Send + 'static,
    ConnID: PartialEq + Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new(nz!(10), nz!(20)).unwrap()
    }
}

/// Return type of [`Pool::get_connection_or_create_cb()`] to support advanced use cases
pub enum GetConnectionOrCreate<F, C, ConnID>
where
    F: FnOnce(C) -> LeasedConnection<C, ConnID>,
{
    /// Connection was found in the pool for given ConnID and is ready to be used
    LeasedConnection(LeasedConnection<C, ConnID>),
    /// Pool doesn't have connection for ConnID but instead returns a function
    /// which should be called by the external user to put a new connection
    /// inside the pool. This fn also instantly returns a [`LeasedConnection`]
    /// that is ready to be used
    AddConnection(F),
}

impl<S: PoolStorage> Pool<S> {
    pub fn new(max_active: NonZeroU16, max_total: NonZeroU16) -> Result<Pool<S>, OpaqueError> {
        if max_active > max_total {
            return Err(OpaqueError::from_display(
                "max_active should be <= then max_total connection",
            ));
        }

        let storage = S::new(max_total);
        let max_total: usize = Into::<u16>::into(max_total).into();

        Ok(Pool {
            inner: Arc::new(PoolInner {
                total_slots: Arc::new(Semaphore::new(max_total)),
                active_slots: Arc::new(Semaphore::new(Into::<u16>::into(max_active).into())),
                storage,
            }),
        })
    }
}

impl<S: PoolStorage> Pool<S> {
    /// Get connection or create a new one using provided async fn if we don't find one inside pool
    pub async fn get_connection_or_create<F, Fut>(
        &self,
        id: &S::ConnID,
        create_conn: F,
    ) -> Result<LeasedConnection<S::Connection, S::ConnID>, OpaqueError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<S::Connection, OpaqueError>>,
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
        id: &S::ConnID,
    ) -> Result<
        GetConnectionOrCreate<
            impl FnOnce(S::Connection) -> LeasedConnection<S::Connection, S::ConnID>,
            S::Connection,
            S::ConnID,
        >,
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

        let pooled_conn = self.inner.storage.get_connection(&id);

        let pool = Arc::downgrade(&self.inner);
        let returner = Arc::new(move |conn| {
            if let Some(pool) = pool.upgrade() {
                pool.storage.add_connection(conn);
            }
        });

        if pooled_conn.is_some() {
            trace!("creating leased connection from stored pooled connection");
            let leased_conn = LeasedConnection {
                _slot: active_slot,
                pooled_conn,
                returner,
            };
            return Ok(GetConnectionOrCreate::LeasedConnection(leased_conn));
        };

        // If we have an active slot we should always be able to get a pool slot. Unless our pool
        // is totally full, and in that case we just need to drop one connection and use that slot instead
        let pool_slot = match self.inner.total_slots.clone().try_acquire_owned() {
            Ok(pool_permit) => PoolSlot(pool_permit),
            Err(_) => {
                let pooled_conn = self.inner.storage.get_connection_to_drop()?;
                pooled_conn.slot
            }
        };

        trace!("no pooled connection found, returning callback to create leased connection");
        Ok(GetConnectionOrCreate::AddConnection(
            move |conn: S::Connection| LeasedConnection {
                _slot: active_slot,
                returner,
                pooled_conn: Some(PooledConnection {
                    conn,
                    id: id.clone(),
                    slot: pool_slot,
                }),
            },
        ))
    }
}

/// [`ReqToConnID`] is used to convert a `Request` to a connection ID. These IDs are
/// not unique and multiple connections can have the same ID. IDs are used to filter
/// which connections can be used for a specific Request in a way that is indepent of
/// what a Request is.
pub trait ReqToConnID<State, Request>: Sized + Send + Sync + 'static {
    type ConnID: Send + Sync + PartialEq + Clone + 'static;

    fn id(&self, ctx: &Context<State>, request: &Request) -> Result<Self::ConnID, OpaqueError>;
}

impl<State, Request, ConnID, F> ReqToConnID<State, Request> for F
where
    F: Fn(&Context<State>, &Request) -> Result<ConnID, OpaqueError> + Send + Sync + 'static,
    ConnID: Send + Sync + PartialEq + Clone + 'static,
{
    type ConnID = ConnID;

    fn id(&self, ctx: &Context<State>, request: &Request) -> Result<Self::ConnID, OpaqueError> {
        self(ctx, request)
    }
}

/// [`PooledConnector`] is a connector that will keep connections around in a local pool
/// so they can be reused later. If no connections are available for a specifc `id`
/// it will create a new one.
pub struct PooledConnector<S, Storage, R> {
    inner: S,
    pool: Pool<Storage>,
    req_to_conn_id: R,
    wait_for_pool_timeout: Option<Duration>,
}

impl<S, Storage, R> PooledConnector<S, Storage, R> {
    pub fn new(inner: S, pool: Pool<Storage>, req_to_conn_id: R) -> PooledConnector<S, Storage, R> {
        PooledConnector {
            inner,
            pool,
            req_to_conn_id,
            wait_for_pool_timeout: None,
        }
    }

    generate_field_setters!(wait_for_pool_timeout, Duration);
}

impl<State, Request, S, Storage, R> Service<State, Request> for PooledConnector<S, Storage, R>
where
    S: ConnectorService<State, Request, Connection: Send, Error: Send + 'static>,
    State: Send + Sync + 'static,
    Request: Send + 'static,
    Storage: PoolStorage<ConnID = R::ConnID, Connection = S::Connection>,
    R: ReqToConnID<State, Request>,
{
    type Response = EstablishedClientConnection<
        LeasedConnection<Storage::Connection, Storage::ConnID>,
        State,
        Request,
    >;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let conn_id = self.req_to_conn_id.id(&ctx, &req)?;

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

    impl<State> ReqToConnID<State, String> for StringRequestLengthID {
        type ConnID = usize;

        fn id(&self, _ctx: &Context<State>, req: &String) -> Result<Self::ConnID, OpaqueError> {
            Ok(req.chars().count())
        }
    }

    #[tokio::test]
    async fn test_should_reuse_connections() {
        let pool = Pool::<ConnStoreFiFoReuseLruDrop<_, _>>::default();
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
        let pool = Pool::<ConnStoreFiFoReuseLruDrop<_, _>>::default();
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
        let pool = Pool::<ConnStoreFiFoReuseLruDrop<_, _>>::new(nz!(1), nz!(1)).unwrap();
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
