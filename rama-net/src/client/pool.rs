use super::conn::{ConnectorService, EstablishedClientConnection};
use crate::stream::Socket;
use rama_core::error::{BoxError, ErrorContext, OpaqueError};
use rama_core::{Context, Service};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::num::NonZeroU16;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::sync::{Mutex, MutexGuard};
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

#[derive(Debug)]
/// A connection which is stored in a pool. A hash is used to determine
/// which connections can be used for a request. This hash encodes
/// all the details that make a connection unique/suitable for a request.
struct PooledConnection<C> {
    hash: String,
    conn: C,
    slot: PoolSlot,
}

#[derive(Debug)]
/// [`LeasedConnection`] is a connection that is temporarily leased from
/// a pool and that will be returned to the pool once dropped if user didn't
/// take ownership of the connection `C` with [`LeasedConnection::conn_to_owned()`].
/// [`LeasedConnection`]s are considered active pool connections until dropped or
/// ownership is taken of the internal connection.
pub struct LeasedConnection<C> {
    pooled_conn: Option<PooledConnection<C>>,
    /// Weak reference to pool so we can return connections on drop
    pool: Weak<PoolInner<C>>,
    _slot: ActiveSlot,
}

impl<C> LeasedConnection<C> {
    /// Take ownership of the internal connection. This will remove it from the pool.
    pub fn take(mut self) -> C {
        let conn = self.pooled_conn.take().expect("only None after drop").conn;
        conn
    }
}

impl<C> Deref for LeasedConnection<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self
            .pooled_conn
            .as_ref()
            .expect("only None after drop")
            .conn
    }
}

impl<C> DerefMut for LeasedConnection<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self
            .pooled_conn
            .as_mut()
            .expect("only None after drop")
            .conn
    }
}

impl<C> AsRef<C> for LeasedConnection<C> {
    fn as_ref(&self) -> &C {
        self
    }
}

impl<C> AsMut<C> for LeasedConnection<C> {
    fn as_mut(&mut self) -> &mut C {
        self
    }
}

impl<C> Drop for LeasedConnection<C> {
    fn drop(&mut self) {
        if let (Some(pool), Some(pooled_conn)) = (self.pool.upgrade(), self.pooled_conn.take()) {
            match pool.return_pooled_conn(pooled_conn) {
                Ok(_) => (),
                Err(err) => {
                    tracing::error!(error = %err, "error returning connection to pool (dropping instead)")
                }
            }
        }
    }
}

// We want to be able to use LeasedConnection as a transparent wrapper around our connection.
// To achieve that we conditially implement all traits that are used by our Connectors

impl<C: Socket> Socket for LeasedConnection<C> {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.as_ref().local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.as_ref().peer_addr()
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for LeasedConnection<C> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self).poll_shutdown(cx)
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for LeasedConnection<C> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self).poll_read(cx, buf)
    }
}

impl<State, Request, C: Service<State, Request>> Service<State, Request> for LeasedConnection<C> {
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

/// [`ReqToConnHasher`] is used to convert a `Request` to a hash. This hash
/// is then used to group connections that can be reused for other `Requests`
/// that have the same hash
pub trait ReqToConnHasher<Request>: Sized + Send + Sync + 'static
where
    Request: Send + 'static,
{
    fn hash(&self, request: Request) -> (Request, String);
}

impl<Request, F> ReqToConnHasher<Request> for F
where
    F: Fn(Request) -> (Request, String) + Send + Sync + 'static,
    Request: Send + 'static,
{
    fn hash(&self, request: Request) -> (Request, String) {
        self(request)
    }
}

struct PoolInner<C> {
    total_slots: Arc<Semaphore>,
    active_slots: Arc<Semaphore>,
    connections: Mutex<VecDeque<PooledConnection<C>>>,
    // TODO support different modes, right now use LIFO to get connection
    // and LRU to evict. In other words we always insert in front, start
    // searching in front and always drop the back if needed.
}

impl<C> PoolInner<C> {
    fn return_pooled_conn(&self, conn: PooledConnection<C>) -> Result<(), OpaqueError> {
        self.connections()?.push_front(conn);
        Ok(())
    }

    fn connections(&self) -> Result<MutexGuard<'_, VecDeque<PooledConnection<C>>>, OpaqueError> {
        self.connections
            .lock()
            .map_err(|_| OpaqueError::from_display("failed to lock connections"))
    }
}

impl<C> Debug for PoolInner<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let connection_hashes: Vec<String> = self
            .connections()
            .map_err(|_| std::fmt::Error)?
            .iter()
            .map(|conn| conn.hash.clone())
            .collect();

        f.debug_struct("PoolInner")
            .field("total_slots", &self.total_slots)
            .field("active_slots", &self.active_slots)
            .field("connections", &connection_hashes)
            .finish()
    }
}

#[derive(Clone)]
/// Connection pool which can be used to store and reuse existing connection.
/// This struct can be copied and passed around as needed
pub struct Pool<C> {
    inner: Arc<PoolInner<C>>,
}

impl<C> Default for Pool<C> {
    fn default() -> Self {
        Self {
            inner: Arc::new(PoolInner {
                total_slots: Arc::new(Semaphore::new(20)),
                active_slots: Arc::new(Semaphore::new(10)),
                connections: Default::default(),
            }),
        }
    }
}

/// Return type of [`Pool::get_connection_or_create_cb()`] to support advanced use cases
pub enum GetConnectionOrCreate<C, F>
where
    F: FnOnce(C) -> LeasedConnection<C>,
{
    /// Connection was found in pool for given hash and is ready to be used
    LeasedConnection(LeasedConnection<C>),
    /// Pool doesn't have connection for hash but instead returns a function
    /// which should be called by the external user to put a new connection
    /// inside the pool. This fn also instantly returns a [`LeasedConnection`]
    /// that is ready to be used
    AddConnection(F),
}

impl<C> Pool<C> {
    pub fn new(max_active: NonZeroU16, max_total: NonZeroU16) -> Result<Self, OpaqueError> {
        if max_active > max_total {
            return Err(OpaqueError::from_display(
                "max_active should be <= then max_total connection",
            ));
        }
        Ok(Self {
            inner: Arc::new(PoolInner {
                total_slots: Arc::new(Semaphore::new(Into::<u16>::into(max_total).into())),
                active_slots: Arc::new(Semaphore::new(Into::<u16>::into(max_active).into())),
                connections: Mutex::new(VecDeque::with_capacity(
                    Into::<u16>::into(max_total).into(),
                )),
            }),
        })
    }

    /// Get connection or create a new using provided async fn if we don't find one inside pool
    pub async fn get_connection_or_create<F, Fut, E>(
        &self,
        hash: &str,
        create_conn: F,
    ) -> Result<LeasedConnection<C>, OpaqueError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<C, OpaqueError>>,
    {
        match self.get_connection_or_create_cb(hash).await? {
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
        hash: &str,
    ) -> Result<GetConnectionOrCreate<C, impl FnOnce(C) -> LeasedConnection<C>>, OpaqueError> {
        let active_permit = self
            .inner
            .active_slots
            .clone()
            .acquire_owned()
            .await
            .context("failed to acquire active slot permit")?;

        let active_slot = ActiveSlot(active_permit);
        let pool = Arc::<PoolInner<C>>::downgrade(&self.inner);

        // Check if we can reuse stored connection
        let pooled_conn = {
            let mut connections = self.inner.connections()?;
            connections
                .iter()
                .position(|stored| stored.hash == hash)
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
                let pooled_conn = self.inner.connections()?.pop_back().context(
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
                    hash: hash.to_string(),
                    slot: pool_slot,
                }),
            }
        }))
    }
}

/// [`PooledConnector`] is a connector that will keep connections around in a local pool
/// so they can be reused later. If no connections are available for a specifc `hash`
/// it will create a new one. A `hasher` is used to map requests to a connections.
pub struct PooledConnector<S, C, R> {
    inner: S,
    pool: Pool<C>,
    hasher: R,
    wait_for_pool_timeout: Option<Duration>,
}

impl<S, C, H> PooledConnector<S, C, H> {
    pub fn new(inner: S, pool: Pool<C>, hasher: H) -> PooledConnector<S, C, H> {
        PooledConnector {
            inner,
            hasher,
            pool,
            wait_for_pool_timeout: None,
        }
    }

    pub fn with_wait_for_pool_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.wait_for_pool_timeout = timeout;
        self
    }
}

impl<State, Request, S, H> Service<State, Request> for PooledConnector<S, S::Connection, H>
where
    S: ConnectorService<State, Request, Connection: Send, Error: Send + Sync + 'static>,
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
    H: ReqToConnHasher<Request>,
{
    type Response = EstablishedClientConnection<LeasedConnection<S::Connection>, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let (req, hash) = self.hasher.hash(req);

        let pool_result = if let Some(duration) = self.wait_for_pool_timeout {
            timeout(duration, self.pool.get_connection_or_create_cb(&hash))
                .await
                .map_err(|err| OpaqueError::from_std(err))?
        } else {
            self.pool.get_connection_or_create_cb(&hash).await
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
        ops::Add,
        sync::{Arc, Mutex},
    };
    use tokio_test::assert_err;

    struct TestService {
        pub created_connection: Arc<Mutex<u32>>,
    }

    impl Default for TestService {
        fn default() -> Self {
            Self {
                created_connection: Arc::new(Mutex::new(0)),
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
            let mut counter = self.created_connection.lock().expect("mutex not poisened");
            *counter = counter.add(1);

            let conn = vec![];
            Ok(EstablishedClientConnection { ctx, req, conn })
        }
    }

    struct StringRequestHasher;

    impl ReqToConnHasher<String> for StringRequestHasher {
        fn hash(&self, req: String) -> (String, String) {
            let count = req.chars().count().to_string();
            return (req, count);
        }
    }

    #[tokio::test]
    async fn test_should_reuse_connections() {
        let pool = Pool::new(NonZeroU16::new(1).unwrap(), NonZeroU16::new(1).unwrap()).unwrap();
        let svc = PooledConnector::new(TestService::default(), pool, |req| (req, String::new()));

        let iterations = 10;
        for _i in 0..iterations {
            let _conn = svc
                .connect(Context::default(), String::new())
                .await
                .unwrap();
        }

        let created_connection = *svc.inner.created_connection.lock().unwrap();
        assert_eq!(created_connection, 1);
    }

    #[tokio::test]
    async fn test_hashing_to_separate() {
        let pool = Pool::default();
        let svc = PooledConnector::new(TestService::default(), pool, StringRequestHasher {});

        {
            let mut conn = svc
                .connect(Context::default(), String::from("a"))
                .await
                .unwrap()
                .conn;

            conn.push(1);
            assert_eq!(conn.as_ref(), &vec![1]);
            assert_eq!(*svc.inner.created_connection.lock().unwrap(), 1);
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
            assert_eq!(*svc.inner.created_connection.lock().unwrap(), 1);
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
            assert_eq!(*svc.inner.created_connection.lock().unwrap(), 2);
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
            assert_eq!(*svc.inner.created_connection.lock().unwrap(), 2);
        }
    }

    #[tokio::test]
    async fn test_pool_max_size() {
        let pool = Pool::new(NonZeroU16::new(1).unwrap(), NonZeroU16::new(1).unwrap()).unwrap();
        let svc = PooledConnector::new(TestService::default(), pool, StringRequestHasher)
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
