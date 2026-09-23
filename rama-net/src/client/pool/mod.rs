use core::{fmt::Debug, hash::Hash};
use std::{sync::Arc, time::Duration};

use super::conn::{ConnectorService, EstablishedClientConnection};
use super::{ConnectionError, ConnectionErrorKind};

use rama_core::error::BoxError;
use rama_core::extensions::{Extension, Extensions, ExtensionsRef};
use rama_core::telemetry::tracing::trace;
use rama_core::{Layer, Service};
use rama_utils::macros::generate_set_and_with;

use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;

#[cfg(feature = "opentelemetry")]
#[cfg_attr(docsrs, doc(cfg(feature = "opentelemetry")))]
pub mod metrics;

mod exclusive;
#[doc(inline)]
pub use exclusive::{LeasedConnection, LruDropPool, ReuseStrategy};

mod identifier;
#[doc(inline)]
pub use identifier::{BasicConnId, BasicConnIdentifier};

pub mod multiplex;
#[doc(inline)]
pub use multiplex::{MultiplexPool, MultiplexedConnection, MuxSelection};

/// Connection-owned requirements for reusing an established transport.
///
/// Publish this through [`ConnectionReuse`] after establishment. Matching must be
/// deterministic, nonblocking and side-effect free for a fixed connector policy.
/// Pools invoke it outside their storage locks. Retire a pool before changing the
/// connector's fixed defaults; these requirements describe its established connections.
pub trait ConnectionReusePolicy: Debug + Send + Sync + 'static {
    /// Whether this connection may be retained after its establishing request.
    fn is_reusable(&self) -> bool {
        true
    }

    /// Whether the request's extensions are compatible with this connection.
    fn matches(&self, input: &Extensions) -> bool;
}

/// Reuse requirements published by a connector on its established connection.
///
/// Without this extension, the pool's connection identifier determines reuse.
/// Connectors whose policy varies by request must publish their requirements.
/// Layered transports can combine requirements once with [`Self::and`].
#[derive(Clone, Debug, Extension)]
pub struct ConnectionReuse {
    policy: Arc<dyn ConnectionReusePolicy>,
    complete: bool,
}

impl ConnectionReuse {
    /// Publish the complete reuse policy for the requested endpoint.
    ///
    /// This describes policy compatibility, not peer authentication. Transport
    /// layers which cover only an intermediary must use [`Self::restriction`].
    pub fn new(policy: impl ConnectionReusePolicy) -> Self {
        Self {
            policy: Arc::new(policy),
            complete: true,
        }
    }

    /// Publish an additional transport restriction without certifying the
    /// requested endpoint's complete policy, such as TLS to an intermediary.
    pub fn restriction(policy: impl ConnectionReusePolicy) -> Self {
        Self::new(policy).into_restriction()
    }

    /// Whether a connector has published the requested endpoint's complete policy.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Preserve the requirements while limiting them to an inner transport.
    ///
    /// A tunnel layer must apply this to its combined inner requirements before
    /// passing the connection to the requested endpoint's connector.
    #[must_use]
    pub fn into_restriction(mut self) -> Self {
        self.complete = false;
        self
    }

    /// Whether the established connection may be retained for later requests.
    pub fn is_reusable(&self) -> bool {
        self.policy.is_reusable()
    }

    /// Check the request against the established connection's requirements.
    pub fn matches(&self, input: &Extensions) -> bool {
        self.is_reusable() && self.policy.matches(input)
    }

    /// Require both transport layers to accept reuse of the connection.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        let complete = self.complete || other.complete;
        Self {
            policy: Arc::new(CombinedReuse(self, other)),
            complete,
        }
    }
}

#[derive(Debug)]
struct CombinedReuse(ConnectionReuse, ConnectionReuse);

impl ConnectionReusePolicy for CombinedReuse {
    fn is_reusable(&self) -> bool {
        self.0.is_reusable() && self.1.is_reusable()
    }

    fn matches(&self, input: &Extensions) -> bool {
        self.0.matches(input) && self.1.matches(input)
    }
}

/// [`Pool`] implements the storage part of a connection pool. This storage
/// also decides which connection it returns for a given ID or when the caller asks to
/// remove one, this results in the storage deciding which mode we use for connection
/// reuse and dropping (eg FIFO for reuse and LRU for dropping conn when pool is full)
pub trait Pool<C, ID>: Send + Sync + 'static {
    type Connection: Send + ExtensionsRef;
    type CreatePermit: Send;

    /// Get a compatible connection, or a permit to establish a new connection.
    ///
    /// Implementations must check [`ConnectionReuse`] against `input` before
    /// admitting a stored connection, and honor its retention policy in `create`.
    /// Evaluate connector-owned policies outside storage locks.
    ///
    /// A [`Pool::CreatePermit`] is needed to add a new connection to the pool. Depending on how
    /// the [`Pool::CreatePermit`] is used a pool can implement policies for max connection and max
    /// total connections.
    fn get_conn(
        &self,
        id: &ID,
        input: &Extensions,
    ) -> impl Future<
        Output = Result<ConnectionResult<Self::Connection, Self::CreatePermit>, BoxError>,
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
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
    C: Send + ExtensionsRef + 'static,
    ID: Clone + Send + Sync + PartialEq + 'static,
{
    type Connection = C;
    type CreatePermit = ();

    async fn get_conn(
        &self,
        _id: &ID,
        _input: &Extensions,
    ) -> Result<ConnectionResult<Self::Connection, Self::CreatePermit>, BoxError> {
        Ok(ConnectionResult::CreatePermit(()))
    }

    async fn create(&self, _id: ID, conn: C, _permit: Self::CreatePermit) -> Self::Connection {
        conn
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

/// [`ReqToConnID`] is used to convert a `Input` to a connection ID. These IDs
/// are not unique and multiple connections can have the same ID. IDs are used
/// to filter which connections can be used for a specific input in a way that
/// is independent of what an input is.
pub trait ReqToConnID<Input: ExtensionsRef>: Sized + Clone + Send + Sync + 'static {
    type ID: ConnID;

    fn id(&self, input: &Input) -> Result<Self::ID, BoxError>;
}

/// [`ConnID`] is used to identify a connection in a connection pool. These IDs
/// are not unique and multiple connections can have the same ID. IDs are used
/// to filter which connections can be used for a specific input in a way that
/// is independent of what an input is.
pub trait ConnID: Send + Sync + Eq + Hash + Clone + Debug + 'static {
    /// Whether a connection with this policy may be shared with later requests.
    ///
    /// A false result requires a fresh connection that is discarded after use.
    /// Pool capacity limits still apply.
    fn is_reusable(&self) -> bool {
        true
    }

    #[cfg(feature = "opentelemetry")]
    /// Returns a list of attributes to add to metrics generated by the
    /// connection pool.
    fn attributes(&self) -> impl Iterator<Item = rama_core::telemetry::opentelemetry::KeyValue> {
        core::iter::empty()
    }
}

impl<Input, ID, F> ReqToConnID<Input> for F
where
    F: Fn(&Input) -> Result<ID, BoxError> + Clone + Send + Sync + 'static,
    ID: ConnID,
    Input: ExtensionsRef,
{
    type ID = ID;

    fn id(&self, request: &Input) -> Result<Self::ID, BoxError> {
        self(request)
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

impl<Input, S, P, R> Service<Input> for PooledConnector<S, P, R>
where
    S: ConnectorService<Input>,
    Input: Send + ExtensionsRef + 'static,
    P: Pool<S::Connection, R::ID> + Extension,
    R: ReqToConnID<Input>,
{
    type Output = EstablishedClientConnection<P::Connection, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let conn_id = self.req_to_conn_id.id(&input).map_err(|error| {
            ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                .context("pooled connector: derive connection id")
        })?;

        // Try to get connection from pool, if no connection is found, we will have to create a new
        // one using the returned create permit

        // Resolve once and keep an owned handle: the same pool that minted a
        // create permit must also receive the created connection.
        let input_pool = input.extensions().get_arc::<P>();
        let pool = if let Some(pool) = input_pool.as_deref() {
            trace!("pooled connector: using pool from ctx");
            pool
        } else {
            trace!("pooled connector: using pool from connector");
            &self.pool
        };

        let pool_result = if let Some(duration) = self.wait_for_pool_timeout {
            timeout(duration, pool.get_conn(&conn_id, input.extensions()))
                    .await
                    .inspect_err(|err|{
                        trace!(%err, "pooled connector: timeout triggered while waiting for a connection (/w conn id: {conn_id:?}) from pool");
                    })
                    .map_err(|error| {
                        ConnectionError::local(error, ConnectionErrorKind::Timeout)
                            .context("pooled connector: wait for connection")
                    })?
        } else {
            pool.get_conn(&conn_id, input.extensions()).await
        };

        match pool_result.map_err(|error| {
            ConnectionError::local(error, ConnectionErrorKind::Internal)
                .context("pooled connector: acquire connection")
        })? {
            ConnectionResult::Connection(conn) => {
                trace!(
                    "pooled connector: got connection (w/ conn id: {conn_id:?}) from pool (running health checks now)"
                );

                Ok(EstablishedClientConnection { conn, input })
            }
            ConnectionResult::CreatePermit(permit) => {
                trace!(
                    "pooled connector: no connection (w/ conn id: {conn_id:?}) found, received permit to create a new one"
                );
                let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

                trace!(
                    "pooled connector: returning new pooled connection (w/ conn id: {conn_id:?}"
                );
                let conn = pool.create(conn_id, conn, permit).await;
                Ok(EstablishedClientConnection { input, conn })
            }
        }
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
mod reuse_tests;
