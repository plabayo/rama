use core::{fmt::Debug, hash::Hash};
use std::time::Duration;

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

mod admission;
#[doc(inline)]
pub use admission::{ConnectionAdmission, ConnectionAdmissionLease, ConnectionAdmissionPolicy};

mod exclusive;
#[doc(inline)]
pub use exclusive::{LeasedConnection, LruDropPool, ReuseStrategy};

mod identifier;
#[doc(inline)]
pub use identifier::{BasicConnId, BasicConnIdentifier};

pub mod multiplex;
#[doc(inline)]
pub use multiplex::{
    MultiplexPool, MultiplexSlot, MultiplexedConnection, MuxSelection, SaturationPolicy,
};

mod reuse;
#[doc(inline)]
pub use reuse::{ConnectionReuse, ConnectionReusePolicy, ReuseKey};

/// [`Pool`] implements the storage part of a connection pool. This storage
/// also decides which connection it returns for a given ID or when the caller asks to
/// remove one, this results in the storage deciding which mode we use for connection
/// reuse and dropping (eg FIFO for reuse and LRU for dropping conn when pool is full)
pub trait Pool<C, ID>: Send + Sync + 'static {
    type Connection: Send + ExtensionsRef;
    type CreatePermit: Send;

    /// Get a compatible connection, or a permit to establish a new connection.
    ///
    /// Implementations read a connection's [`ConnectionReuse`] once, in
    /// `create`, and only hand it to requests whose key matches its key.
    /// Pools which retain connections must honor [`ConnectionAdmission`] before
    /// handout and hold its lease until consumed or dropped. Evaluate providers
    /// and compatibility policies outside storage and admission locks.
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

    /// The connection `create_permit` was for could not be established. Pools
    /// that let checkouts wait for it instead of dialing fail them alike.
    fn abandon(&self, create_permit: Self::CreatePermit, error: &ConnectionError);

    /// Admit the establishing request before publishing its new connection.
    ///
    /// Retaining pools reserve any [`ConnectionAdmission`] resources against
    /// `input` before exposing the connection to concurrent checkouts. Obtain
    /// the creation permit from [`Self::get_conn`].
    fn create(
        &self,
        id: ID,
        conn: C,
        create_permit: Self::CreatePermit,
        input: &Extensions,
    ) -> impl Future<Output = Result<Self::Connection, BoxError>> + Send;
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
/// don't want connection pooling to happen. Since every request establishes
/// its own connection, resource admission remains with the transport itself.
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

    fn abandon(&self, _create_permit: (), _error: &ConnectionError) {}

    async fn create(
        &self,
        _id: ID,
        conn: C,
        _permit: Self::CreatePermit,
        _input: &Extensions,
    ) -> Result<Self::Connection, BoxError> {
        Ok(conn)
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
        /// Bound each wait for a pool slot or newly established transport credit.
        ///
        /// The transport handshake is separate. `None` leaves these waits unbounded.
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

        match pool_result.map_err(|error| match error.downcast::<ConnectionError>() {
            // Such as the connect it waited for failing: classified already.
            Ok(error) => *error,
            Err(error) => ConnectionError::local(error, ConnectionErrorKind::Internal)
                .context("pooled connector: acquire connection"),
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
                let EstablishedClientConnection { input, conn } =
                    match self.inner.connect(input).await {
                        Ok(established) => established,
                        Err(error) => {
                            pool.abandon(permit, &error);
                            return Err(error);
                        }
                    };

                trace!(
                    "pooled connector: returning new pooled connection (w/ conn id: {conn_id:?}"
                );
                let admission = pool.create(conn_id, conn, permit, input.extensions());
                let conn = if let Some(duration) = self.wait_for_pool_timeout {
                    timeout(duration, admission).await.map_err(|error| {
                        ConnectionError::local(error, ConnectionErrorKind::Timeout)
                            .context("pooled connector: wait for new connection admission")
                    })?
                } else {
                    admission.await
                }
                .map_err(|error| {
                    ConnectionError::from(error).context("pooled connector: admit new connection")
                })?;
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
