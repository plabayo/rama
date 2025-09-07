use super::{LruDropPool, PooledConnector, ReqToConnID};
use crate::{Protocol, address::Authority, client::pool::OpaqueError, http::RequestContext};
use rama_core::Context;
use rama_http_types::Request;
use std::time::Duration;

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
/// [`BasicHttpConnIdentifier`] can be used together with a [`super::Pool`] to create a basic http connection pool
pub struct BasicHttpConnIdentifier;

pub type BasicHttpConId = (Protocol, Authority);

impl super::ConnID for BasicHttpConId {
    #[cfg(feature = "opentelemetry")]
    fn attributes(&self) -> impl Iterator<Item = rama_core::telemetry::opentelemetry::KeyValue> {
        [
            rama_core::telemetry::opentelemetry::KeyValue::new("protocol", self.0.to_string()),
            rama_core::telemetry::opentelemetry::KeyValue::new("authority", self.1.to_string()),
        ]
        .into_iter()
    }
}

impl<Body> ReqToConnID<Request<Body>> for BasicHttpConnIdentifier {
    type ID = BasicHttpConId;

    fn id(&self, ctx: &Context, req: &Request<Body>) -> Result<Self::ID, OpaqueError> {
        let req_ctx = match ctx.get::<RequestContext>() {
            Some(ctx) => ctx,
            None => &RequestContext::try_from((ctx, req))?,
        };

        Ok((req_ctx.protocol.clone(), req_ctx.authority.clone()))
    }
}

#[derive(Clone)]
/// Config used to create the default http connection pool
pub struct HttpPooledConnectorConfig {
    /// Set the max amount of connections that this connection pool will contain
    ///
    /// This is the sum of active connections and idle connections. When this limit
    /// is hit idle connections will be replaced with new ones.
    pub max_total: usize,
    /// Set the max amount of connections that can actively be used
    ///
    /// Requesting a connection from the pool will block until the pool
    /// is below max capacity again.
    pub max_active: usize,
    /// If connections have been idle for longer then the provided timeout they
    /// will be dropped and removed from the pool
    ///
    /// Note: timeout is only checked when a connection is requested from the pool,
    /// it is not something that is done periodically
    pub idle_timeout: Option<Duration>,
    /// When a pool is operating at max active capacity wait for this duration
    /// to get a connection from the pool before the connector raises a timeout error
    pub wait_for_pool_timeout: Option<Duration>,
}

impl Default for HttpPooledConnectorConfig {
    fn default() -> Self {
        Self {
            max_total: 50,
            max_active: 20,
            wait_for_pool_timeout: Some(Duration::from_secs(120)),
            idle_timeout: Some(Duration::from_secs(300)),
        }
    }
}

impl HttpPooledConnectorConfig {
    pub fn build_connector<C, S>(
        self,
        inner: S,
    ) -> Result<
        PooledConnector<S, LruDropPool<C, BasicHttpConId>, BasicHttpConnIdentifier>,
        OpaqueError,
    > {
        let pool = LruDropPool::new(self.max_active, self.max_total)?
            .maybe_with_idle_timeout(self.idle_timeout);

        Ok(PooledConnector::new(inner, pool, BasicHttpConnIdentifier)
            .maybe_with_wait_for_pool_timeout(self.wait_for_pool_timeout))
    }
}
