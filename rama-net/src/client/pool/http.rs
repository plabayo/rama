use super::{LruDropPool, PooledConnector};
use crate::address::ProxyAddress;
use crate::client::ConnectorTarget;
use crate::{Protocol, address::HostWithOptPort};
use rama_core::error::BoxError;
use rama_core::extensions::ExtensionsRef;
use std::time::Duration;

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
/// [`BasicHttpConnIdentifier`] can be used together with a [`super::Pool`] to create a basic http connection pool
pub struct BasicHttpConnIdentifier;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Connection Identifier which will match inputs that have the exact same
/// protocol, authority, proxy address and connector target
pub struct BasicHttpConId {
    pub protocol: Option<Protocol>,
    pub authority: HostWithOptPort,
    pub proxy_address: Option<ProxyAddress>,
    pub connector_target: Option<ConnectorTarget>,
}

impl super::ConnID for BasicHttpConId {
    #[cfg(feature = "opentelemetry")]
    fn attributes(&self) -> impl Iterator<Item = rama_core::telemetry::opentelemetry::KeyValue> {
        self.protocol
            .as_ref()
            .map(|protocol| {
                rama_core::telemetry::opentelemetry::KeyValue::new("protocol", protocol.to_string())
            })
            .into_iter()
            .chain([rama_core::telemetry::opentelemetry::KeyValue::new(
                "authority",
                self.authority.to_string(),
            )])
    }
}

#[derive(Debug, Clone)]
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
    pub fn build_connector<C: ExtensionsRef, S>(
        self,
        inner: S,
    ) -> Result<PooledConnector<S, LruDropPool<C, BasicHttpConId>, BasicHttpConnIdentifier>, BoxError>
    {
        let pool = LruDropPool::try_new(self.max_active, self.max_total)?
            .maybe_with_idle_timeout(self.idle_timeout);

        Ok(PooledConnector::new(inner, pool, BasicHttpConnIdentifier)
            .maybe_with_wait_for_pool_timeout(self.wait_for_pool_timeout))
    }
}
