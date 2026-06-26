use super::{MultiplexPool, MuxSelection, PooledConnector};
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
/// Config used to create a multiplexing http connection pool ([`MultiplexPool`]).
///
/// The per-connection concurrency comes from the connection's
/// [`MaxConcurrency`](crate::conn::MaxConcurrency) extension (set by the http
/// connectors: 1 for http/1, the stream capacity for http/2), clamped to
/// `max_concurrent_streams` as an upper bound.
pub struct HttpPooledConnectorConfig {
    /// Set the max amount of connections that this connection pool will contain
    ///
    /// This is the sum of active connections and idle connections. When this limit
    /// is hit idle connections will be replaced with new ones.
    pub max_total: usize,
    /// Upper bound on the concurrent requests a single connection may serve.
    ///
    /// Acts as a ceiling for each connection, each connection also figures
    /// it's own max concurrency out by itself
    pub max_concurrent_streams: usize,
    /// How a connection is chosen among several that can serve a request.
    pub selection: MuxSelection,
    /// If connections have been idle (no active streams) for longer than this
    /// timeout they are dropped. Only checked when a connection is requested.
    pub idle_timeout: Option<Duration>,
    /// How long to wait for the pool to hand out a connection before timing out.
    pub wait_for_pool_timeout: Option<Duration>,
}

impl Default for HttpPooledConnectorConfig {
    fn default() -> Self {
        Self {
            max_total: 50,
            max_concurrent_streams: 100,
            selection: MuxSelection::default(),
            idle_timeout: Some(Duration::from_secs(300)),
            wait_for_pool_timeout: Some(Duration::from_secs(120)),
        }
    }
}

impl HttpPooledConnectorConfig {
    pub fn build_connector<C: ExtensionsRef, S>(
        self,
        inner: S,
    ) -> Result<
        PooledConnector<S, MultiplexPool<C, BasicHttpConId>, BasicHttpConnIdentifier>,
        BoxError,
    > {
        let pool = MultiplexPool::try_new(self.max_concurrent_streams, self.max_total)?
            .with_selection(self.selection)
            .maybe_with_idle_timeout(self.idle_timeout);

        Ok(PooledConnector::new(inner, pool, BasicHttpConnIdentifier)
            .maybe_with_wait_for_pool_timeout(self.wait_for_pool_timeout))
    }
}
