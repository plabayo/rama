//! Upstream proxy types and utilities.
//!
//! See the [`ProxyFilter`] for more information on how to select a proxy,
//! and the [`ProxyDB`] trait for how to implement a proxy database.
//!
//! If you wish to support proxy filters directly from the username,
//! you can use the [`ProxyFilterUsernameParser`] to extract the proxy filter
//! so it will be added to the [`Context`]'s [`Extensions`].
//!
//! The [`ProxyDB`] is used by Connection Pools to connect via a proxy,
//! in case a [`ProxyFilter`] is present in the [`Context`]'s [`Extensions`].
//!
//! [`Context`]: crate::service::Context
//! [`Extensions`]: crate::service::context::Extensions

use std::net::SocketAddr;

mod username;

pub use username::ProxyFilterUsernameParser;

pub mod http;
pub mod pp;

mod proxydb;
#[doc(inline)]
pub use proxydb::{
    layer, proxy_is_valid, MemoryProxyDB, MemoryProxyDBInsertError, MemoryProxyDBInsertErrorKind,
    MemoryProxyDBQueryError, MemoryProxyDBQueryErrorKind, Proxy, ProxyCredentials,
    ProxyCsvRowReader, ProxyCsvRowReaderError, ProxyCsvRowReaderErrorKind, ProxyDB, ProxyFilter,
    StringFilter,
};

#[derive(Debug, Clone)]
/// An address that can be set by any service or middleware,
/// to make connectors connect to the specified [`Proxy`] [`SocketAddr`],
/// instead of connecting to the [`Request`] authority.
///
/// [`Request`]: crate::http::Request
/// [`SocketAddr`]: std::net::SocketAddr
pub struct ProxySocketAddr(SocketAddr);

impl ProxySocketAddr {
    /// Create a new [`ProxySocketAddr`] for the given target [`SocketAddr`].
    pub fn new(target: SocketAddr) -> Self {
        Self(target)
    }

    /// Get the target [`SocketAddr`] of this [`ProxySocketAddr`].
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    pub fn addr(&self) -> &SocketAddr {
        &self.0
    }
}
