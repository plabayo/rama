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

mod username;
pub use username::ProxyFilterUsernameParser;

pub mod pp;

mod proxydb;
#[doc(inline)]
pub use proxydb::{
    layer, proxy_is_valid, MemoryProxyDB, MemoryProxyDBInsertError, MemoryProxyDBInsertErrorKind,
    MemoryProxyDBQueryError, MemoryProxyDBQueryErrorKind, Proxy, ProxyCredentials,
    ProxyCsvRowReader, ProxyCsvRowReaderError, ProxyCsvRowReaderErrorKind, ProxyDB, ProxyFilter,
    StringFilter,
};
