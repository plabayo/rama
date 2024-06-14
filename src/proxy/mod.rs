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
//! # DB Live Reloads
//!
//! [`ProxyDB`] implementations like the [`MemoryProxyDB`] feel static in nature, and they are.
//! The goal is really to load it once and read it often as fast as possible.
//!
//! In fact, given that we access everything through shared references,
//! there is also no cheap way to mutate it all the time.
//!
//! As such the normal way to update data such as your proxy list
//! is by performing a rolling update of your actual rama-driven proxy workloads.
//!
//! That said. By using crates such as [left-right](https://crates.io/crates/left-right)
//! you can relatively affordable perform live reloads by having the writer on its own tokio
//! task and wrap the reader in a [`ProxyDB`] implementation. This way you can live reload based upon
//! a signal, or more realistically, every x minutes.
//!
//! [`Context`]: crate::service::Context
//! [`Extensions`]: crate::service::context::Extensions

mod username;

pub use username::ProxyFilterUsernameParser;

pub mod http;
pub mod pp;

mod proxydb;
#[doc(inline)]
pub use proxydb::{
    layer, MemoryProxyDB, MemoryProxyDBInsertError, MemoryProxyDBInsertErrorKind,
    MemoryProxyDBQueryError, MemoryProxyDBQueryErrorKind, Proxy, ProxyCsvRowReader,
    ProxyCsvRowReaderError, ProxyCsvRowReaderErrorKind, ProxyDB, ProxyFilter, StringFilter,
};
