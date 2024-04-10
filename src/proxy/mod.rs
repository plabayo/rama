//! Upstream proxy types and utilities.
//!
//! See the [`ProxyFilter`] for more information on how to select a proxy,
//! and the [`ProxyDB`] trait for how to implement a proxy database.
//!
//! If you wish to support proxy filters directly from the username,
//! you can use the [`UsernameConfig`] to extract the proxy filter
//! from the username and add yourself it to the [`Context`]'s [`Extensions`].
//!
//! The [`ProxyDB`] is used by Connection Pools to connect via a proxy,
//! in case a [`ProxyFilter`] is present in the [`Context`]'s [`Extensions`].
//!
//! [`Context`]: crate::service::Context
//! [`Extensions`]: crate::service::context::Extensions

use crate::{http::Version, url::Scheme};
use serde::Deserialize;
use std::future::Future;

pub mod username;
pub use username::{parse_username_config, UsernameConfig};

pub mod pp;

#[derive(Debug, Default, Clone, Deserialize, PartialEq)]
/// Filter to select a specific kind of proxy.
///
/// If the `id` is specified the other fields are used
/// as a validator to see if the only possible matching proxy
/// matches these fields.
///
/// If the `id` is not specified, the other fields are used
/// to select a random proxy from the pool.
///
/// Filters can be combined to make combinations with special meaning.
/// E.g. `datacenter:true, residential:true` is essentially an ISP proxy.
///
/// ## Usage
///
/// - Use [`HeaderConfigLayer`] to have this proxy filter be given by the [`Request`] headers,
///   which will add the extracted and parsed [`ProxyFilter`] to the [`Context`]'s [`Extensions`].
/// - Or extract yourself from the username/token validated in the [`ProxyAuthLayer`]
///   to add it manually to the [`Context`]'s [`Extensions`].
///
/// [`HeaderConfigLayer`]: crate::http::layer::header_config::HeaderConfigLayer
/// [`Request`]: crate::http::Request
/// [`ProxyAuthLayer`]: crate::http::layer::proxy_auth::ProxyAuthLayer
/// [`Context`]: crate::service::Context
/// [`Extensions`]: crate::service::context::Extensions
pub struct ProxyFilter {
    /// The ID of the proxy to select.
    pub id: Option<String>,

    /// The country of the proxy.
    pub country: Option<String>,

    /// The ID of the pool from which to select the proxy.
    pub pool_id: Option<String>,

    /// Set explicitly to `true` to select a datacenter proxy.
    pub datacenter: Option<bool>,

    /// Set explicitly to `true` to select a residential proxy.
    pub residential: Option<bool>,

    /// Set explicitly to `true` to select a mobile proxy.
    pub mobile: Option<bool>,
}

mod default_proxy {
    use super::*;
    use venndb::VennDB;

    #[derive(Debug, Clone, VennDB)]
    /// The selected proxy to use to connect to the proxy.
    pub struct Proxy {
        #[venndb(key)]
        /// Unique identifier of the proxy.
        pub id: String,

        /// True if the proxy supports TCP connections.
        pub tcp: bool,

        /// True if the proxy supports UDP connections.
        pub udp: bool,

        /// http-proxy enabled
        pub http: bool,

        /// socks5-proxy enabled
        pub socks5: bool,

        /// Proxy is located in a datacenter.
        pub datacenter: bool,

        /// Proxy's IP is labeled as residential.
        pub residential: bool,

        /// Proxy's IP originates from a mobile network.
        pub mobile: bool,

        /// The address of the proxy to use to connect to the proxy,
        /// containing the port and the host.
        pub address: String,

        #[venndb(filter)]
        /// Pool ID of the proxy.
        ///
        /// TODO: sanatize these?!
        pub pool_id: String,

        #[venndb(filter)]
        /// Country of the proxy.
        ///
        /// TODO: sanatize these?!
        pub country: String,

        /// The optional credentials to use to authenticate with the proxy.
        ///
        /// See [`ProxyCredentials`] for more information.
        pub credentials: Option<ProxyCredentials>,
    }

    impl Proxy {
        /// Check if the proxy is a match for the given[`RequestContext`] and [`ProxyFilter`].
        ///
        /// TODO: add unit tests for this?!
        pub fn is_match(&self, ctx: &RequestContext, filter: &ProxyFilter) -> bool {
            if (ctx.http_version == Version::HTTP_3 && !self.socks5 && !self.udp)
                || (ctx.http_version != Version::HTTP_3 && !self.tcp)
            {
                return false;
            }

            return filter
                .country
                .as_ref()
                .map(|c| c == &self.country)
                .unwrap_or(true)
                && filter
                    .pool_id
                    .as_ref()
                    .map(|p| p == &self.pool_id)
                    .unwrap_or(true)
                && filter
                    .datacenter
                    .map(|d| d == self.datacenter)
                    .unwrap_or(true)
                && filter
                    .residential
                    .map(|r| r == self.residential)
                    .unwrap_or(true)
                && filter.mobile.map(|m| m == self.mobile).unwrap_or(true);
        }
    }
}

pub use default_proxy::{
    Proxy, ProxyDB as MemoryProxyDB, ProxyDBError as MemoryProxyDBInsertError,
    ProxyDBErrorKind as MemoryProxyDBInsertErrorKind, ProxyDBQuery as MemoryProxyDBQuery,
};

#[derive(Debug, Clone)]
/// The credentials to use to authenticate with the proxy.
pub enum ProxyCredentials {
    /// Basic authentication
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc7617> for more information.
    Basic {
        /// The username to use to authenticate with the proxy.
        username: String,
        /// The optional password to use to authenticate with the proxy,
        /// in combination with the username.
        password: Option<String>,
    },
    /// Bearer token authentication, token content is opaque for the proxy facilities.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc6750> for more information.
    Bearer(String),
}

#[derive(Debug, Clone)]
/// The context of the request to use to select a proxy,
/// can be useful to know if a specific protocol or transport is required.
pub struct RequestContext {
    /// The version of the HTTP that is required for
    /// the given [`Request`](crate::http::Request) to be proxied.
    pub http_version: Version,
    /// The [`Scheme`] of the HTTP's [`Uri`](crate::http::Uri) that is defined for
    /// the given [`Request`](crate::http::Request) to be proxied.
    pub scheme: Scheme,
    /// The host of the HTTP's [`Uri`](crate::http::Uri) Authority component that is defined for
    /// the given [`Request`](crate::http::Request) to be proxied.
    pub host: String,
    /// The port of the HTTP's [`Uri`](crate::http::Uri) Authority component that is defined for
    /// the given [`Request`](crate::http::Request) to be proxied.
    ///
    /// It defaults to the standard port of the scheme if not present.
    pub port: Option<u16>,
}

/// The trait to implement to provide a proxy database to other facilities,
/// such as connection pools, to provide a proxy based on the given
/// [`RequestContext`] and [`ProxyFilter`].
pub trait ProxyDB: Send + Sync + 'static {
    /// The error type that can be returned by the proxy database
    ///
    /// Examples are generic I/O issues or
    /// even more common if no proxy match could be found.
    type Error;

    /// Get a [`Proxy`] based on the given [`RequestContext`] and [`ProxyFilter`],
    /// or return an error in case no [`Proxy`] could be returned.
    fn get_proxy(
        &self,
        ctx: RequestContext,
        filter: ProxyFilter,
    ) -> impl Future<Output = Result<Proxy, Self::Error>> + Send + '_;
}

impl ProxyDB for MemoryProxyDB {
    type Error = MemoryProxyDBError;

    async fn get_proxy(
        &self,
        ctx: RequestContext,
        filter: ProxyFilter,
    ) -> Result<Proxy, Self::Error> {
        match &filter.id {
            Some(id) => match self.get_by_id(id) {
                None => Err(MemoryProxyDBError::not_found()),
                Some(proxy) => {
                    if proxy.is_match(&ctx, &filter) {
                        Ok(proxy.clone())
                    } else {
                        Err(MemoryProxyDBError::mismatch())
                    }
                }
            },
            None => {
                let mut query = self.query();

                if let Some(pool_id) = filter.pool_id {
                    query.pool_id(pool_id);
                }
                if let Some(country) = filter.country {
                    query.country(country);
                }

                if let Some(value) = filter.datacenter {
                    query.datacenter(value);
                }
                if let Some(value) = filter.residential {
                    query.residential(value);
                }
                if let Some(value) = filter.mobile {
                    query.mobile(value);
                }

                if ctx.http_version == Version::HTTP_3 {
                    query.udp(true);
                    query.socks5(true);
                } else {
                    // TODO: is there ever a need to allow non-http/3
                    // reqs to request socks5??? Probably yes,
                    // e.g. non-http protocols, but we need to
                    // implement that somehow then. As such... TODO
                    query.tcp(true);
                }

                match query.execute().map(|result| result.any()).cloned() {
                    None => Err(MemoryProxyDBError::not_found()),
                    Some(proxy) => Ok(proxy),
                }
            }
        }
    }
}

/// The error type that can be returned by [`MemoryProxyDB`] when no proxy match could be found.
#[derive(Debug)]
pub struct MemoryProxyDBError {
    kind: MemoryProxyDBErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The kind of error that [`MemoryProxyDBError`] represents.
pub enum MemoryProxyDBErrorKind {
    /// No proxy match could be found.
    NotFound,
    /// A proxy looked up by key had a config that did not match the given filters/requirements.
    Mismatch,
}

impl std::fmt::Display for MemoryProxyDBError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "No proxy match could be found")
    }
}

impl std::error::Error for MemoryProxyDBError {}

impl MemoryProxyDBError {
    fn not_found() -> Self {
        MemoryProxyDBError {
            kind: MemoryProxyDBErrorKind::NotFound,
        }
    }

    fn mismatch() -> Self {
        MemoryProxyDBError {
            kind: MemoryProxyDBErrorKind::Mismatch,
        }
    }

    /// Returns the kind of error that [`MemoryProxyDBError`] represents.
    pub fn kind(&self) -> MemoryProxyDBErrorKind {
        self.kind
    }
}
