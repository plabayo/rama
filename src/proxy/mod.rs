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

use crate::http::Version;
use serde::Deserialize;
use std::future::Future;

pub mod username;
pub use username::{parse_username_config, UsernameConfig};

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
    pub datacenter: bool,

    /// Set explicitly to `true` to select a residential proxy.
    pub residential: bool,

    /// Set explicitly to `true` to select a mobile proxy.
    pub mobile: bool,
}

#[derive(Debug, Clone)]
/// The selected proxy to use to connect to the proxy.
pub struct Proxy {
    /// The transport of the proxy to use to connect to the proxy.
    ///
    /// See [`ProxyTransport`] for more information.
    pub transport: ProxyTransport,

    /// The protocol of the proxy to use to connect to the proxy.
    ///
    /// See [`ProxyProtocol`] for more information.
    pub protocol: ProxyProtocol,

    /// The address of the proxy to use to connect to the proxy,
    /// containing the port and the host.
    pub address: String,

    /// The optional credentials to use to authenticate with the proxy.
    ///
    /// See [`ProxyCredentials`] for more information.
    pub credentials: Option<ProxyCredentials>,
}

#[derive(Debug, Clone)]
/// The protocol of the proxy to use to connect to the proxy.
pub enum ProxyProtocol {
    /// HTTP proxy
    Http,
    /// Socks5 proxy
    Socks5,
}

#[derive(Debug, Clone)]
/// The transport of the proxy to use to connect to the proxy.
pub enum ProxyTransport {
    /// Use TCP to connect to the proxy
    Tcp,
    /// Use UDP to connect to the proxy
    Udp,
}

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
        /// in combiantion with the username.
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
    /// The scheme of the HTTP's [`Uri`](crate::http::Uri) that is defined for
    /// the given [`Request`](crate::http::Request) to be proxied.
    pub scheme: String,
    /// The host of the HTTP's [`Uri`](crate::http::Uri) Authority component that is defined for
    /// the given [`Request`](crate::http::Request) to be proxied.
    pub host: String,
    /// The port of the HTTP's [`Uri`](crate::http::Uri) Authority component that is defined for
    /// the given [`Request`](crate::http::Request) to be proxied.
    ///
    /// It defaults to the standard port of the scheme if not present.
    pub port: u16,
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
