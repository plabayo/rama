//! Upstream proxy types and utilities.

use serde::Deserialize;

#[derive(Debug, Default, Clone, Deserialize)]
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
///
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
