//! Client Http Proxy Connector Support.

pub mod layer;

mod forward;
#[doc(inline)]
pub use forward::{HttpForwardProxyConnection, HttpForwardProxyConnector, forwarding_proxy};

mod select;
#[doc(inline)]
pub use select::{HttpForwardRoute, HttpTunnelRoute};

use rama_core::extensions::Extensions;
use rama_net::{address::ProxyAddress, client::ConnectionError};

/// Whether the connection to a proxy is one credentials may travel over.
#[cfg(feature = "tls")]
pub(crate) fn verify_proxy_tls(
    proxy: &ProxyAddress,
    conn: &Extensions,
) -> Result<(), ConnectionError> {
    rama_tls::client::verify_proxy_tls(proxy, conn)
}

#[cfg(not(feature = "tls"))]
/// Whether the connection to a proxy is one credentials may travel over.
pub(crate) fn verify_proxy_tls(
    proxy: &ProxyAddress,
    _: &Extensions,
) -> Result<(), ConnectionError> {
    if !proxy.protocol.is_secure() {
        return Ok(());
    }
    Err(ConnectionError::transport(
        rama_core::error::BoxError::from_static_str(
            "https proxy selected without proxy-side TLS support",
        ),
        rama_net::client::ConnectionErrorKind::Protocol,
    ))
}
