//! Authentication outcome of an established HTTP forward-proxy connection.

use std::fmt;

/// An established HTTP forward proxy requires authentication.
///
/// Returned instead of the response when the connector which forwards over a proxy
/// isolates its authentication challenges, so an intermediary never hands one proxy's
/// challenge to its own client. The proxy's response headers and body are discarded.
#[derive(Debug, Clone, Copy)]
pub struct HttpForwardProxyAuthRequired;

impl fmt::Display for HttpForwardProxyAuthRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HTTP forward proxy authentication required")
    }
}

impl std::error::Error for HttpForwardProxyAuthRequired {}
