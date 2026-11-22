use rama_core::extensions::{Extension, Extensions, ExtensionsTransfer};

#[cfg(doc)]
use super::proxy_request;
#[cfg(doc)]
use crate::client::pool::{PoolPartition, ReuseKey};

/// [Connection-scoped] extensions for the hop to the proxy.
///
/// A request's extensions configure its way to the origin; this bag is how you configure
/// the connection to the proxy itself. [`proxy_request`] copies it onto the request that
/// dials the proxy, so it acts as that hop's request extensions: TLS settings for the
/// proxy, a [`PoolPartition`] of its own, or a [`ProxyRoute`] to reach the proxy through
/// another proxy. The proxy address still decides target, transport and HTTP version.
///
/// It is connection scoped itself, so it configures this one hop only. For the hop after
/// it, put a bag in this bag. Its TLS settings and partition also keep tunnels over
/// differently configured connections to one proxy apart in the pool.
///
/// The connection *to* a proxy is, for example, TCP → TLS → HTTP/2 to `proxy.example:443`;
/// many CONNECT streams share it. A connection *through* the proxy is one of those
/// streams → TLS → HTTP/2 to the origin, and is always kept per credential. This bag only
/// configures the first kind.
///
/// A connection to a proxy is shared across credentials by default, as each request and
/// each CONNECT carries its own `Proxy-Authorization`. When a proxy binds its
/// authentication or state to the connection (NTLM, Negotiate, a session per connection),
/// give each credential its own [`PoolPartition`] in this bag. Build it from a hash of the
/// credential with [`ReuseKey::from_bits`], not from the credential itself: a partition
/// shows up in debug logs.
///
/// Put it on a request, or on one route of a [`ProxyRoutes`] plan.
///
/// [Connection-scoped]: rama_core::extensions::ExtensionScope::Connection
/// [`ProxyRoute`]: crate::client::ProxyRoute
/// [`ProxyRoutes`]: crate::client::ProxyRoutes
#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(net, proxy), scope(connection))]
pub struct ProxyConnectionExtensions(pub Extensions);

/// Moves the contents of [`ProxyConnectionExtensions`] onto the connection to
/// the proxy, see [`proxy_request`].
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ProxyConnectionExtensionsTransfer;

impl ProxyConnectionExtensionsTransfer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ExtensionsTransfer for ProxyConnectionExtensionsTransfer {
    fn transfer(&self, parent: &Extensions, child: &Extensions) {
        if let Some(settings) = parent.get_ref::<ProxyConnectionExtensions>() {
            child.extend_chain(&settings.0);
        }
    }
}
