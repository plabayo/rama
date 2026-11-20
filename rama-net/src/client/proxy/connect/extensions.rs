use rama_core::extensions::{Extension, Extensions, ExtensionsTransfer};

#[cfg(doc)]
use super::proxy_request;
#[cfg(doc)]
use crate::client::pool::PoolPartition;

/// Extensions for the connection to the proxy, not the origin behind it.
///
/// [`proxy_request`] copies its contents onto the request that dials the proxy.
/// Use it for the proxy's TLS settings (server name, trust, client certificate, ...)
/// or a [`PoolPartition`] of its own. The route still decides where and how the
/// proxy is dialed: its target, transport and, for an HTTP proxy, its version win
/// over the same settings in here.
///
/// Its TLS settings and partition also keep tunnels over differently configured
/// connections to the same proxy apart in the pool.
///
/// Put it on a request, or on one route of a [`ProxyRoutes`] plan. If the bag is a
/// fork of other extensions, the levels it was forked from count too, newest wins.
///
/// [`ProxyRoutes`]: crate::client::ProxyRoutes
#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(net, proxy))]
pub struct ProxyConnectionExtensions(pub Extensions);

/// Moves the contents of [`ProxyConnectionExtensions`] onto the connection to
/// the proxy, see [`proxy_request`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ProxyConnectionExtensionsTransfer;

impl ExtensionsTransfer for ProxyConnectionExtensionsTransfer {
    fn transfer(&self, parent: &Extensions, child: &Extensions) {
        if let Some(settings) = parent.get_ref::<ProxyConnectionExtensions>() {
            child.extend_chain(&settings.0);
        }
    }
}
