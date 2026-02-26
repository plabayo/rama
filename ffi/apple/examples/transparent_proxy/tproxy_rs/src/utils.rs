use rama::net::{
    address::HostWithPort,
    apple::networkextension::tproxy::{TransparentProxyConfig, TransparentProxyMeta},
    proxy::ProxyTarget,
};

/// Resolve a remote target endpoint from extensions.
pub(super) fn resolve_target_from_extensions(
    ext: &rama::extensions::Extensions,
) -> Option<HostWithPort> {
    ext.get::<ProxyTarget>()
        .cloned()
        .map(|target| target.0)
        .or_else(|| {
            ext.get::<TransparentProxyMeta>()
                .and_then(|meta| meta.remote_endpoint().cloned())
        })
        .or_else(|| {
            ext.get::<TransparentProxyConfig>()
                .and_then(|cfg| cfg.default_remote_endpoint().cloned())
        })
}
