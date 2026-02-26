use rama::net::{
    address::HostWithPort,
    apple::networkextension::tproxy::TransparentProxyFlowMeta,
    proxy::ProxyTarget,
};

/// Resolve a remote target endpoint from extensions.
pub(super) fn resolve_target_from_extensions(
    ext: &rama::extensions::Extensions,
) -> Option<HostWithPort> {
    ext.get::<ProxyTarget>()
        .cloned()
        .map(|target| target.0)
        .or_else(|| ext.get::<TransparentProxyFlowMeta>().and_then(|meta| meta.remote_endpoint.clone()))
}
