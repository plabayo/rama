use std::sync::Arc;

use rama_core::graceful::WeakScope;

#[derive(Clone)]
pub struct TransparentProxyServiceContext {
    pub scope: WeakScope,
    pub(super) network_path: tokio::sync::watch::Receiver<super::TransparentProxyNetworkPath>,
    pub(super) opaque_config: Option<Arc<[u8]>>,
    pub(super) provider_pid: u32,
    pub(super) provider_generation: u64,
    pub(super) udp_ingress_per_flow_max_bytes: usize,
    pub(super) udp_ingress_global_max_bytes: usize,
}

impl TransparentProxyServiceContext {
    /// Subscribe to provider network changes. This is a hint to reassess routing policy,
    /// not permission to bypass a flow's configured connector or interface constraints.
    pub fn network_path_changes(
        &self,
    ) -> tokio::sync::watch::Receiver<super::TransparentProxyNetworkPath> {
        self.network_path.clone()
    }

    pub fn opaque_config(&self) -> Option<&[u8]> {
        self.opaque_config.as_deref()
    }

    /// PID of the process that owns this immutable engine generation.
    pub fn provider_pid(&self) -> u32 {
        self.provider_pid
    }

    /// Process-local monotonic identity of this immutable engine generation.
    pub fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    /// The intercepted UDP ingress one flow may hold, as this engine bounds it: a service that
    /// queues a flow's datagrams itself should hold no more.
    pub fn udp_ingress_per_flow_max_bytes(&self) -> usize {
        self.udp_ingress_per_flow_max_bytes
    }

    /// The intercepted UDP ingress all flows together may hold, as this engine bounds it.
    pub fn udp_ingress_global_max_bytes(&self) -> usize {
        self.udp_ingress_global_max_bytes
    }
}
