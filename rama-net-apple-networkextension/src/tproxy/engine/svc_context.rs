use std::sync::Arc;

use rama_core::rt::Executor;

#[derive(Clone)]
pub struct TransparentProxyServiceContext {
    pub executor: Executor,
    pub(super) opaque_config: Option<Arc<[u8]>>,
    pub(super) provider_pid: u32,
    pub(super) provider_generation: u64,
}

impl TransparentProxyServiceContext {
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
}
