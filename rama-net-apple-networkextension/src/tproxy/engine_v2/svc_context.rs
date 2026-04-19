use std::sync::Arc;

use rama_core::rt::Executor;

#[derive(Clone)]
pub(crate) struct TransparentProxyServiceContext {
    pub(crate) executor: Executor,
    pub(super) opaque_config: Option<Arc<[u8]>>,
}

impl TransparentProxyServiceContext {
    pub(crate) fn opaque_config(&self) -> Option<&[u8]> {
        self.opaque_config.as_deref()
    }
}
