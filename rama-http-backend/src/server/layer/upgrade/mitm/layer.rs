use rama_core::{Layer, rt::Executor};

use crate::server::layer::upgrade::mitm::HttpUpgradeMitmRelay;

#[derive(Debug, Clone)]
/// Layer used to create the middleware [`HttpUpgradeMitmRelay`] service.
pub struct HttpUpgradeMitmRelayLayer<M> {
    exec: Executor,
    nested_matcher_svc: M,
}

impl<U> HttpUpgradeMitmRelayLayer<U> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpUpgradeMitmRelayLayer`] used to produce
    /// the middleware [`HttpUpgradeMitmRelay`] service.
    pub const fn new(exec: Executor, nested_matcher_svc: U) -> Self {
        Self {
            exec,
            nested_matcher_svc,
        }
    }
}

impl<M: Clone, S> Layer<S> for HttpUpgradeMitmRelayLayer<M> {
    type Service = HttpUpgradeMitmRelay<M, S>;

    #[inline(always)]
    fn layer(&self, inner_svc: S) -> Self::Service {
        Self::Service::new(
            self.exec.clone(),
            self.nested_matcher_svc.clone(),
            inner_svc,
        )
    }

    #[inline(always)]
    fn into_layer(self, inner_svc: S) -> Self::Service {
        Self::Service::new(self.exec, self.nested_matcher_svc, inner_svc)
    }
}
