use std::fmt;
use std::sync::Arc;

use rama_core::{
    Layer,
    error_sink::{ErrorSink, TracingErrorSink},
    graceful::WeakScope,
};

use super::HttpUpgradeMitmRelay;

#[derive(Clone)]
/// Layer used to create the middleware [`HttpUpgradeMitmRelay`] service.
pub struct HttpUpgradeMitmRelayLayer<M> {
    scope: WeakScope,
    nested_matcher_svc: M,
    error_sink: Arc<dyn ErrorSink>,
}

impl<U> HttpUpgradeMitmRelayLayer<U> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpUpgradeMitmRelayLayer`] used to produce
    /// the middleware [`HttpUpgradeMitmRelay`] service.
    pub fn new(scope: impl Into<WeakScope>, nested_matcher_svc: U) -> Self {
        let scope = scope.into();
        Self {
            scope,
            nested_matcher_svc,
            error_sink: Arc::new(TracingErrorSink::default()),
        }
    }

    /// Set a custom [`ErrorSink`] used to observe errors from the detached
    /// relay task. Defaults to [`TracingErrorSink::default`] (traces at DEBUG).
    #[must_use]
    pub fn with_error_sink(mut self, sink: impl ErrorSink) -> Self {
        self.error_sink = Arc::new(sink);
        self
    }
}

impl<M: fmt::Debug> fmt::Debug for HttpUpgradeMitmRelayLayer<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpUpgradeMitmRelayLayer")
            .field("scope", &self.scope)
            .field("nested_matcher_svc", &self.nested_matcher_svc)
            .finish()
    }
}

impl<M: Clone, S> Layer<S> for HttpUpgradeMitmRelayLayer<M> {
    type Service = HttpUpgradeMitmRelay<M, S>;

    #[inline(always)]
    fn layer(&self, inner_svc: S) -> Self::Service {
        HttpUpgradeMitmRelay::new(
            self.scope.clone(),
            self.nested_matcher_svc.clone(),
            inner_svc,
        )
        .with_error_sink(self.error_sink.clone())
    }

    #[inline(always)]
    fn into_layer(self, inner_svc: S) -> Self::Service {
        HttpUpgradeMitmRelay::new(self.scope, self.nested_matcher_svc, inner_svc)
            .with_error_sink(self.error_sink)
    }
}
