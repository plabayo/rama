use super::{UpgradeService, Upgraded, service::UpgradeHandler};
use rama_core::{Layer, Service, matcher::Matcher};
use rama_http_types::Request;
use std::{convert::Infallible, fmt, sync::Arc};

/// UpgradeLayer is a middleware that can be used to upgrade a request.
///
/// See [`UpgradeService`] for more details.
///
/// [`UpgradeService`]: crate::server::layer::upgrade::UpgradeService
pub struct UpgradeLayer<O> {
    handlers: Vec<Arc<UpgradeHandler<O>>>,
}

impl<O> UpgradeLayer<O> {
    /// Create a new upgrade layer.
    pub fn new<M, R, H>(matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Response = (O, Request), Error = O> + Clone,
        H: Service<Upgraded, Response = (), Error = Infallible> + Clone,
    {
        Self {
            handlers: vec![Arc::new(UpgradeHandler::new(matcher, responder, handler))],
        }
    }

    /// Add an extra upgrade handler to the layer.
    #[must_use]
    pub fn on<M, R, H>(mut self, matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<Request>,
        R: Service<Request, Response = (O, Request), Error = O> + Clone,
        H: Service<Upgraded, Response = (), Error = Infallible> + Clone,
    {
        self.handlers
            .push(Arc::new(UpgradeHandler::new(matcher, responder, handler)));
        self
    }
}

impl<O> fmt::Debug for UpgradeLayer<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpgradeLayer")
            .field("handlers", &self.handlers)
            .finish()
    }
}

impl<O> Clone for UpgradeLayer<O> {
    fn clone(&self) -> Self {
        Self {
            handlers: self.handlers.clone(),
        }
    }
}

impl<S, O> Layer<S> for UpgradeLayer<O> {
    type Service = UpgradeService<S, O>;

    fn layer(&self, inner: S) -> Self::Service {
        UpgradeService::new(self.handlers.clone(), inner)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        UpgradeService::new(self.handlers, inner)
    }
}
