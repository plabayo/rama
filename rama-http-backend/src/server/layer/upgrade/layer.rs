use super::{UpgradeService, Upgraded, service::UpgradeHandler};
use rama_core::{Context, Layer, Service, matcher::Matcher};
use rama_http_types::Request;
use std::{convert::Infallible, fmt, sync::Arc};

/// UpgradeLayer is a middleware that can be used to upgrade a request.
///
/// See [`UpgradeService`] for more details.
///
/// [`UpgradeService`]: crate::server::layer::upgrade::UpgradeService
pub struct UpgradeLayer<S, O> {
    handlers: Vec<Arc<UpgradeHandler<S, O>>>,
}

impl<S, O> UpgradeLayer<S, O> {
    /// Create a new upgrade layer.
    pub fn new<M, R, H>(matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<S, Request>,
        R: Service<S, Request, Response = (O, Context<S>, Request), Error = O> + Clone,
        H: Service<S, Upgraded, Response = (), Error = Infallible> + Clone,
    {
        Self {
            handlers: vec![Arc::new(UpgradeHandler::new(matcher, responder, handler))],
        }
    }

    /// Add an extra upgrade handler to the layer.
    #[must_use]
    pub fn on<M, R, H>(mut self, matcher: M, responder: R, handler: H) -> Self
    where
        M: Matcher<S, Request>,
        R: Service<S, Request, Response = (O, Context<S>, Request), Error = O> + Clone,
        H: Service<S, Upgraded, Response = (), Error = Infallible> + Clone,
    {
        self.handlers
            .push(Arc::new(UpgradeHandler::new(matcher, responder, handler)));
        self
    }
}

impl<S, O> fmt::Debug for UpgradeLayer<S, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpgradeLayer")
            .field("handlers", &self.handlers)
            .finish()
    }
}

impl<S, O> Clone for UpgradeLayer<S, O> {
    fn clone(&self) -> Self {
        Self {
            handlers: self.handlers.clone(),
        }
    }
}

impl<S, State, O> Layer<S> for UpgradeLayer<State, O> {
    type Service = UpgradeService<S, State, O>;

    fn layer(&self, inner: S) -> Self::Service {
        UpgradeService::new(self.handlers.clone(), inner)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        UpgradeService::new(self.handlers, inner)
    }
}
