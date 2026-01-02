use std::marker::PhantomData;

use rama_core::Layer;

use super::GrpcConnector;

#[derive(Clone, Debug)]
/// A [`Layer`] that produces a [`GrpcConnector`].
pub struct GrpcConnectorLayer<Body> {
    _phantom: PhantomData<Body>,
}

impl<Body> GrpcConnectorLayer<Body> {
    /// Create a new [`GrpcConnectorLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<Body> Default for GrpcConnectorLayer<Body> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, Body> Layer<S> for GrpcConnectorLayer<Body> {
    type Service = GrpcConnector<S, Body>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        GrpcConnector::new(inner)
    }
}
