use rama_core::Layer;

use super::GrpcWebService;

/// Layer implementing the grpc-web protocol.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct GrpcWebLayer;

impl GrpcWebLayer {
    /// Create a new grpc-web layer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> Layer<S> for GrpcWebLayer {
    type Service = GrpcWebService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcWebService::new(inner)
    }
}
