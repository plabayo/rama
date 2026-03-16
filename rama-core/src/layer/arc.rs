use std::sync::Arc;

use crate::Layer;

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// [`Layer`] for [`Arc`]ing a [`crate::Service`].
pub struct ArcLayer;

impl ArcLayer {
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for ArcLayer {
    type Service = Arc<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        Arc::new(inner)
    }
}
