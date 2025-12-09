use super::Retry;
use rama_core::Layer;

/// Retry requests based on a policy
#[derive(Debug, Clone)]
pub struct RetryLayer<P> {
    policy: P,
}

impl<P> RetryLayer<P> {
    /// Creates a new [`RetryLayer`] from a retry policy.
    pub const fn new(policy: P) -> Self {
        Self { policy }
    }
}

impl<P, S> Layer<S> for RetryLayer<P>
where
    P: Clone,
{
    type Service = Retry<P, S>;

    fn layer(&self, service: S) -> Self::Service {
        Retry::new(self.policy.clone(), service)
    }

    fn into_layer(self, service: S) -> Self::Service {
        Retry::new(self.policy, service)
    }
}
