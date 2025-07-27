use super::Retry;
use rama_core::Layer;
use std::fmt;

/// Retry requests based on a policy
pub struct RetryLayer<P> {
    policy: P,
}

impl<P: fmt::Debug> fmt::Debug for RetryLayer<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RetryLayer")
            .field("policy", &self.policy)
            .finish()
    }
}

impl<P: Clone> Clone for RetryLayer<P> {
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
        }
    }
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
