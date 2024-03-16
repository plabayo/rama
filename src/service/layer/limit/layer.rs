use super::Limit;
use crate::service::Layer;

/// Limit requests based on a policy
#[derive(Debug)]
pub struct LimitLayer<P> {
    policy: P,
}

impl<P> LimitLayer<P> {
    /// Creates a new [`LimitLayer`] from a [`crate::service::layer::limit::Policy`].
    pub fn new(policy: P) -> Self {
        LimitLayer { policy }
    }
}

impl<P> Clone for LimitLayer<P>
where
    P: Clone,
{
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
        }
    }
}

impl<T, P> Layer<T> for LimitLayer<P>
where
    P: Clone,
{
    type Service = Limit<T, P>;

    fn layer(&self, service: T) -> Self::Service {
        let policy = self.policy.clone();
        Limit::new(service, policy)
    }
}
