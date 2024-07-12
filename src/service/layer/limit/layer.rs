use std::fmt;

use super::{policy::UnlimitedPolicy, Limit};
use crate::service::Layer;

/// Limit requests based on a [`Policy`].
///
/// [`Policy`]: crate::service::layer::limit::Policy
pub struct LimitLayer<P> {
    policy: P,
}

impl<P> LimitLayer<P> {
    /// Creates a new [`LimitLayer`] from a [`crate::service::layer::limit::Policy`].
    pub fn new(policy: P) -> Self {
        LimitLayer { policy }
    }
}

impl LimitLayer<UnlimitedPolicy> {
    /// Creates a new [`LimitLayer`] with an unlimited policy.
    ///
    /// Meaning that all requests are allowed to proceed.
    pub fn unlimited() -> Self {
        Self::new(UnlimitedPolicy::default())
    }
}

impl<P: fmt::Debug> std::fmt::Debug for LimitLayer<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LimitLayer")
            .field("policy", &self.policy)
            .finish()
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
