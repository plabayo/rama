use std::fmt;

use super::{Limit, into_output::ErrorIntoOutputFn, policy::UnlimitedPolicy};
use crate::Layer;

/// Limit requests based on a [`Policy`].
///
/// [`Policy`]: crate::layer::limit::Policy
pub struct LimitLayer<P, F = ()> {
    policy: P,
    error_into_output: F,
}

impl<P> LimitLayer<P> {
    /// Creates a new [`LimitLayer`] from a [`crate::layer::limit::Policy`].
    pub const fn new(policy: P) -> Self {
        Self {
            policy,
            error_into_output: (),
        }
    }

    /// Attach a function to this [`LimitLayer`] to allow you to turn the Policy error
    /// into a Result fully compatible with the inner `Service` Result.
    pub fn with_error_into_response_fn<F>(self, f: F) -> LimitLayer<P, ErrorIntoOutputFn<F>> {
        LimitLayer {
            policy: self.policy,
            error_into_output: ErrorIntoOutputFn(f),
        }
    }
}

impl LimitLayer<UnlimitedPolicy> {
    /// Creates a new [`LimitLayer`] with an unlimited policy.
    ///
    /// Meaning that all requests are allowed to proceed.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(UnlimitedPolicy::default())
    }
}

impl<P: fmt::Debug, F: fmt::Debug> std::fmt::Debug for LimitLayer<P, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LimitLayer")
            .field("policy", &self.policy)
            .field("self.error_into_output", &self.error_into_output)
            .finish()
    }
}

impl<P, F> Clone for LimitLayer<P, F>
where
    P: Clone,
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
            error_into_output: self.error_into_output.clone(),
        }
    }
}

impl<T, P, F> Layer<T> for LimitLayer<P, F>
where
    P: Clone,
    F: Clone,
{
    type Service = Limit<T, P, F>;

    fn layer(&self, service: T) -> Self::Service {
        Limit {
            inner: service,
            policy: self.policy.clone(),
            error_into_output: self.error_into_output.clone(),
        }
    }

    fn into_layer(self, service: T) -> Self::Service {
        Limit {
            inner: service,
            policy: self.policy,
            error_into_output: self.error_into_output,
        }
    }
}
