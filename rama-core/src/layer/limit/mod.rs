//! A middleware that limits the number of in-flight inputs.
//!
//! See [`Limit`].

use crate::Service;
use crate::error::{BoxError, ErrorContext as _};
use into_output::{ErrorIntoOutput, ErrorIntoOutputFn};
use rama_utils::macros::define_inner_service_accessors;

pub mod policy;
use policy::UnlimitedPolicy;
pub use policy::{Policy, PolicyOutput};

mod layer;
#[doc(inline)]
pub use layer::LimitLayer;

mod into_output;

/// Limit inputs based on a [`Policy`].
///
/// [`Policy`]: crate::layer::limit::Policy
#[derive(Debug, Clone)]
pub struct Limit<S, P, F = ()> {
    inner: S,
    policy: P,
    error_into_output: F,
}

impl<S, P> Limit<S, P, ()> {
    /// Creates a new [`Limit`] from a limit [`Policy`],
    /// wrapping the given [`Service`].
    pub const fn new(inner: S, policy: P) -> Self {
        Self {
            inner,
            policy,
            error_into_output: (),
        }
    }

    /// Attach a function to this [`Limit`] to allow you to turn the Policy error
    /// into a Result fully compatible with the inner `Service` Result.
    pub fn with_error_into_output_fn<F>(self, f: F) -> Limit<S, P, ErrorIntoOutputFn<F>> {
        Limit {
            inner: self.inner,
            policy: self.policy,
            error_into_output: ErrorIntoOutputFn(f),
        }
    }

    define_inner_service_accessors!();
}

impl<T> Limit<T, UnlimitedPolicy, ()> {
    /// Creates a new [`Limit`] with an unlimited policy.
    ///
    /// Meaning that all inputs are allowed to proceed.
    pub const fn unlimited(inner: T) -> Self {
        Self {
            inner,
            policy: UnlimitedPolicy,
            error_into_output: (),
        }
    }
}

impl<T, P, Input> Service<Input> for Limit<T, P, ()>
where
    T: Service<Input, Error: Into<BoxError>>,
    P: policy::Policy<Input, Error: Into<BoxError>>,
    Input: Send + Sync + 'static,
{
    type Output = T::Output;
    type Error = BoxError;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        loop {
            let result = self.policy.check(input).await;

            input = result.input;

            match result.output {
                policy::PolicyOutput::Ready(guard) => {
                    let _ = guard;
                    return self.inner.serve(input).await.into_box_error();
                }
                policy::PolicyOutput::Abort(err) => return Err(err.into()),
                policy::PolicyOutput::Retry => (),
            }
        }
    }
}

impl<T, P, F, Input, FnOutput, FnError> Service<Input> for Limit<T, P, ErrorIntoOutputFn<F>>
where
    T: Service<Input>,
    P: policy::Policy<Input>,
    F: Fn(P::Error) -> Result<FnOutput, FnError> + Send + Sync + 'static,
    FnOutput: Into<T::Output> + Send + 'static,
    FnError: Into<T::Error> + Send + Sync + 'static,
    Input: Send + Sync + 'static,
{
    type Output = T::Output;
    type Error = T::Error;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        loop {
            let result = self.policy.check(input).await;

            input = result.input;

            match result.output {
                policy::PolicyOutput::Ready(guard) => {
                    let _ = guard;
                    return self.inner.serve(input).await;
                }
                policy::PolicyOutput::Abort(err) => {
                    return match self.error_into_output.error_into_output(err) {
                        Ok(ok) => Ok(ok.into()),
                        Err(err) => Err(err.into()),
                    };
                }
                policy::PolicyOutput::Retry => (),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::policy::ConcurrentPolicy;
    use super::*;

    use crate::futures::zip;
    use crate::{Layer, Service, service::service_fn};
    use std::convert::Infallible;

    #[tokio::test]
    async fn test_limit() {
        async fn handle_input<Input>(req: Input) -> Result<Input, Infallible> {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            Ok(req)
        }

        let layer: LimitLayer<ConcurrentPolicy<_, _>> = LimitLayer::new(ConcurrentPolicy::max(1));

        let service_1 = layer.layer(service_fn(handle_input));
        let service_2 = layer.layer(service_fn(handle_input));

        let future_1 = service_1.serve("Hello");
        let future_2 = service_2.serve("Hello");

        let (result_1, result_2) = zip(future_1, future_2).await;

        // check that one input succeeded and the other failed
        if let Ok(value_1) = result_1 {
            assert_eq!(value_1, "Hello");
            assert!(result_2.is_err());
        } else {
            assert_eq!(result_2.unwrap(), "Hello");
        }
    }

    #[tokio::test]
    async fn test_with_error_into_response_fn() {
        async fn handle_input<Input>(_req: Input) -> Result<&'static str, Infallible> {
            Ok("good")
        }

        let layer: LimitLayer<ConcurrentPolicy<_, _>, _> =
            LimitLayer::new(ConcurrentPolicy::max(0))
                .with_error_into_response_fn(|_| Ok::<_, Infallible>("bad"));

        let service = layer.layer(service_fn(handle_input));

        let resp = service.serve("Hello").await.unwrap();
        assert_eq!("bad", resp);
    }

    #[tokio::test]
    async fn test_zero_limit() {
        async fn handle_input<Input>(req: Input) -> Result<Input, Infallible> {
            Ok(req)
        }

        let layer: LimitLayer<ConcurrentPolicy<_, _>> = LimitLayer::new(ConcurrentPolicy::max(0));

        let service_1 = layer.layer(service_fn(handle_input));
        let result_1 = service_1.serve("Hello").await;
        assert!(result_1.is_err());
    }
}
