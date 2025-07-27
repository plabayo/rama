//! A middleware that limits the number of in-flight requests.
//!
//! See [`Limit`].

use std::fmt;

use crate::error::BoxError;
use crate::{Context, Service};
use into_response::{ErrorIntoResponse, ErrorIntoResponseFn};
use rama_utils::macros::define_inner_service_accessors;

pub mod policy;
use policy::UnlimitedPolicy;
pub use policy::{Policy, PolicyOutput};

mod layer;
#[doc(inline)]
pub use layer::LimitLayer;

mod into_response;

/// Limit requests based on a [`Policy`].
///
/// [`Policy`]: crate::layer::limit::Policy
pub struct Limit<S, P, F = ()> {
    inner: S,
    policy: P,
    error_into_response: F,
}

impl<S, P> Limit<S, P, ()> {
    /// Creates a new [`Limit`] from a limit [`Policy`],
    /// wrapping the given [`Service`].
    pub const fn new(inner: S, policy: P) -> Self {
        Self {
            inner,
            policy,
            error_into_response: (),
        }
    }

    /// Attach a function to this [`Limit`] to allow you to turn the Policy error
    /// into a Result fully compatible with the inner `Service` Result.
    pub fn with_error_into_response_fn<F>(self, f: F) -> Limit<S, P, ErrorIntoResponseFn<F>> {
        Limit {
            inner: self.inner,
            policy: self.policy,
            error_into_response: ErrorIntoResponseFn(f),
        }
    }

    define_inner_service_accessors!();
}

impl<T> Limit<T, UnlimitedPolicy, ()> {
    /// Creates a new [`Limit`] with an unlimited policy.
    ///
    /// Meaning that all requests are allowed to proceed.
    pub const fn unlimited(inner: T) -> Self {
        Self {
            inner,
            policy: UnlimitedPolicy,
            error_into_response: (),
        }
    }
}

impl<T: fmt::Debug, P: fmt::Debug, F: fmt::Debug> fmt::Debug for Limit<T, P, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Limit")
            .field("inner", &self.inner)
            .field("policy", &self.policy)
            .field("error_into_response", &self.error_into_response)
            .finish()
    }
}

impl<T, P, F> Clone for Limit<T, P, F>
where
    T: Clone,
    P: Clone,
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            policy: self.policy.clone(),
            error_into_response: self.error_into_response.clone(),
        }
    }
}

impl<T, P, State, Request> Service<State, Request> for Limit<T, P, ()>
where
    T: Service<State, Request, Error: Into<BoxError>>,
    P: policy::Policy<State, Request, Error: Into<BoxError>>,
    Request: Send + Sync + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = T::Response;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        mut request: Request,
    ) -> Result<Self::Response, Self::Error> {
        loop {
            let result = self.policy.check(ctx, request).await;
            ctx = result.ctx;
            request = result.request;

            match result.output {
                policy::PolicyOutput::Ready(guard) => {
                    let _ = guard;
                    return self.inner.serve(ctx, request).await.map_err(Into::into);
                }
                policy::PolicyOutput::Abort(err) => return Err(err.into()),
                policy::PolicyOutput::Retry => (),
            }
        }
    }
}

impl<T, P, F, State, Request, FnResponse, FnError> Service<State, Request>
    for Limit<T, P, ErrorIntoResponseFn<F>>
where
    T: Service<State, Request>,
    P: policy::Policy<State, Request>,
    F: Fn(P::Error) -> Result<FnResponse, FnError> + Send + Sync + 'static,
    FnResponse: Into<T::Response> + Send + 'static,
    FnError: Into<T::Error> + Send + Sync + 'static,
    Request: Send + Sync + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = T::Response;
    type Error = T::Error;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        mut request: Request,
    ) -> Result<Self::Response, Self::Error> {
        loop {
            let result = self.policy.check(ctx, request).await;
            ctx = result.ctx;
            request = result.request;

            match result.output {
                policy::PolicyOutput::Ready(guard) => {
                    let _ = guard;
                    return self.inner.serve(ctx, request).await;
                }
                policy::PolicyOutput::Abort(err) => {
                    return match self.error_into_response.error_into_response(err) {
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
    use crate::{Context, Layer, Service, service::service_fn};
    use std::convert::Infallible;

    #[tokio::test]
    async fn test_limit() {
        async fn handle_request<State, Request>(
            _ctx: Context<State>,
            req: Request,
        ) -> Result<Request, Infallible> {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            Ok(req)
        }

        let layer: LimitLayer<ConcurrentPolicy<_, _>> = LimitLayer::new(ConcurrentPolicy::max(1));

        let service_1 = layer.layer(service_fn(handle_request));
        let service_2 = layer.layer(service_fn(handle_request));

        let future_1 = service_1.serve(Context::default(), "Hello");
        let future_2 = service_2.serve(Context::default(), "Hello");

        let (result_1, result_2) = zip(future_1, future_2).await;

        // check that one request succeeded and the other failed
        if result_1.is_err() {
            assert_eq!(result_2.unwrap(), "Hello");
        } else {
            assert_eq!(result_1.unwrap(), "Hello");
            assert!(result_2.is_err());
        }
    }

    #[tokio::test]
    async fn test_with_error_into_response_fn() {
        async fn handle_request<State, Request>(
            _ctx: Context<State>,
            _req: Request,
        ) -> Result<&'static str, Infallible> {
            Ok("good")
        }

        let layer: LimitLayer<ConcurrentPolicy<_, _>, _> =
            LimitLayer::new(ConcurrentPolicy::max(0))
                .with_error_into_response_fn(|_| Ok::<_, Infallible>("bad"));

        let service = layer.layer(service_fn(handle_request));

        let resp = service.serve(Context::default(), "Hello").await.unwrap();
        assert_eq!("bad", resp);
    }

    #[tokio::test]
    async fn test_zero_limit() {
        async fn handle_request<State, Request>(
            _ctx: Context<State>,
            req: Request,
        ) -> Result<Request, Infallible> {
            Ok(req)
        }

        let layer: LimitLayer<ConcurrentPolicy<_, _>> = LimitLayer::new(ConcurrentPolicy::max(0));

        let service_1 = layer.layer(service_fn(handle_request));
        let result_1 = service_1.serve(Context::default(), "Hello").await;
        assert!(result_1.is_err());
    }
}
