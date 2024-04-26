//! A middleware that limits the number of in-flight requests.
//!
//! See [`Limit`].

use crate::error::{Error, StdError};
use crate::service::{Context, Service};

pub mod policy;
pub use policy::{Policy, PolicyOutput};

mod layer;
#[doc(inline)]
pub use layer::LimitLayer;

/// Limit requests based on a policy
#[derive(Debug)]
pub struct Limit<T, P> {
    inner: T,
    policy: P,
}

impl<T, P> Limit<T, P> {
    /// Creates a new [`Limit`] from a limit policy,
    /// wrapping the given service.
    pub fn new(inner: T, policy: P) -> Self {
        Limit { inner, policy }
    }
}

impl<T, P> Clone for Limit<T, P>
where
    T: Clone,
    P: Clone,
{
    fn clone(&self) -> Self {
        Limit {
            inner: self.inner.clone(),
            policy: self.policy.clone(),
        }
    }
}

impl<T, P, State, Request> Service<State, Request> for Limit<T, P>
where
    T: Service<State, Request>,
    T::Error: StdError + Send + Sync + 'static,
    P: policy::Policy<State, Request>,
    P::Error: StdError + Send + Sync + 'static,
    Request: Send + Sync + 'static,
    State: Send + Sync + 'static,
{
    type Response = T::Response;
    type Error = Error;

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
                    return self.inner.serve(ctx, request).await.map_err(Error::new);
                }
                policy::PolicyOutput::Abort(err) => return Err(Error::new(err)),
                policy::PolicyOutput::Retry => (),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::policy::ConcurrentPolicy;
    use super::*;

    use crate::service::{service_fn, Context, Layer, Service};
    use std::convert::Infallible;

    use futures_util::future::join_all;

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

        let mut results = join_all(vec![future_1, future_2]).await;
        let result_1 = results.pop().unwrap();
        let result_2 = results.pop().unwrap();

        // check that one request succeeded and the other failed
        if result_1.is_err() {
            assert_eq!(result_2.unwrap(), "Hello");
        } else {
            assert_eq!(result_1.unwrap(), "Hello");
            assert!(result_2.is_err());
        }
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
