//! Middleware for retrying "failed" requests.

use crate::service::{Context, Service};

pub mod budget;
mod layer;
mod policy;

#[cfg(test)]
mod tests;

pub use self::layer::RetryLayer;
pub use self::policy::{Policy, PolicyResult};

/// Configure retrying requests of "failed" responses.
///
/// A [`Policy`] classifies what is a "failed" response.
pub struct Retry<P, S> {
    policy: P,
    service: S,
}

impl<P, S> std::fmt::Debug for Retry<P, S>
where
    P: std::fmt::Debug,
    S: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Retry")
            .field("policy", &self.policy)
            .field("service", &self.service)
            .finish()
    }
}

impl<P, S> Clone for Retry<P, S>
where
    P: Clone,
    S: Clone,
{
    fn clone(&self) -> Self {
        Retry {
            policy: self.policy.clone(),
            service: self.service.clone(),
        }
    }
}

// ===== impl Retry =====

impl<P, S> Retry<P, S> {
    /// Retry the inner service depending on this [`Policy`].
    pub fn new(policy: P, service: S) -> Self {
        Retry { policy, service }
    }

    /// Get a reference to the inner service
    pub fn get_ref(&self) -> &S {
        &self.service
    }

    /// Get a mutable reference to the inner service
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.service
    }

    /// Consume `self`, returning the inner service
    pub fn into_inner(self) -> S {
        self.service
    }
}

impl<P, S, State, Request> Service<State, Request> for Retry<P, S>
where
    P: Policy<State, Request, S::Response, S::Error>,
    S: Service<State, Request>,
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> Result<Self::Response, Self::Error> {
        let mut ctx = ctx;
        let mut request = request;

        let mut cloned = self.policy.clone_input(&ctx, &request);

        loop {
            let resp = self.service.serve(ctx, request).await;
            match cloned.take() {
                Some((cloned_ctx, cloned_req)) => {
                    let (cloned_ctx, cloned_req) =
                        match self.policy.retry(cloned_ctx, cloned_req, resp).await {
                            PolicyResult::Abort(result) => return result,
                            PolicyResult::Retry { ctx, req } => (ctx, req),
                        };

                    cloned = self.policy.clone_input(&cloned_ctx, &cloned_req);
                    ctx = cloned_ctx;
                    request = cloned_req;
                }
                // no clone was made, so no possibility to retry
                None => return resp,
            }
        }
    }
}
