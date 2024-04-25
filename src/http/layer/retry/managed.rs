//! Managed retry [`Policy`].
//!
//! See [`ManagedPolicy`] for more details.
//!
//! [`Policy`]: super::Policy

use super::{Policy, PolicyResult, RetryBody};
use crate::{
    http::{Request, Response},
    service::{util::backoff::Backoff, Context},
};
use std::future::Future;

/// A managed retry [`Policy`],
/// which allows for an easier interface to configure retrying requests.
pub struct ManagedPolicy<B = Undefined, C = Undefined, R = Undefined> {
    backoff: B,
    clone: C,
    retry: R,
}

impl<B, C, R, State, Response, Error> Policy<State, Response, Error> for ManagedPolicy<B, C, R>
where
    B: Backoff,
    C: CloneInput<State>,
    R: RetryRule<Response, Error>,
    State: Send + Sync + 'static,
    Response: Send + 'static,
    Error: Send + Sync + 'static,
{
    async fn retry(
        &self,
        ctx: Context<State>,
        req: Request<RetryBody>,
        result: Result<Response, Error>,
    ) -> PolicyResult<State, Response, Error> {
        let (result, retry) = self.retry.retry(result).await;
        if retry && self.backoff.next_backoff().await {
            PolicyResult::Retry { ctx, req }
        } else {
            self.backoff.reset().await;
            PolicyResult::Abort(result)
        }
    }

    fn clone_input(
        &self,
        ctx: &Context<State>,
        req: &Request<RetryBody>,
    ) -> Option<(Context<State>, Request<RetryBody>)> {
        self.clone.clone_input(ctx, req)
    }
}

impl<B, C, R> std::fmt::Debug for ManagedPolicy<B, C, R>
where
    B: std::fmt::Debug,
    C: std::fmt::Debug,
    R: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedPolicy")
            .field("backoff", &self.backoff)
            .field("clone", &self.clone)
            .field("retry", &self.retry)
            .finish()
    }
}

impl<B, C, R> Clone for ManagedPolicy<B, C, R>
where
    B: Clone,
    C: Clone,
    R: Clone,
{
    fn clone(&self) -> Self {
        ManagedPolicy {
            backoff: self.backoff.clone(),
            clone: self.clone.clone(),
            retry: self.retry.clone(),
        }
    }
}

impl Default for ManagedPolicy<Undefined, Undefined, Undefined> {
    fn default() -> Self {
        ManagedPolicy {
            backoff: Undefined,
            clone: Undefined,
            retry: Undefined,
        }
    }
}

impl<F> ManagedPolicy<Undefined, Undefined, F> {
    /// Create a new [`ManagedPolicy`] which uses the provided
    /// function to determine if a request should be retried.
    ///
    /// The default cloning is used and no backoff is applied.
    pub fn new(retry: F) -> Self {
        ManagedPolicy {
            backoff: Undefined,
            clone: Undefined,
            retry,
        }
    }
}

impl<B, C, R> ManagedPolicy<B, C, R> {
    /// add a backoff to this [`ManagedPolicy`].
    pub fn with_backoff<B2>(self, backoff: B2) -> ManagedPolicy<B2, C, R> {
        ManagedPolicy {
            backoff,
            clone: self.clone,
            retry: self.retry,
        }
    }

    /// add a cloning function to this [`ManagedPolicy`].
    /// to determine if a request should be cloned
    pub fn with_clone<C2>(self, clone: C2) -> ManagedPolicy<B, C2, R> {
        ManagedPolicy {
            backoff: self.backoff,
            clone,
            retry: self.retry,
        }
    }
}

/// A trait that is used to umbrella-cover all possible
/// implementation kinds for the retry rule functionality.
pub trait RetryRule<R, E>: private::Sealed<(R, E)> + Send + Sync + 'static {
    /// Check if the given result should be retried.
    fn retry(&self, result: Result<R, E>)
        -> impl Future<Output = (Result<R, E>, bool)> + Send + '_;
}

impl<Body, E> RetryRule<Response<Body>, E> for Undefined
where
    E: std::fmt::Debug + Send + Sync + 'static,
    Body: Send + 'static,
{
    async fn retry(&self, result: Result<Response<Body>, E>) -> (Result<Response<Body>, E>, bool) {
        match &result {
            Ok(response) => {
                let status = response.status();
                if status.is_server_error() {
                    tracing::debug!(
                        "retrying server error http status code: {status} ({})",
                        status.as_u16()
                    );
                    (result, true)
                } else {
                    (result, false)
                }
            }
            Err(error) => {
                tracing::debug!("retrying error: {:?}", error);
                (result, true)
            }
        }
    }
}

impl<F, Fut, R, E> RetryRule<R, E> for F
where
    F: Fn(Result<R, E>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Result<R, E>, bool)> + Send + 'static,
    R: Send + 'static,
    E: Send + Sync + 'static,
{
    async fn retry(&self, result: Result<R, E>) -> (Result<R, E>, bool) {
        self(result).await
    }
}

/// A trait that is used to umbrella-cover all possible
/// implementation kinds for the cloning functionality.
pub trait CloneInput<S>: private::Sealed<(S,)> + Send + Sync + 'static {
    /// Clone the input request if necessary.
    ///
    /// See [`Policy::clone_input`] for more details.
    ///
    /// [`Policy::clone_input`]: super::Policy::clone_input
    fn clone_input(
        &self,
        ctx: &Context<S>,
        req: &Request<RetryBody>,
    ) -> Option<(Context<S>, Request<RetryBody>)>;
}

impl<S> CloneInput<S> for Undefined {
    fn clone_input(
        &self,
        ctx: &Context<S>,
        req: &Request<RetryBody>,
    ) -> Option<(Context<S>, Request<RetryBody>)> {
        Some((ctx.clone(), req.clone()))
    }
}

impl<F, S> CloneInput<S> for F
where
    F: Fn(&Context<S>, &Request<RetryBody>) -> Option<(Context<S>, Request<RetryBody>)>
        + Send
        + Sync
        + 'static,
{
    fn clone_input(
        &self,
        ctx: &Context<S>,
        req: &Request<RetryBody>,
    ) -> Option<(Context<S>, Request<RetryBody>)> {
        self(ctx, req)
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// An type to represent the undefined default type,
/// which is used as the placeholder in the [`ManagedPolicy`],
/// when the user does not provide a specific type.
pub struct Undefined;

impl std::fmt::Display for Undefined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Undefined")
    }
}

impl Backoff for Undefined {
    async fn next_backoff(&self) -> bool {
        true
    }

    async fn reset(&self) {}
}

mod private {
    use super::*;

    pub trait Sealed<S> {}

    impl<S> Sealed<S> for Undefined {}
    impl<F, S> Sealed<(S,)> for F where
        F: Fn(&Context<S>, &Request<RetryBody>) -> Option<(Context<S>, Request<RetryBody>)>
            + Send
            + Sync
            + 'static
    {
    }
    impl<F, Fut, R, E> Sealed<(R, E)> for F
    where
        F: Fn(Result<R, E>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = (Result<R, E>, bool)> + Send + 'static,
    {
    }
}
