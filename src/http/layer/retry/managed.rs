//! Managed retry [`Policy`].
//!
//! See [`ManagedPolicy`] for more details.
//!
//! [`Policy`]: super::Policy

use super::{Policy, PolicyResult, RetryBody};
use crate::{
    http::Request,
    service::{util::backoff::Backoff, Context},
};
use std::future::Future;

/// A managed retry [`Policy`],
/// which allows for an easier interface to configure retrying requests.
pub struct ManagedPolicy<B, C, R> {
    backoff: B,
    clone: C,
    retry: R,
}

impl<B, C, R, State, Response, Error> Policy<State, Response, Error> for ManagedPolicy<B, C, R>
where
    B: Backoff,
    C: CloneInput<State>,
    R: RetryRule<Error>,
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
        match result {
            Ok(response) => {
                // Treat all `Response`s as success,
                // so deposit budget and don't retry...
                PolicyResult::Abort(Ok(response))
            }
            Err(err) => match self.retry.retry(err).await {
                (err, true) => {
                    if self.backoff.next_backoff().await {
                        // Try again!
                        PolicyResult::Retry { ctx, req }
                    } else {
                        // Don't retry, we've reached the backoff limit.
                        PolicyResult::Abort(Err(err))
                    }
                }
                (err, false) => {
                    // Treat all errors as failures...
                    // But we limit the number of attempts...
                    PolicyResult::Abort(Err(err))
                }
            },
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

impl ManagedPolicy<Undefined, Undefined, Undefined> {
    /// Create a new [`ManagedPolicy`] which retries all requests,
    /// with an unlimited budget, and default cloning.
    pub fn retry_all() -> Self {
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
    /// The default cloning is used and no budget is enforced.
    pub fn retry_when(retry: F) -> Self {
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
pub trait RetryRule<E>: private::Sealed<((), E)> + Send + Sync + 'static {
    /// Check if the given error should be retried,
    /// and return the error if it should be retried.
    fn retry(&self, error: E) -> impl Future<Output = (E, bool)> + Send + '_;
}

impl<E> RetryRule<E> for Undefined
where
    E: std::fmt::Debug + Send + Sync + 'static,
{
    async fn retry(&self, error: E) -> (E, bool) {
        tracing::debug!("retrying error: {:?}", error);
        (error, true)
    }
}

impl<F, Fut, E> RetryRule<E> for F
where
    F: Fn(E) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (E, bool)> + Send + 'static,
    E: Send + Sync + 'static,
{
    async fn retry(&self, error: E) -> (E, bool) {
        self(error).await
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
    impl<F, Fut, E> Sealed<((), E)> for F
    where
        F: Fn(E) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = (E, bool)> + Send + 'static,
    {
    }
}
