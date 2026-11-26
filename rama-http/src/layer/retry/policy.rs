use super::{RetryBody, storage::ReplayStore};
use crate::{
    Request,
    body::{CollectOptions, SizeHint},
    request::Parts,
};

/// A "retry policy" to classify if a request should be retried.
///
/// [`ManagedPolicy`](super::ManagedPolicy) implements this trait from plain
/// functions. A custom policy that keeps the defaults returns
/// [`MemoryReplay::DEFAULT`](super::storage::MemoryReplay::DEFAULT) from
/// [`Self::replay_store`] and `true` from [`Self::next_attempt`].
pub trait Policy<R, E>: Send + Sync + 'static {
    /// Decide whether to prepare a replay before polling the request body.
    ///
    /// `None` streams the request once, without cloning it or calling `retry`.
    /// These options can tighten the selected store's byte limit and timeout.
    /// Exceeding a limit disables retries while the first upload continues.
    ///
    /// `is_end_stream` is the body's own assertion that no frames remain.
    /// A zero size hint alone does not exclude trailers. Each policy explicitly
    /// chooses whether collection is allowed and which limits apply.
    fn prepare_body(
        &self,
        parts: &Parts,
        is_end_stream: bool,
        size_hint: &SizeHint,
    ) -> Option<CollectOptions>;

    /// Select storage for an approved, nonempty body before it is first polled.
    ///
    /// A store can be selected using request metadata.
    /// [`MemoryReplay::DEFAULT`](super::storage::MemoryReplay::DEFAULT)
    /// keeps up to 64 KiB in memory with a 30-second deadline.
    fn replay_store(&self, parts: &Parts) -> &dyn ReplayStore;

    /// Classify the result of an attempt and optionally prepare the next request.
    ///
    /// Returning [`PolicyResult::Abort`] forwards the result immediately.
    /// Returning [`PolicyResult::Retry`] asks the middleware to finish any
    /// outstanding capture before issuing the next request. Supply the current
    /// result as the fallback if the body cannot be recovered. Reading the
    /// candidate body inside this method also requests that capture be finished.
    /// While the first attempt's reader is still alive, finishing waits up to
    /// the store's [`handoff_timeout`](super::storage::ReplayStore::handoff_timeout)
    /// for that reader to be dropped or to reach the end of the upload.
    ///
    /// ## Mutating Requests
    ///
    /// The policy MAY chose to mutate the `req`: if the request is mutated, the
    /// mutated request will be sent to the inner service in the next retry.
    /// This can be helpful for use cases like tracking the retry count in a
    /// header. Mutate the handed-in request *in place* — its
    /// [`Extensions`](rama_core::extensions::Extensions) are the caller's
    /// store, so recorded metadata both reaches the next attempt and stays
    /// visible to the caller after the call. Returning a freshly built request
    /// instead keeps its body and headers but not its extensions: each attempt
    /// is re-forked from the caller's store (see the
    /// [module docs](crate::layer::retry)).
    ///
    /// ## Mutating Results
    ///
    /// The policy MAY chose to mutate the result. This enables the retry
    /// policy to convert a failure into a success and vice versa. For example,
    /// if the policy is used to poll while waiting for a state change, the
    /// policy can switch the result to emit a specific error when retries are
    /// exhausted.
    ///
    /// As above, record such metadata on the handed-in request (e.g. the
    /// number of retries required, or that a failure exhausted all retries).
    ///
    /// [`Service::Output`]: rama_core::Service::Output
    /// [`Service::Error`]: rama_core::Service::Error
    fn retry(
        &self,

        req: Request<RetryBody>,
        result: Result<R, E>,
    ) -> impl Future<Output = PolicyResult<R, E>> + Send + '_;

    /// Apply the retry delay or attempt budget after a complete body is ready.
    ///
    /// Return `false` to return the candidate outcome to the caller. Keeping
    /// backoff here allows a pending upload to finish before a delay begins.
    fn next_attempt(&self) -> impl Future<Output = bool> + Send + '_;

    /// Tries to clone a request before being passed to the inner service.
    ///
    /// Return [`None`] to skip retry classification and abandon capture. Use
    /// [`RetryBody::try_clone`] to retain a candidate while a streamed upload
    /// is still being captured. Capture can later exceed its limits.
    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>>;
}

impl<P, R, E> Policy<R, E> for &'static P
where
    P: Policy<R, E>,
{
    fn prepare_body(
        &self,
        parts: &Parts,
        is_end_stream: bool,
        size_hint: &SizeHint,
    ) -> Option<CollectOptions> {
        (**self).prepare_body(parts, is_end_stream, size_hint)
    }

    fn replay_store(&self, parts: &Parts) -> &dyn ReplayStore {
        (**self).replay_store(parts)
    }

    #[inline(always)]
    fn retry(
        &self,
        req: Request<RetryBody>,
        result: Result<R, E>,
    ) -> impl Future<Output = PolicyResult<R, E>> + Send + '_ {
        (**self).retry(req, result)
    }

    #[inline(always)]
    fn next_attempt(&self) -> impl Future<Output = bool> + Send + '_ {
        (**self).next_attempt()
    }

    #[inline(always)]
    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
        (**self).clone_input(req)
    }
}

impl<P, R, E> Policy<R, E> for std::sync::Arc<P>
where
    P: Policy<R, E>,
{
    fn prepare_body(
        &self,
        parts: &Parts,
        is_end_stream: bool,
        size_hint: &SizeHint,
    ) -> Option<CollectOptions> {
        (**self).prepare_body(parts, is_end_stream, size_hint)
    }

    fn replay_store(&self, parts: &Parts) -> &dyn ReplayStore {
        (**self).replay_store(parts)
    }

    #[inline(always)]
    fn retry(
        &self,

        req: Request<RetryBody>,
        result: Result<R, E>,
    ) -> impl Future<Output = PolicyResult<R, E>> + Send + '_ {
        (**self).retry(req, result)
    }

    #[inline(always)]
    fn next_attempt(&self) -> impl Future<Output = bool> + Send + '_ {
        (**self).next_attempt()
    }

    #[inline(always)]
    fn clone_input(&self, req: &Request<RetryBody>) -> Option<Request<RetryBody>> {
        (**self).clone_input(req)
    }
}

/// A retry decision and the result to forward if no further attempt is made.
#[expect(
    clippy::large_enum_variant,
    reason = "keep the retry request inline instead of allocating on every retry"
)]
pub enum PolicyResult<R, E> {
    /// The result should not be retried,
    /// and the result should be returned to the caller.
    Abort(Result<R, E>),
    /// Request another attempt once capture and the policy's delay or budget allow it.
    Retry {
        /// The request for the next attempt.
        req: Request<RetryBody>,
        /// Return this result if capture fails or [`Policy::next_attempt`] declines.
        result: Result<R, E>,
    },
}

impl<R, E> std::fmt::Debug for PolicyResult<R, E>
where
    R: std::fmt::Debug,
    E: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Abort(err) => write!(f, "PolicyResult::Abort({err:?})"),
            Self::Retry { req, result } => {
                write!(
                    f,
                    "PolicyResult::Retry {{ req: {req:?}, result: {result:?} }}"
                )
            }
        }
    }
}

macro_rules! impl_retry_policy_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+, Response, Error> Policy< Response, Error> for rama_core::combinators::$id<$($param),+>
        where
            $($param: Policy< Response, Error>),+,

            Response: Send + 'static,
            Error: Send + 'static,
        {
            fn prepare_body(
                &self,
                parts: &Parts,
                is_end_stream: bool,
                size_hint: &SizeHint,
            ) -> Option<CollectOptions> {
                match self {
                    $(rama_core::combinators::$id::$param(policy) => policy.prepare_body(parts, is_end_stream, size_hint),)+
                }
            }

            fn replay_store(&self, parts: &Parts) -> &dyn ReplayStore {
                match self {
                    $(rama_core::combinators::$id::$param(policy) => policy.replay_store(parts),)+
                }
            }

            async fn retry(
                &self,
                req: rama_http_types::Request<RetryBody>,
                result: Result<Response, Error>,
            ) -> PolicyResult< Response, Error> {
                match self {
                    $(
                        rama_core::combinators::$id::$param(policy) => policy.retry(req, result).await,
                    )+
                }
            }

            async fn next_attempt(&self) -> bool {
                match self {
                    $(rama_core::combinators::$id::$param(policy) => policy.next_attempt().await,)+
                }
            }

            fn clone_input(
                &self,
                req: &rama_http_types::Request<RetryBody>,
            ) -> Option<rama_http_types::Request<RetryBody>> {
                match self {
                    $(
                        rama_core::combinators::$id::$param(policy) => policy.clone_input(req),
                    )+
                }
            }
        }
    };
}

rama_core::combinators::impl_either!(impl_retry_policy_either);
