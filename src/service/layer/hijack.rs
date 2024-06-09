//! Middleware to hijack request to a [`Service`] which match using a [`Matcher`].
//!
//! Common usecases for hijacking requests are:
//! - Redirecting requests to a different service based on the conditions specified in the [`Matcher`].
//! - Block requests based on the conditions specified in the [`Matcher`] (and thus act like a Firewall).
//!
//! [`Service`]: crate::service::Service
//! [`Matcher`]: crate::service::Matcher

use crate::service::{context::Extensions, Context, Layer, Matcher, Service};

/// Middleware to hijack request to a [`Service`] which match using a [`Matcher`].
///
/// Common usecases for hijacking requests are:
/// - Redirecting requests to a different service based on the conditions specified in the [`Matcher`].
/// - Block requests based on the conditions specified in the [`Matcher`] (and thus act like a Firewall).
///
/// [`Service`]: crate::service::Service
/// [`Matcher`]: crate::service::Matcher
pub struct HijackService<S, H, M> {
    inner: S,
    hijack: H,
    matcher: M,
}

impl<S, H, M> std::fmt::Debug for HijackService<S, H, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HijackService").finish()
    }
}

impl<S, H, M> Clone for HijackService<S, H, M>
where
    S: Clone,
    H: Clone,
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            hijack: self.hijack.clone(),
            matcher: self.matcher.clone(),
        }
    }
}

impl<S, H, M> HijackService<S, H, M> {
    /// Create a new `HijackService`.
    pub fn new(inner: S, hijack: H, matcher: M) -> Self {
        Self {
            inner,
            hijack,
            matcher,
        }
    }

    define_inner_service_accessors!();
}

impl<S, H, M, State, Request> Service<State, Request> for HijackService<S, H, M>
where
    S: Service<State, Request>,
    H: Service<State, Request>,
    <H as Service<State, Request>>::Response: Into<S::Response>,
    <H as Service<State, Request>>::Error: Into<S::Error>,
    M: Matcher<State, Request>,
    State: Send + Sync + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let mut ext = Extensions::new();
        if self.matcher.matches(Some(&mut ext), &ctx, &req) {
            ctx.extend(ext);
            match self.hijack.serve(ctx, req).await {
                Ok(response) => Ok(response.into()),
                Err(err) => Err(err.into()),
            }
        } else {
            self.inner.serve(ctx, req).await
        }
    }
}

/// Middleware to hijack request to a [`Service`] which match using a [`Matcher`].
///
/// Common usecases for hijacking requests are:
/// - Redirecting requests to a different service based on the conditions specified in the [`Matcher`].
/// - Block requests based on the conditions specified in the [`Matcher`] (and thus act like an Http Firewall).
///
/// [`Service`]: crate::service::Service
/// [`Matcher`]: crate::service::Matcher
pub struct HijackLayer<H, M> {
    hijack: H,
    matcher: M,
}

impl<H, M> std::fmt::Debug for HijackLayer<H, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HijackLayer").finish()
    }
}

impl<H, M> Clone for HijackLayer<H, M>
where
    H: Clone,
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            hijack: self.hijack.clone(),
            matcher: self.matcher.clone(),
        }
    }
}

impl<H, M> HijackLayer<H, M> {
    /// Create a new [`HijackLayer`].
    pub fn new(matcher: M, hijack: H) -> Self {
        Self { hijack, matcher }
    }
}

impl<S, H, M> Layer<S> for HijackLayer<H, M>
where
    H: Clone,
    M: Clone,
{
    type Service = HijackService<S, H, M>;

    fn layer(&self, inner: S) -> Self::Service {
        HijackService::new(inner, self.hijack.clone(), self.matcher.clone())
    }
}
