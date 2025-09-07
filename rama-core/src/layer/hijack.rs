//! Middleware to hijack request to a [`Service`] which match using a [`Matcher`].
//!
//! Common usecases for hijacking requests are:
//! - Redirecting requests to a different service based on the conditions specified in the [`Matcher`].
//! - Block requests based on the conditions specified in the [`Matcher`] (and thus act like a Firewall).
//!
//! [`Service`]: crate
//! [`Matcher`]: crate::matcher::Matcher

use crate::{Context, Layer, Service, context::Extensions, matcher::Matcher};
use rama_utils::macros::define_inner_service_accessors;

/// Middleware to hijack request to a [`Service`] which match using a [`Matcher`].
///
/// Common usecases for hijacking requests are:
/// - Redirecting requests to a different service based on the conditions specified in the [`Matcher`].
/// - Block requests based on the conditions specified in the [`Matcher`] (and thus act like a Firewall).
///
/// [`Service`]: crate
/// [`Matcher`]: crate::matcher::Matcher
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
    pub const fn new(inner: S, hijack: H, matcher: M) -> Self {
        Self {
            inner,
            hijack,
            matcher,
        }
    }

    define_inner_service_accessors!();
}

impl<S, H, M, Request> Service<Request> for HijackService<S, H, M>
where
    S: Service<Request>,
    H: Service<Request, Response: Into<S::Response>, Error: Into<S::Error>>,
    M: Matcher<Request>,
    Request: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(&self, mut ctx: Context, req: Request) -> Result<Self::Response, Self::Error> {
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
/// [`Service`]: crate
/// [`Matcher`]: crate::matcher::Matcher
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
    pub const fn new(matcher: M, hijack: H) -> Self {
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

    fn into_layer(self, inner: S) -> Self::Service {
        HijackService::new(inner, self.hijack, self.matcher)
    }
}
