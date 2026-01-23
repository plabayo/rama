//! Middleware to hijack an input to a [`Service`] which match using a [`Matcher`].
//!
//! Common usecases for hijacking inputs are:
//! - Redirecting inputs to a different service based on the conditions specified in the [`Matcher`].
//! - Block inputs based on the conditions specified in the [`Matcher`] (and thus act like a Firewall).
//!
//! [`Service`]: crate
//! [`Matcher`]: crate::matcher::Matcher

use crate::{Layer, Service, extensions::Extensions, extensions::ExtensionsMut, matcher::Matcher};
use rama_utils::macros::define_inner_service_accessors;

/// Middleware to hijack inputs to a [`Service`] which match using a [`Matcher`].
///
/// Common usecases for hijacking inputs are:
/// - Redirecting inputs to a different service based on the conditions specified in the [`Matcher`].
/// - Block inputs based on the conditions specified in the [`Matcher`] (and thus act like a Firewall).
///
/// [`Service`]: crate
/// [`Matcher`]: crate::matcher::Matcher
#[derive(Debug, Clone)]
pub struct HijackService<S, H, M> {
    inner: S,
    hijack: H,
    matcher: M,
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

impl<S, H, M, Input> Service<Input> for HijackService<S, H, M>
where
    S: Service<Input>,
    H: Service<Input, Output: Into<S::Output>, Error: Into<S::Error>>,
    M: Matcher<Input>,
    Input: Send + ExtensionsMut + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        let mut ext = Extensions::new();
        if self.matcher.matches(Some(&mut ext), &input) {
            input.extensions_mut().extend(ext);
            match self.hijack.serve(input).await {
                Ok(response) => Ok(response.into()),
                Err(err) => Err(err.into()),
            }
        } else {
            self.inner.serve(input).await
        }
    }
}

/// Middleware to hijack an inputs to a [`Service`] which match using a [`Matcher`].
///
/// Common usecases for hijacking inputs are:
/// - Redirecting inputs to a different service based on the conditions specified in the [`Matcher`].
/// - Block inputs based on the conditions specified in the [`Matcher`] (and thus act like an Http Firewall).
///
/// [`Service`]: crate
/// [`Matcher`]: crate::matcher::Matcher
#[derive(Debug, Clone)]
pub struct HijackLayer<H, M> {
    hijack: H,
    matcher: M,
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
