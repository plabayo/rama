use std::fmt;

use rama_core::Layer;

use super::UserAgentSelectFallback;

pub struct UserAgentEmulateLayer<P> {
    provider: P,
    optional: bool,
    select_fallback: Option<UserAgentSelectFallback>,
}

impl<P: fmt::Debug> fmt::Debug for UserAgentEmulateLayer<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserAgentEmulateLayer")
            .field("provider", &self.provider)
            .field("optional", &self.optional)
            .field("select_fallback", &self.select_fallback)
            .finish()
    }
}

impl<P: Clone> Clone for UserAgentEmulateLayer<P> {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider.clone(),
            optional: self.optional,
            select_fallback: self.select_fallback,
        }
    }
}

impl<P> UserAgentEmulateLayer<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            optional: false,
            select_fallback: None,
        }
    }

    /// When no user agent profile was found it will
    /// fail the request unless optional is true. In case of
    /// the latter the service will do nothing.
    pub fn optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    /// See [`Self::optional`].
    pub fn set_optional(&mut self, optional: bool) -> &mut Self {
        self.optional = optional;
        self
    }

    /// Choose what to do in case no profile could be selected
    /// using the regular pre-conditions as specified by the provider.
    pub fn select_fallback(mut self, fb: UserAgentSelectFallback) -> Self {
        self.select_fallback = Some(fb);
        self
    }

    /// See [`Self::select_fallback`].
    pub fn set_select_fallback(&mut self, fb: UserAgentSelectFallback) -> &mut Self {
        self.select_fallback = Some(fb);
        self
    }
}

impl<S, P: Clone> Layer<S> for UserAgentEmulateLayer<P> {
    type Service = super::UserAgentEmulateService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        let mut svc = super::UserAgentEmulateService::new(inner, self.provider.clone())
            .optional(self.optional);
        if let Some(fb) = self.select_fallback {
            svc.set_select_fallback(fb);
        }
        svc
    }
}
