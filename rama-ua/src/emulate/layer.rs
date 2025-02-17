use std::fmt;

use rama_core::Layer;

pub struct UserAgentEmulateLayer<P> {
    provider: P,
    optional: bool,
}

impl<P: fmt::Debug> fmt::Debug for UserAgentEmulateLayer<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserAgentEmulateLayer")
            .field("provider", &self.provider)
            .field("optional", &self.optional)
            .finish()
    }
}

impl<P: Clone> Clone for UserAgentEmulateLayer<P> {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider.clone(),
            optional: self.optional,
        }
    }
}

impl<P> UserAgentEmulateLayer<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            optional: false,
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
}

impl<S, P: Clone> Layer<S> for UserAgentEmulateLayer<P> {
    type Service = super::UserAgentEmulateService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        super::UserAgentEmulateService::new(inner, self.provider.clone()).optional(self.optional)
    }
}
