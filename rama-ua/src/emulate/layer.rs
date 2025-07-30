use std::fmt;

use rama_core::Layer;
use rama_http_types::HeaderName;

use super::UserAgentSelectFallback;

/// A layer that emulates a user agent profile.
///
/// See [`UserAgentEmulateService`] for more details.
///
/// This layer is used to emulate a user agent profile for a request.
/// It makes use of a [`UserAgentProvider`] (`P`) to select a user agent profile.
///
/// [`UserAgentProvider`]: crate::emulate::UserAgentProvider
/// [`UserAgentEmulateService`]: crate::emulate::UserAgentEmulateService
pub struct UserAgentEmulateLayer<P> {
    provider: P,
    optional: bool,
    try_auto_detect_user_agent: bool,
    input_header_order: Option<HeaderName>,
    select_fallback: Option<UserAgentSelectFallback>,
}

impl<P: fmt::Debug> fmt::Debug for UserAgentEmulateLayer<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserAgentEmulateLayer")
            .field("provider", &self.provider)
            .field("optional", &self.optional)
            .field(
                "try_auto_detect_user_agent",
                &self.try_auto_detect_user_agent,
            )
            .field("input_header_order", &self.input_header_order)
            .field("select_fallback", &self.select_fallback)
            .finish()
    }
}

impl<P: Clone> Clone for UserAgentEmulateLayer<P> {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider.clone(),
            optional: self.optional,
            try_auto_detect_user_agent: self.try_auto_detect_user_agent,
            input_header_order: self.input_header_order.clone(),
            select_fallback: self.select_fallback,
        }
    }
}

impl<P> UserAgentEmulateLayer<P> {
    /// Create a new [`UserAgentEmulateLayer`] with the given provider.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            optional: false,
            try_auto_detect_user_agent: false,
            input_header_order: None,
            select_fallback: None,
        }
    }

    /// When no user agent profile was found it will
    /// fail the request unless optional is true. In case of
    /// the latter the service will do nothing.
    #[must_use]
    pub fn optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    /// See [`Self::optional`].
    pub fn set_optional(&mut self, optional: bool) -> &mut Self {
        self.optional = optional;
        self
    }

    /// If true, the layer will try to auto-detect the user agent from the request,
    /// but only in case that info is not yet found in the context.
    #[must_use]
    pub fn try_auto_detect_user_agent(mut self, try_auto_detect_user_agent: bool) -> Self {
        self.try_auto_detect_user_agent = try_auto_detect_user_agent;
        self
    }

    /// See [`Self::try_auto_detect_user_agent`].
    pub fn set_try_auto_detect_user_agent(
        &mut self,
        try_auto_detect_user_agent: bool,
    ) -> &mut Self {
        self.try_auto_detect_user_agent = try_auto_detect_user_agent;
        self
    }

    /// Define a header that if present is to contain a CSV header name list,
    /// that allows you to define the desired header order for the (extra) headers
    /// found in the input (http) request.
    ///
    /// Extra meaning any headers not considered a base header and already defined
    /// by the (selected) User Agent Profile.
    ///
    /// This can be useful because your http client might not respect the header casing
    /// and/or order of the headers taken together. Using this metadata allows you to
    /// communicate this data through anyway. If however your http client does respect
    /// casing and order, or you don't care about some of it, you might not need it.
    #[must_use]
    pub fn input_header_order(mut self, name: HeaderName) -> Self {
        self.input_header_order = Some(name);
        self
    }

    /// See [`Self::input_header_order`].
    pub fn set_input_header_order(&mut self, name: HeaderName) -> &mut Self {
        self.input_header_order = Some(name);
        self
    }

    /// Choose what to do in case no profile could be selected
    /// using the regular pre-conditions as specified by the provider.
    #[must_use]
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
            .optional(self.optional)
            .try_auto_detect_user_agent(self.try_auto_detect_user_agent);
        if let Some(fb) = self.select_fallback {
            svc.set_select_fallback(fb);
        }
        if let Some(name) = self.input_header_order.clone() {
            svc.set_input_header_order(name);
        }
        svc
    }

    fn into_layer(self, inner: S) -> Self::Service {
        let mut svc = super::UserAgentEmulateService::new(inner, self.provider)
            .optional(self.optional)
            .try_auto_detect_user_agent(self.try_auto_detect_user_agent);
        if let Some(fb) = self.select_fallback {
            svc.set_select_fallback(fb);
        }
        if let Some(name) = self.input_header_order {
            svc.set_input_header_order(name);
        }
        svc
    }
}
