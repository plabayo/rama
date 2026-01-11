use rama_core::Layer;
use rama_http::HeaderName;

use super::UserAgentSelectFallback;

/// A layer that emulates a user agent profile.
///
/// See [`UserAgentEmulateService`] for more details.
///
/// This layer is used to emulate a user agent profile for a request.
/// It makes use of a [`UserAgentProvider`] (`P`) to select a user agent profile.
///
/// [`UserAgentProvider`]: crate::layer::emulate::UserAgentProvider
/// [`UserAgentEmulateService`]: crate::layer::emulate::UserAgentEmulateService
#[derive(Debug, Clone)]
pub struct UserAgentEmulateLayer<P> {
    provider: P,
    optional: bool,
    try_auto_detect_user_agent: bool,
    input_header_order: Option<HeaderName>,
    select_fallback: Option<UserAgentSelectFallback>,
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

    rama_utils::macros::generate_set_and_with! {
        /// When no user agent profile was found it will
        /// fail the request unless optional is true. In case of
        /// the latter the service will do nothing.
        pub fn is_optional(mut self, optional: bool) -> Self {
            self.optional = optional;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// If true, the layer will try to auto-detect the user agent from the request,
        /// but only in case that info is not yet found in the context.
        pub fn try_auto_detect_user_agent(mut self, try_auto_detect_user_agent: bool) -> Self {
            self.try_auto_detect_user_agent = try_auto_detect_user_agent;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
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
        pub fn input_header_order(mut self, name: Option<HeaderName>) -> Self {
            self.input_header_order = name;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Choose what to do in case no profile could be selected
        /// using the regular pre-conditions as specified by the provider.
        pub fn select_fallback(mut self, fb: Option<UserAgentSelectFallback>) -> Self {
            self.select_fallback = fb;
            self
        }
    }
}

impl<S, P: Clone> Layer<S> for UserAgentEmulateLayer<P> {
    type Service = super::UserAgentEmulateService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        super::UserAgentEmulateService::new(inner, self.provider.clone())
            .with_is_optional(self.optional)
            .with_try_auto_detect_user_agent(self.try_auto_detect_user_agent)
            .maybe_with_select_fallback(self.select_fallback)
            .maybe_with_input_header_order(self.input_header_order.clone())
    }

    fn into_layer(self, inner: S) -> Self::Service {
        super::UserAgentEmulateService::new(inner, self.provider)
            .with_is_optional(self.optional)
            .with_try_auto_detect_user_agent(self.try_auto_detect_user_agent)
            .maybe_with_select_fallback(self.select_fallback)
            .maybe_with_input_header_order(self.input_header_order)
    }
}
