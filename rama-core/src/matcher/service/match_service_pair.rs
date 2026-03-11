use std::convert::Infallible;

use crate::{
    extensions::{Extensions, ExtensionsMut},
    matcher::Matcher,
};

use super::{ServiceMatch, ServiceMatcher};

/// Couples a plain [`crate::matcher::Matcher`] with a concrete service.
///
/// This wrapper exists because `(M, S)` cannot be implemented directly
/// without overlapping the tuple-based `ServiceMatcher` chain impls.
pub struct MatcherServicePair<M, S>(pub M, pub S);

impl<M, S> MatcherServicePair<M, S> {
    /// Create a new matcher-service pair.
    #[inline]
    pub fn new(matcher: M, service: S) -> Self {
        Self(matcher, service)
    }
}

impl<M, S> From<(M, S)> for MatcherServicePair<M, S> {
    fn from(value: (M, S)) -> Self {
        Self(value.0, value.1)
    }
}

impl<Input, M, S> ServiceMatcher<Input> for MatcherServicePair<M, S>
where
    Input: Send + ExtensionsMut + 'static,
    S: Send + Sync + Clone + 'static,
    M: Matcher<Input>,
{
    type Service = S;
    type Error = Infallible;

    async fn match_service(
        &self,
        mut input: Input,
    ) -> Result<ServiceMatch<Input, Self::Service>, Self::Error> {
        let MatcherServicePair(matcher, service) = self;
        let mut ext = Extensions::new();
        if matcher.matches(Some(&mut ext), &input) {
            input.extensions_mut().extend(ext);
            Ok(ServiceMatch {
                input,
                service: Some(service.clone()),
            })
        } else {
            Ok(ServiceMatch {
                input,
                service: None,
            })
        }
    }

    async fn into_match_service(
        self,
        mut input: Input,
    ) -> Result<ServiceMatch<Input, Self::Service>, Self::Error>
    where
        Input: Send,
    {
        let MatcherServicePair(matcher, service) = self;
        let mut ext = Extensions::new();
        if matcher.matches(Some(&mut ext), &input) {
            input.extensions_mut().extend(ext);
            Ok(ServiceMatch {
                input,
                service: Some(service),
            })
        } else {
            Ok(ServiceMatch {
                input,
                service: None,
            })
        }
    }
}
