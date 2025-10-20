use super::{UriMatchError, UriMatchReplace};
use rama_core::error::ErrorContext as _;
use rama_http_types::{Scheme, Uri};
use std::borrow::Cow;

#[derive(Debug, Clone)]
/// Replace or overwrite the existing [`Scheme`].
pub struct UriMatchReplaceScheme {
    condition: Option<Scheme>,
    overwrite: Scheme,
}

impl UriMatchReplaceScheme {
    #[must_use]
    pub fn set_always(scheme: Scheme) -> Self {
        Self {
            condition: None,
            overwrite: scheme,
        }
    }

    #[must_use]
    pub fn replace(old: Scheme, new: Scheme) -> Self {
        Self {
            condition: Some(old),
            overwrite: new,
        }
    }

    #[must_use]
    pub fn http_to_https() -> Self {
        Self::replace(Scheme::HTTP, Scheme::HTTPS)
    }
}

impl UriMatchReplace for UriMatchReplaceScheme {
    fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
        if (self.condition.is_none() && uri.authority().is_some())
            || uri.scheme() == self.condition.as_ref()
        {
            let mut uri_parts = uri.into_owned().into_parts();
            uri_parts.scheme = Some(self.overwrite.clone());
            Uri::from_parts(uri_parts)
                .context("re-create uri with scheme overwrite")
                .map_err(UriMatchError::Unexpected)
                .map(Cow::Owned)
        } else {
            Err(UriMatchError::NoMatch(uri))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_uri_match(
        matcher: &UriMatchReplaceScheme,
        input_uri: &'static str,
        expected: &'static str,
    ) {
        let expected_uri = Uri::from_static(expected);
        match matcher.match_replace_uri(Cow::Owned(Uri::from_static(input_uri))) {
            Ok(uri) => assert_eq!(
                uri.as_ref(),
                &expected_uri,
                "input uri: {input_uri}; matcher: {matcher:?}"
            ),
            Err(err) => {
                panic!("unexpected error: {err}; input uri: {input_uri}; matcher: {matcher:?}")
            }
        }
    }

    #[test]
    fn test_scheme_match() {
        for (input, expected_output) in [
            ("http://example.com", "https://example.com"),
            ("http://example:8080.com", "https://example:8080.com"),
            ("http://example.com/bar?q=v", "https://example.com/bar?q=v"),
            (
                "http://example.com:8080/bar?q=v",
                "https://example.com:8080/bar?q=v",
            ),
        ] {
            let matcher = UriMatchReplaceScheme::http_to_https();
            expect_uri_match(&matcher, input, expected_output);
        }
    }

    fn expect_uri_no_match(matcher: &UriMatchReplaceScheme, input_uri: &'static str) {
        let uri = Cow::Owned(Uri::from_static(input_uri));
        match matcher.match_replace_uri(uri) {
            Ok(found) => panic!("unexpected match for uri {input_uri}: {found}"),
            Err(UriMatchError::NoMatch(_)) => (), // good
            Err(UriMatchError::Unexpected(err)) => {
                panic!("unexpected match error for uri {input_uri}: {err}")
            }
        }
    }

    #[test]
    fn test_scheme_no_match() {
        for (matcher, input_uri) in [
            (
                UriMatchReplaceScheme::http_to_https(),
                "https://example.com",
            ),
            (UriMatchReplaceScheme::http_to_https(), "ftp://example.com"),
            (
                UriMatchReplaceScheme::http_to_https(),
                "https://example.com?q=v",
            ),
            (
                UriMatchReplaceScheme::http_to_https(),
                "ftp://example.com?q=v",
            ),
            (
                UriMatchReplaceScheme::http_to_https(),
                "https://example.com:8080",
            ),
            (
                UriMatchReplaceScheme::http_to_https(),
                "ftp://example.com:8080",
            ),
        ] {
            expect_uri_no_match(&matcher, input_uri);
        }
    }
}
