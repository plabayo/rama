use std::{fmt, sync::Arc};

use rama_core::extensions::Extensions;

use crate::headers::{ContentType, HeaderMapExt};
use crate::{
    HeaderMap,
    header::{self, content_type::parse_mime_type},
};

#[derive(Clone)]
pub(crate) enum BodyRewritePolicy {
    /// A response's unencoded type, read as browsers read one.
    UnencodedContentType(fn(&ContentType) -> bool),
    /// A request's unencoded type, its whole value as one type as the extractors judge it.
    UnencodedRequestContentType(fn(&ContentType) -> bool),
    Custom(Arc<dyn Fn(&HeaderMap, &Extensions) -> bool + Send + Sync>),
}

impl fmt::Debug for BodyRewritePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnencodedContentType(_) => f.write_str("UnencodedContentType"),
            Self::UnencodedRequestContentType(_) => f.write_str("UnencodedRequestContentType"),
            Self::Custom(_) => f.write_str("Custom"),
        }
    }
}

impl BodyRewritePolicy {
    pub(crate) const fn unencoded_content_type(predicate: fn(&ContentType) -> bool) -> Self {
        Self::UnencodedContentType(predicate)
    }

    pub(crate) const fn unencoded_request_content_type(
        predicate: fn(&ContentType) -> bool,
    ) -> Self {
        Self::UnencodedRequestContentType(predicate)
    }

    pub(crate) fn custom(
        predicate: impl Fn(&HeaderMap, &Extensions) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self::Custom(Arc::new(predicate))
    }

    pub(crate) fn should_rewrite(&self, headers: &HeaderMap, extensions: &Extensions) -> bool {
        if headers.contains_key(header::CONTENT_ENCODING) {
            return false;
        }

        match self {
            Self::UnencodedContentType(predicate) => headers
                .typed_get::<ContentType>()
                .is_some_and(|ct| predicate(&ct)),
            Self::UnencodedRequestContentType(predicate) => {
                parse_mime_type(headers.get_all(header::CONTENT_TYPE))
                    .is_some_and(|mime| predicate(&ContentType::from(mime)))
            }
            Self::Custom(predicate) => predicate(headers, extensions),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request is rewritten when the extractors would read its type, a response when a
    /// browser would.
    #[test]
    fn request_and_response_types_are_read_as_their_consumers_read_them() {
        fn is_json(content_type: &ContentType) -> bool {
            content_type.mime().subtype() == "json"
        }
        let request = BodyRewritePolicy::unencoded_request_content_type(is_json);
        let response = BodyRewritePolicy::unencoded_content_type(is_json);
        for (lines, rewrite_request, rewrite_response) in [
            (&["application/json"][..], true, true),
            (&["application/json;a=b", "text/plain"], true, false),
            (&["text/plain;,application/json"], false, true),
        ] {
            let mut headers = HeaderMap::new();
            for line in lines {
                headers.append(header::CONTENT_TYPE, line.parse().unwrap());
            }
            let extensions = Extensions::new();
            assert_eq!(
                request.should_rewrite(&headers, &extensions),
                rewrite_request,
                "{lines:?}"
            );
            assert_eq!(
                response.should_rewrite(&headers, &extensions),
                rewrite_response,
                "{lines:?}"
            );
        }
    }

    #[test]
    fn custom_policy_can_accept_any_header_set() {
        let policy =
            BodyRewritePolicy::custom(|headers, _extensions| headers.contains_key("x-rewrite"));
        let mut headers = HeaderMap::new();
        let extensions = Extensions::new();
        assert!(!policy.should_rewrite(&headers, &extensions));
        headers.insert("x-rewrite", "1".parse().unwrap());
        assert!(policy.should_rewrite(&headers, &extensions));
        headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        assert!(!policy.should_rewrite(&headers, &extensions));
    }

    #[test]
    fn custom_policy_can_inspect_extensions() {
        #[derive(Debug)]
        struct RewriteEnabled;

        impl rama_core::extensions::Extension for RewriteEnabled {}

        let policy = BodyRewritePolicy::custom(|_headers, extensions| {
            extensions.get_ref::<RewriteEnabled>().is_some()
        });
        let headers = HeaderMap::new();
        let extensions = Extensions::new();
        assert!(!policy.should_rewrite(&headers, &extensions));
        extensions.insert(RewriteEnabled);
        assert!(policy.should_rewrite(&headers, &extensions));
    }
}
