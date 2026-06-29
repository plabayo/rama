use std::{fmt, sync::Arc};

use rama_core::extensions::Extensions;

use crate::headers::{ContentType, HeaderMapExt};
use crate::{HeaderMap, header};

#[derive(Clone)]
pub(crate) enum BodyRewritePolicy {
    UnencodedContentType(fn(&ContentType) -> bool),
    Custom(Arc<dyn Fn(&HeaderMap, &Extensions) -> bool + Send + Sync>),
}

impl fmt::Debug for BodyRewritePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnencodedContentType(_) => f.write_str("UnencodedContentType"),
            Self::Custom(_) => f.write_str("Custom"),
        }
    }
}

impl BodyRewritePolicy {
    pub(crate) const fn unencoded_content_type(predicate: fn(&ContentType) -> bool) -> Self {
        Self::UnencodedContentType(predicate)
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
            Self::Custom(predicate) => predicate(headers, extensions),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
