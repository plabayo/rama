use std::sync::Arc;

use crate::headers::{ContentType, HeaderMapExt};
use crate::{HeaderMap, header};

#[derive(Clone)]
pub(crate) enum BodyRewritePolicy {
    UnencodedContentType(fn(&ContentType) -> bool),
    Custom(Arc<dyn Fn(&HeaderMap) -> bool + Send + Sync>),
}

impl BodyRewritePolicy {
    pub(crate) const fn unencoded_content_type(predicate: fn(&ContentType) -> bool) -> Self {
        Self::UnencodedContentType(predicate)
    }

    pub(crate) fn custom(predicate: impl Fn(&HeaderMap) -> bool + Send + Sync + 'static) -> Self {
        Self::Custom(Arc::new(predicate))
    }

    pub(crate) fn should_rewrite(&self, headers: &HeaderMap) -> bool {
        match self {
            Self::UnencodedContentType(predicate) => {
                !headers.contains_key(header::CONTENT_ENCODING)
                    && headers
                        .typed_get::<ContentType>()
                        .is_some_and(|ct| predicate(&ct))
            }
            Self::Custom(predicate) => predicate(headers),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_policy_can_accept_any_header_set() {
        let policy = BodyRewritePolicy::custom(|headers| headers.contains_key("x-rewrite"));
        let mut headers = HeaderMap::new();
        assert!(!policy.should_rewrite(&headers));
        headers.insert("x-rewrite", "1".parse().unwrap());
        assert!(policy.should_rewrite(&headers));
    }
}
