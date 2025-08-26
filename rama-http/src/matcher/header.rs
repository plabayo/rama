use crate::{HeaderName, HeaderValue, Request};
use rama_core::{Context, context::Extensions, matcher::Matcher};

#[derive(Debug, Clone)]
/// Matcher based on the [`Request`]'s headers.
///
/// [`Request`]: crate::Request
pub struct HeaderMatcher {
    name: HeaderName,
    kind: HeaderMatcherKind,
}

#[derive(Debug, Clone)]
enum HeaderMatcherKind {
    Exists,
    Is(HeaderValue),
    Contains(HeaderValue),
}

impl HeaderMatcher {
    /// Create a new header matcher to match on the existence of a header.
    pub fn exists(name: HeaderName) -> Self {
        Self {
            name,
            kind: HeaderMatcherKind::Exists,
        }
    }

    /// Create a new header matcher to match on an exact header value match.
    pub fn is(name: HeaderName, value: HeaderValue) -> Self {
        Self {
            name,
            kind: HeaderMatcherKind::Is(value),
        }
    }

    /// Create a new header matcher to match that the header contains the given value.
    pub fn contains(name: HeaderName, value: HeaderValue) -> Self {
        Self {
            name,
            kind: HeaderMatcherKind::Contains(value),
        }
    }
}

impl<Body> Matcher<Request<Body>> for HeaderMatcher {
    fn matches(&self, _ext: Option<&mut Extensions>, _ctx: &Context, req: &Request<Body>) -> bool {
        let headers = req.headers();
        match self.kind {
            HeaderMatcherKind::Exists => headers.contains_key(&self.name),
            HeaderMatcherKind::Is(ref value) => headers.get(&self.name) == Some(value),
            HeaderMatcherKind::Contains(ref value) => {
                headers.get_all(&self.name).iter().any(|v| v == value)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_header_matcher_exists() {
        let matcher = HeaderMatcher::exists("content-type".parse().unwrap());
        let req = Request::builder()
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        assert!(matcher.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_matcher_exists_no_match() {
        let matcher = HeaderMatcher::exists("content-type".parse().unwrap());
        let req = Request::builder().body(()).unwrap();
        assert!(!matcher.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_matcher_is() {
        let matcher = HeaderMatcher::is(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        assert!(matcher.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_matcher_is_no_match() {
        let matcher = HeaderMatcher::is(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/html")
            .body(())
            .unwrap();
        assert!(!matcher.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_matcher_contains() {
        let matcher = HeaderMatcher::contains(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        assert!(matcher.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_matcher_contains_no_match() {
        let matcher = HeaderMatcher::contains(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/html")
            .body(())
            .unwrap();
        assert!(!matcher.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_matcher_contains_multiple() {
        let matcher = HeaderMatcher::contains(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/html")
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        assert!(matcher.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_matcher_contains_multiple_no_match() {
        let matcher = HeaderMatcher::contains(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/html")
            .header("content-type", "text/xml")
            .body(())
            .unwrap();
        assert!(!matcher.matches(None, &Context::default(), &req));
    }
}
