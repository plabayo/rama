use crate::{
    http::{HeaderName, HeaderValue, Request},
    service::{context::Extensions, Context, Matcher},
};

#[derive(Debug, Clone)]
/// Filter based on the [`Request`]'s headers.
///
/// [`Request`]: crate::http::Request
pub struct HeaderFilter {
    name: HeaderName,
    kind: HeaderFilterKind,
}

#[derive(Debug, Clone)]
enum HeaderFilterKind {
    Exists,
    Is(HeaderValue),
    Contains(HeaderValue),
}

impl HeaderFilter {
    /// Create a new header filter to filter on the existence of a header.
    pub fn exists(name: HeaderName) -> Self {
        Self {
            name,
            kind: HeaderFilterKind::Exists,
        }
    }

    /// Create a new header filter to filter on an exact header value match.
    pub fn is(name: HeaderName, value: HeaderValue) -> Self {
        Self {
            name,
            kind: HeaderFilterKind::Is(value),
        }
    }

    /// Create a new header filter to filter that the header contains the given value.
    pub fn contains(name: HeaderName, value: HeaderValue) -> Self {
        Self {
            name,
            kind: HeaderFilterKind::Contains(value),
        }
    }
}

impl<State, Body> Matcher<State, Request<Body>> for HeaderFilter {
    fn matches(
        &self,
        _ext: Option<&mut Extensions>,
        _ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        let headers = req.headers();
        match self.kind {
            HeaderFilterKind::Exists => headers.contains_key(&self.name),
            HeaderFilterKind::Is(ref value) => headers.get(&self.name) == Some(value),
            HeaderFilterKind::Contains(ref value) => {
                headers.get_all(&self.name).iter().any(|v| v == value)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_header_filter_exists() {
        let filter = HeaderFilter::exists("content-type".parse().unwrap());
        let req = Request::builder()
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        assert!(filter.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_filter_exists_no_match() {
        let filter = HeaderFilter::exists("content-type".parse().unwrap());
        let req = Request::builder().body(()).unwrap();
        assert!(!filter.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_filter_is() {
        let filter = HeaderFilter::is(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        assert!(filter.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_filter_is_no_match() {
        let filter = HeaderFilter::is(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/html")
            .body(())
            .unwrap();
        assert!(!filter.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_filter_contains() {
        let filter = HeaderFilter::contains(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        assert!(filter.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_filter_contains_no_match() {
        let filter = HeaderFilter::contains(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/html")
            .body(())
            .unwrap();
        assert!(!filter.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_filter_contains_multiple() {
        let filter = HeaderFilter::contains(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/html")
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        assert!(filter.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_header_filter_contains_multiple_no_match() {
        let filter = HeaderFilter::contains(
            "content-type".parse().unwrap(),
            "text/plain".parse().unwrap(),
        );
        let req = Request::builder()
            .header("content-type", "text/html")
            .header("content-type", "text/xml")
            .body(())
            .unwrap();
        assert!(!filter.matches(None, &Context::default(), &req));
    }
}
