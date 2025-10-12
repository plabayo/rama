//! provides a [`UriMatcher`] matcher for matching requests based on their URI.

use crate::{Request, Uri};
use rama_core::extensions::Extensions;
use rama_utils::thirdparty::{regex::Regex, wildcard::Wildcard};

#[derive(Debug, Clone)]
/// Matcher the request's URI, using a substring or regex pattern.
pub struct UriMatcher {
    engine: Engine,
}

#[derive(Debug, Clone)]
enum Engine {
    Re(Regex),
    Wc(Wildcard<'static>),
}

impl Engine {
    fn is_match(&self, s: &str) -> bool {
        match self {
            Self::Re(regex) => regex.is_match(s),
            Self::Wc(wildcard) => wildcard.is_match(s.as_bytes()),
        }
    }
}

impl UriMatcher {
    #[must_use]
    /// create a new Uri matcher using a regex pattern.
    pub fn regex(re: Regex) -> Self {
        Self {
            engine: Engine::Re(re),
        }
    }

    #[must_use]
    /// create a new Uri matcher using a wildcard pattern.
    pub fn wildcard(wc: Wildcard<'static>) -> Self {
        Self {
            engine: Engine::Wc(wc),
        }
    }

    #[inline]
    pub(crate) fn matches_uri(&self, uri: &Uri) -> bool {
        match uri.authority() {
            Some(authority) => {
                let s = smol_str::format_smolstr!(
                    "{}://{authority}{}",
                    uri.scheme_str().unwrap_or("http"),
                    uri.path()
                );
                self.engine.is_match(s.trim_end_matches('/'))
            }
            None => self.engine.is_match(uri.path()),
        }
    }
}

impl From<Regex> for UriMatcher {
    fn from(re: Regex) -> Self {
        Self {
            engine: Engine::Re(re),
        }
    }
}

impl From<Wildcard<'static>> for UriMatcher {
    fn from(wc: Wildcard<'static>) -> Self {
        Self {
            engine: Engine::Wc(wc),
        }
    }
}

impl<Body> rama_core::matcher::Matcher<Request<Body>> for UriMatcher {
    fn matches(&self, _ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        let uri = crate::utils::request_uri(req);
        // TODO: in future we probably do not want to go via request_uri,
        // as this allocates an entire uri even though we do not want query etc...
        self.matches_uri(uri.as_ref())
    }
}

#[cfg(test)]
mod test {
    use crate::header::HOST;
    use rama_core::matcher::Matcher as _;

    use super::*;

    #[test]
    fn matchest_uri_regex_match() {
        for (matcher, uri) in [
            (r"www\.example\.com", "http://www.example.com"),
            (r"(?i)www\.example\.com", "http://WwW.ExamplE.COM"),
            (
                r"(?i)^[^?]+\.(jpeg|png|gif|css)$",
                "http://www.example.com/assets/style.css?foo=bar",
            ),
            (
                r"(?i)^[^?]+\.(jpeg|png|gif|css)$",
                "http://www.example.com/image.png",
            ),
        ] {
            let matcher = UriMatcher::regex(Regex::new(matcher).unwrap());
            assert!(
                matcher.matches_uri(&(uri.parse().unwrap())),
                "({matcher:?}).matches_uri({uri})",
            );
        }
    }

    #[test]
    fn matchest_uri_wildcard_match() {
        for (matcher, uri) in [
            (r"*www.example.com", "http://www.example.com"),
            (r"*.css", "http://www.example.com/assets/style.css"),
            (r"*.css", "http://www.example.com/assets/style.css?foo=bar"),
            (
                r"*example.com/foo/*/baz",
                "http://www.example.com/foo/bar/42/baz",
            ),
        ] {
            let matcher = UriMatcher::wildcard(Wildcard::new(matcher.as_bytes()).unwrap());
            assert!(
                matcher.matches_uri(&(uri.parse().unwrap())),
                "({matcher:?}).matches_uri({uri})",
            );
        }
    }

    #[test]
    fn matchest_uri_regex_no_match() {
        for (matcher, uri) in [
            ("www.example.com", "http://WwW.ExamplE.COM"),
            (
                r"(?i)^[^?]+\.(jpeg|png|gif|css)(\?|\z)",
                "http://www.example.com/?style.css",
            ),
        ] {
            let matcher = UriMatcher::regex(Regex::new(matcher).unwrap());
            assert!(
                !matcher.matches_uri(&(uri.parse().unwrap())),
                "!({matcher:?}).matches_uri({uri})",
            );
        }
    }

    #[test]
    fn matchest_uri_wildcard_no_match() {
        for (matcher, uri) in [
            ("http://example.com", "www.example.com"),
            (r"*.png", "http://www.example.com/style.css"),
        ] {
            let matcher = UriMatcher::wildcard(Wildcard::new(matcher.as_bytes()).unwrap());
            assert!(
                !matcher.matches_uri(&(uri.parse().unwrap())),
                "!({matcher:?}).matches_uri({uri})",
            );
        }
    }

    #[test]
    fn uri_matches_regex_req() {
        for (matcher, req) in [
            (
                r"(?i)http://www\.example\.com",
                Request::builder().uri("WwW.ExamplE.COM").body(()).unwrap(),
            ),
            (
                r"(?i)^[^?]+\.(jpeg|png|gif|css)(\?|\z)",
                Request::builder()
                    .uri("http://www.example.com/assets/style.css?foo=bar")
                    .body(())
                    .unwrap(),
            ),
            (
                "/foo/bar",
                Request::builder().uri("/foo/bar").body(()).unwrap(),
            ),
            (
                "example.com/foo/bar",
                Request::builder()
                    .uri("/foo/bar")
                    .header(HOST, "example.com")
                    .body(())
                    .unwrap(),
            ),
        ] {
            let matcher = UriMatcher::regex(Regex::new(matcher).unwrap());
            assert!(
                matcher.matches(None, &req),
                "matcher: {matcher:?}; req: {req:?}"
            );
        }
    }

    #[test]
    fn uri_matches_wildcard_req() {
        for (matcher, req) in [
            (
                r"*://www.example.com",
                Request::builder().uri("www.example.com").body(()).unwrap(),
            ),
            (
                r"*/*.css",
                Request::builder()
                    .uri("http://www.example.com/assets/style.css?foo=bar")
                    .body(())
                    .unwrap(),
            ),
            (
                "/foo/bar",
                Request::builder().uri("/foo/bar").body(()).unwrap(),
            ),
            (
                "http://example.com/*/bar",
                Request::builder()
                    .uri("/foo/bar")
                    .header(HOST, "example.com")
                    .body(())
                    .unwrap(),
            ),
        ] {
            let matcher = UriMatcher::wildcard(Wildcard::new(matcher.as_bytes()).unwrap());
            assert!(
                matcher.matches(None, &req),
                "matcher: {matcher:?}; req: {req:?}"
            );
        }
    }
}
