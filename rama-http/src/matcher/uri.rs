//! provides a [`UriMatcher`] matcher for matching requests based on their URI.

use crate::{Request, Uri};
use rama_core::{Context, context::Extensions};

pub mod dep {
    //! dependencies for the `uri` matcher module

    pub use regex;
}

use dep::regex::Regex;

#[derive(Debug, Clone)]
/// Matcher the request's URI, using a substring or regex pattern.
pub struct UriMatcher {
    re: Regex,
}

impl UriMatcher {
    /// create a new Uri matcher using a regex pattern.
    ///
    /// See docs at <https://docs.rs/regex> for more information on regex patterns.
    /// (e.g. to use flags like (?i) for case-insensitive matching)
    ///
    /// # Panics
    ///
    /// Panics if the regex pattern is invalid.
    pub fn new(re: impl AsRef<str>) -> Self {
        let re = Regex::new(re.as_ref()).expect("valid regex pattern");
        Self { re }
    }

    pub(crate) fn matches_uri(&self, uri: &Uri) -> bool {
        self.re.is_match(uri.to_string().as_str())
    }
}

impl From<Regex> for UriMatcher {
    fn from(re: Regex) -> Self {
        Self { re }
    }
}

impl<State, Body> rama_core::matcher::Matcher<State, Request<Body>> for UriMatcher {
    fn matches(
        &self,
        _ext: Option<&mut Extensions>,
        _ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        self.matches_uri(req.uri())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn matchest_uri_match() {
        let test_cases: Vec<(UriMatcher, &str)> = vec![
            (
                UriMatcher::new(r"www\.example\.com"),
                "http://www.example.com",
            ),
            (
                UriMatcher::new(r"(?i)www\.example\.com"),
                "http://WwW.ExamplE.COM",
            ),
            (
                UriMatcher::new(r"(?i)^[^?]+\.(jpeg|png|gif|css)(\?|\z)"),
                "http://www.example.com/assets/style.css?foo=bar",
            ),
            (
                UriMatcher::new(r"(?i)^[^?]+\.(jpeg|png|gif|css)(\?|\z)"),
                "http://www.example.com/image.png",
            ),
        ];
        for (matcher, uri) in test_cases.into_iter() {
            assert!(
                matcher.matches_uri(&(uri.parse().unwrap())),
                "({matcher:?}).matches_uri({uri})",
            );
        }
    }

    #[test]
    fn matchest_uri_no_match() {
        let test_cases = vec![
            (UriMatcher::new("www.example.com"), "http://WwW.ExamplE.COM"),
            (
                UriMatcher::new(r"(?i)^[^?]+\.(jpeg|png|gif|css)(\?|\z)"),
                "http://www.example.com/?style.css",
            ),
        ];
        for (matcher, uri) in test_cases.into_iter() {
            assert!(
                !matcher.matches_uri(&(uri.parse().unwrap())),
                "!({matcher:?}).matches_uri({uri})",
            );
        }
    }
}
