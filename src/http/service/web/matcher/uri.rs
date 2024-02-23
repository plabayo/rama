//! provides a [`UriFilter`] matcher for filtering requests based on their URI.

use super::Matcher;
use crate::{
    http::{Request, Uri},
    service::{context::Extensions, Context},
};

pub mod dep {
    //! dependencies for the `uri` matcher module

    pub use regex;
}

use dep::regex::Regex;

#[derive(Debug, Clone)]
/// Filter the request's URI, using a substring or regex pattern.
pub struct UriFilter {
    re: Regex,
}

impl UriFilter {
    /// create a new Uri filter using a regex pattern.
    ///
    /// See docs at <https://docs.rs/regex> for more information on regex patterns.
    /// (e.g. to use flags like (?i) for case-insensitive matching)
    ///
    /// # Panics
    ///
    /// Panics if the regex pattern is invalid.
    pub fn new(re: &str) -> Self {
        let re = Regex::new(re).expect("valid regex pattern");
        Self { re }
    }

    pub(crate) fn matches_uri(&self, uri: &Uri) -> bool {
        self.re.is_match(uri.to_string().as_str())
    }
}

impl From<Regex> for UriFilter {
    fn from(re: Regex) -> Self {
        Self { re }
    }
}

impl<State> Matcher<State> for UriFilter {
    fn matches(&self, _ext: &mut Extensions, _ctx: &Context<State>, req: &Request) -> bool {
        self.matches_uri(req.uri())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn matchest_uri_match() {
        let test_cases: Vec<(UriFilter, &str)> = vec![
            (
                UriFilter::new(r"www\.example\.com"),
                "http://www.example.com",
            ),
            (
                UriFilter::new(r"(?i)www\.example\.com"),
                "http://WwW.ExamplE.COM",
            ),
            (
                UriFilter::new(r"(?i)^[^?]+\.(jpeg|png|gif|css)(\?|\z)"),
                "http://www.example.com/assets/style.css?foo=bar",
            ),
            (
                UriFilter::new(r"(?i)^[^?]+\.(jpeg|png|gif|css)(\?|\z)"),
                "http://www.example.com/image.png",
            ),
        ];
        for (filter, uri) in test_cases.into_iter() {
            assert!(
                filter.matches_uri(&(uri.parse().unwrap())),
                "({:?}).matches_uri({})",
                filter,
                uri
            );
        }
    }

    #[test]
    fn matchest_uri_no_match() {
        let test_cases = vec![
            (UriFilter::new("www.example.com"), "http://WwW.ExamplE.COM"),
            (
                UriFilter::new(r"(?i)^[^?]+\.(jpeg|png|gif|css)(\?|\z)"),
                "http://www.example.com/?style.css",
            ),
        ];
        for (filter, uri) in test_cases.into_iter() {
            assert!(
                !filter.matches_uri(&(uri.parse().unwrap())),
                "!({:?}).matches_uri({})",
                filter,
                uri
            );
        }
    }
}
