use crate::{
    http::{Request, Version},
    service::{context::Extensions, Context},
};
use std::fmt::Debug;

/// A filter that matches one or more HTTP methods.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct VersionFilter(Version);

impl VersionFilter {
    /// A filter that matches HTTP/1.0 requests.
    pub const HTTP_10: VersionFilter = VersionFilter(Version::HTTP_10);

    /// A filter that matches HTTP/1.1 requests.
    pub const HTTP_11: VersionFilter = VersionFilter(Version::HTTP_11);

    /// A filter that matches HTTP/2.0 (h2) requests.
    pub const HTTP_2: VersionFilter = VersionFilter(Version::HTTP_2);

    /// A filter that matches HTTP/3.0 (h3) requests.
    pub const HTTP_3: VersionFilter = VersionFilter(Version::HTTP_3);
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for VersionFilter {
    /// returns true on a match, false otherwise
    fn matches(
        &self,
        _ext: Option<&mut Extensions>,
        _ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        req.version() == self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::Matcher;

    #[test]
    fn test_version_filter() {
        let filter = VersionFilter::HTTP_11;
        let req = Request::builder()
            .version(Version::HTTP_11)
            .body(())
            .unwrap();
        assert!(filter.matches(None, &Context::default(), &req));
    }

    #[test]
    fn test_version_filter_fail() {
        let filter = VersionFilter::HTTP_11;
        let req = Request::builder()
            .version(Version::HTTP_10)
            .body(())
            .unwrap();
        assert!(!filter.matches(None, &Context::default(), &req));
    }
}
