//! [`service::Matcher`]s implementations to match on [`http::Request`]s.
//!
//! See [`service::matcher` module] for more information.
//!
//! [`service::Matcher`]: crate::service::Matcher
//! [`http::Request`]: crate::http::Request
//! [`service::matcher` module]: crate::service::matcher

mod method;
pub use method::MethodFilter;

mod domain;
pub use domain::DomainFilter;

pub mod uri;
pub use uri::UriFilter;

mod path;
pub use path::{PathFilter, UriParams, UriParamsDeserializeError};

use crate::{
    http::Request,
    service::{context::Extensions, matcher::IteratorMatcherExt, Context},
};

#[derive(Debug, Clone)]
/// A filter that is used to match an http [`Request`]
pub enum HttpMatcher {
    /// [`MethodFilter`], a filter that matches one or more HTTP methods.
    Method(MethodFilter),
    /// [`DomainFilter`], a filter based on the (sub)domain of the request's URI.
    Domain(DomainFilter),
    /// [`UriFilter`], a filter the request's URI, using a substring or regex pattern.
    Uri(UriFilter),
    /// [`PathFilter`], a filter based on the URI path.
    Path(PathFilter),
    /// zero or more [`HttpMatcher`]s that all need to match in order for the filter to return `true`.
    Multiple(Vec<HttpMatcher>),
}

impl HttpMatcher {
    /// Create a [`HttpMatcher::Method`] filter.
    pub fn method(method: MethodFilter) -> Self {
        Self::Method(method)
    }

    /// Add a [`HttpMatcher::Method`] filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_method(self, method: MethodFilter) -> Self {
        HttpMatcher::Multiple(match self {
            HttpMatcher::Multiple(mut v) => {
                v.push(HttpMatcher::method(method));
                v
            }
            _ => vec![self, HttpMatcher::method(method)],
        })
    }

    /// Create a [`HttpMatcher::Domain`] filter.
    pub fn domain(domain: impl Into<String>) -> Self {
        Self::Domain(DomainFilter::new(domain))
    }

    /// Add a [`HttpMatcher::Domain`] filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_domain(self, domain: impl Into<String>) -> Self {
        HttpMatcher::Multiple(match self {
            HttpMatcher::Multiple(mut v) => {
                v.push(HttpMatcher::domain(domain));
                v
            }
            _ => vec![self, HttpMatcher::domain(domain)],
        })
    }

    /// Create a [`HttpMatcher::Uri`] filter.
    pub fn uri(re: impl AsRef<str>) -> Self {
        Self::Uri(UriFilter::new(re))
    }

    /// Add a [`HttpMatcher::Uri`] filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_uri(self, re: impl AsRef<str>) -> Self {
        HttpMatcher::Multiple(match self {
            HttpMatcher::Multiple(mut v) => {
                v.push(HttpMatcher::uri(re));
                v
            }
            _ => vec![self, HttpMatcher::uri(re)],
        })
    }

    /// Create a [`HttpMatcher::Path`] filter.
    pub fn path(path: impl AsRef<str>) -> Self {
        Self::Path(PathFilter::new(path))
    }

    /// Add a [`HttpMatcher::Path`] filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_path(self, path: impl AsRef<str>) -> Self {
        HttpMatcher::Multiple(match self {
            HttpMatcher::Multiple(mut v) => {
                v.push(HttpMatcher::path(path));
                v
            }
            _ => vec![self, HttpMatcher::path(path)],
        })
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for HttpMatcher {
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        match self {
            HttpMatcher::Method(method) => method.matches(ext, ctx, req),
            HttpMatcher::Domain(domain) => domain.matches(ext, ctx, req),
            HttpMatcher::Uri(uri) => uri.matches(ext, ctx, req),
            HttpMatcher::Path(path) => path.matches(ext, ctx, req),
            HttpMatcher::Multiple(all) => all.iter().matches_and(ext, ctx, req),
        }
    }
}
