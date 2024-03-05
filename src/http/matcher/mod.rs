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
    stream::matcher::SocketMatcher,
};

#[derive(Debug, Clone)]
/// A filter that is used to match an http [`Request`]
pub enum HttpMatcher {
    /// zero or more [`HttpMatcher`]s that all need to match in order for the filter to return `true`.
    Multiple(Vec<HttpMatcher>),
    /// [`MethodFilter`], a filter that matches one or more HTTP methods.
    Method(MethodFilter),
    /// [`PathFilter`], a filter based on the URI path.
    Path(PathFilter),
    /// [`DomainFilter`], a filter based on the (sub)domain of the request's URI.
    Domain(DomainFilter),
    /// [`UriFilter`], a filter the request's URI, using a substring or regex pattern.
    Uri(UriFilter),
    /// [`SocketMatcher`], a filter that matches on the [`SocketAddr`] of the peer.
    Socket(SocketMatcher),
}

impl HttpMatcher {
    /// Create a [`HttpMatcher::Method`] filter.
    pub fn method(method: MethodFilter) -> Self {
        Self::Method(method)
    }

    /// Create a [`HttpMatcher::Method`] `DELETE` filter.
    pub fn method_delete() -> Self {
        Self::Method(MethodFilter::DELETE)
    }

    /// Create a [`HttpMatcher::Method`] `GET` filter.
    pub fn method_get() -> Self {
        Self::Method(MethodFilter::GET)
    }

    /// Create a [`HttpMatcher::Method`] `HEAD` filter.
    pub fn method_head() -> Self {
        Self::Method(MethodFilter::HEAD)
    }

    /// Create a [`HttpMatcher::Method`] `OPTIONS` filter.
    pub fn method_options() -> Self {
        Self::Method(MethodFilter::OPTIONS)
    }

    /// Create a [`HttpMatcher::Method`] `PATCH` filter.
    pub fn method_patch() -> Self {
        Self::Method(MethodFilter::PATCH)
    }

    /// Create a [`HttpMatcher::Method`] `POST` filter.
    pub fn method_post() -> Self {
        Self::Method(MethodFilter::POST)
    }

    /// Create a [`HttpMatcher::Method`] `PUT` filter.
    pub fn method_put() -> Self {
        Self::Method(MethodFilter::PUT)
    }

    /// Create a [`HttpMatcher::Method`] `TRACE` filter.
    pub fn method_trace() -> Self {
        Self::Method(MethodFilter::TRACE)
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

    /// Add a [`HttpMatcher::Method`] `DELETE` filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_method_delete(self) -> Self {
        self.with_method(MethodFilter::DELETE)
    }

    /// Add a [`HttpMatcher::Method`] `GET` filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_method_get(self) -> Self {
        self.with_method(MethodFilter::GET)
    }

    /// Add a [`HttpMatcher::Method`] `HEAD` filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_method_head(self) -> Self {
        self.with_method(MethodFilter::HEAD)
    }

    /// Add a [`HttpMatcher::Method`] `OPTIONS` filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_method_options(self) -> Self {
        self.with_method(MethodFilter::OPTIONS)
    }

    /// Add a [`HttpMatcher::Method`] `PATCH` filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_method_patch(self) -> Self {
        self.with_method(MethodFilter::PATCH)
    }

    /// Add a [`HttpMatcher::Method`] `POST` filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_method_post(self) -> Self {
        self.with_method(MethodFilter::POST)
    }

    /// Add a [`HttpMatcher::Method`] `PUT` filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_method_put(self) -> Self {
        self.with_method(MethodFilter::PUT)
    }

    /// Add a [`HttpMatcher::Method`] `TRACE` filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_method_trace(self) -> Self {
        self.with_method(MethodFilter::TRACE)
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

    /// Create a [`HttpMatcher::Socket`] filter.
    pub fn socket(socket: SocketMatcher) -> Self {
        Self::Socket(socket)
    }

    /// Add a [`HttpMatcher::Socket`] filter to the existing set of [`HttpMatcher`] filters.
    pub fn with_socket(self, socket: SocketMatcher) -> Self {
        HttpMatcher::Multiple(match self {
            HttpMatcher::Multiple(mut v) => {
                v.push(HttpMatcher::socket(socket));
                v
            }
            _ => vec![self, HttpMatcher::socket(socket)],
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
            HttpMatcher::Multiple(all) => all.iter().matches_and(ext, ctx, req),
            HttpMatcher::Method(method) => method.matches(ext, ctx, req),
            HttpMatcher::Path(path) => path.matches(ext, ctx, req),
            HttpMatcher::Domain(domain) => domain.matches(ext, ctx, req),
            HttpMatcher::Uri(uri) => uri.matches(ext, ctx, req),
            HttpMatcher::Socket(socket) => socket.matches(ext, ctx, req),
        }
    }
}
