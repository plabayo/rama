//! [`service::Matcher`]s implementations to match on [`http::Request`]s.
//!
//! See [`service::matcher` module] for more information.
//!
//! [`service::Matcher`]: crate::service::Matcher
//! [`http::Request`]: crate::http::Request
//! [`service::matcher` module]: crate::service::matcher

mod method;
#[doc(inline)]
pub use method::MethodFilter;

mod domain;
#[doc(inline)]
pub use domain::DomainFilter;

pub mod uri;
pub use uri::UriFilter;

mod version;
#[doc(inline)]
pub use version::VersionFilter;

mod path;
pub use path::{PathFilter, UriParams, UriParamsDeserializeError};

mod header;
#[doc(inline)]
pub use header::HeaderFilter;

use crate::{
    http::Request,
    service::{context::Extensions, matcher::IteratorMatcherExt, Context},
    stream::matcher::SocketMatcher,
};

#[derive(Debug, Clone)]
/// A filter that is used to match an http [`Request`]
pub struct HttpMatcher {
    kind: HttpFilterKind,
    negate: bool,
}

#[derive(Debug, Clone)]
/// A filter that is used to match an http [`Request`]
pub enum HttpFilterKind {
    /// zero or more [`HttpFilterKind`]s that all need to match in order for the filter to return `true`.
    All(Vec<HttpFilterKind>),
    /// [`MethodFilter`], a filter that matches one or more HTTP methods.
    Method(MethodFilter),
    /// [`PathFilter`], a filter based on the URI path.
    Path(PathFilter),
    /// [`DomainFilter`], a filter based on the (sub)domain of the request's URI.
    Domain(DomainFilter),
    /// [`VersionFilter`], a filter based on the HTTP version of the request.
    Version(VersionFilter),
    /// zero or more [`HttpFilterKind`]s that at least one needs to match in order for the filter to return `true`.
    Any(Vec<HttpFilterKind>),
    /// [`UriFilter`], a filter the request's URI, using a substring or regex pattern.
    Uri(UriFilter),
    /// [`HeaderFilter`], a filter based on the [`Request`]'s headers.
    Header(HeaderFilter),
    /// [`SocketMatcher`], a filter that matches on the [`SocketAddr`] of the peer.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    Socket(SocketMatcher),
}

impl HttpMatcher {
    /// Create a new filter that matches one or more HTTP methods.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn method(method: MethodFilter) -> Self {
        Self {
            kind: HttpFilterKind::Method(method),
            negate: false,
        }
    }

    /// Create a filter that also matches one or more HTTP methods on top of the existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn and_method(mut self, method: MethodFilter) -> Self {
        let filter = HttpFilterKind::Method(method);
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a filter that can also match one or more HTTP methods as an alternative to the existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn or_method(mut self, method: MethodFilter) -> Self {
        let filter = HttpFilterKind::Method(method);
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new filter that matches [`MethodFilter::DELETE`] requests.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn method_delete() -> Self {
        Self {
            kind: HttpFilterKind::Method(MethodFilter::DELETE),
            negate: false,
        }
    }

    /// Add a new filter that also matches [`MethodFilter::DELETE`] on top of the existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn and_method_delete(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::DELETE);
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new filter that can also match [`MethodFilter::DELETE`]
    /// as an alternative tothe existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn or_method_delete(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::DELETE);
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new filter that matches [`MethodFilter::GET`] requests.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn method_get() -> Self {
        Self {
            kind: HttpFilterKind::Method(MethodFilter::GET),
            negate: false,
        }
    }

    /// Add a new filter that also matches [`MethodFilter::GET`] on top of the existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn and_method_get(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::GET);
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new filter that can also match [`MethodFilter::GET`]
    /// as an alternative tothe existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn or_method_get(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::GET);
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new filter that matches [`MethodFilter::HEAD`] requests.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn method_head() -> Self {
        Self {
            kind: HttpFilterKind::Method(MethodFilter::HEAD),
            negate: false,
        }
    }

    /// Add a new filter that also matches [`MethodFilter::HEAD`] on top of the existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn and_method_head(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::HEAD);
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new filter that can also match [`MethodFilter::HEAD`]
    /// as an alternative tothe existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn or_method_head(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::HEAD);
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new filter that matches [`MethodFilter::OPTIONS`] requests.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn method_options() -> Self {
        Self {
            kind: HttpFilterKind::Method(MethodFilter::OPTIONS),
            negate: false,
        }
    }

    /// Add a new filter that also matches [`MethodFilter::OPTIONS`] on top of the existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn and_method_options(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::OPTIONS);
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new filter that can also match [`MethodFilter::OPTIONS`]
    /// as an alternative tothe existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn or_method_options(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::OPTIONS);
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new filter that matches [`MethodFilter::PATCH`] requests.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn method_patch() -> Self {
        Self {
            kind: HttpFilterKind::Method(MethodFilter::PATCH),
            negate: false,
        }
    }

    /// Add a new filter that also matches [`MethodFilter::PATCH`] on top of the existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn and_method_patch(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::PATCH);
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new filter that can also match [`MethodFilter::PATCH`]
    /// as an alternative tothe existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn or_method_patch(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::PATCH);
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new filter that matches [`MethodFilter::POST`] requests.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn method_post() -> Self {
        Self {
            kind: HttpFilterKind::Method(MethodFilter::POST),
            negate: false,
        }
    }

    /// Add a new filter that also matches [`MethodFilter::POST`] on top of the existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn and_method_post(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::POST);
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new filter that can also match [`MethodFilter::POST`]
    /// as an alternative tothe existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn or_method_post(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::POST);
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new filter that matches [`MethodFilter::PUT`] requests.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn method_put() -> Self {
        Self {
            kind: HttpFilterKind::Method(MethodFilter::PUT),
            negate: false,
        }
    }

    /// Add a new filter that also matches [`MethodFilter::PUT`] on top of the existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn and_method_put(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::PUT);
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new filter that can also match [`MethodFilter::PUT`]
    /// as an alternative tothe existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn or_method_put(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::PUT);
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new filter that matches [`MethodFilter::TRACE`] requests.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn method_trace() -> Self {
        Self {
            kind: HttpFilterKind::Method(MethodFilter::TRACE),
            negate: false,
        }
    }

    /// Add a new filter that also matches [`MethodFilter::TRACE`] on top of the existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn and_method_trace(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::TRACE);
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new filter that can also match [`MethodFilter::TRACE`]
    /// as an alternative tothe existing [`HttpMatcher`] filters.
    ///
    /// See [`MethodFilter`] for more information.
    pub fn or_method_trace(mut self) -> Self {
        let filter = HttpFilterKind::Method(MethodFilter::TRACE);
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a [`DomainFilter`] filter.
    pub fn domain(domain: impl Into<String>) -> Self {
        Self {
            kind: HttpFilterKind::Domain(DomainFilter::new(domain)),
            negate: false,
        }
    }

    /// Create a [`DomainFilter`] filter to also match on top of the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`DomainFilter`] for more information.
    pub fn and_domain(mut self, domain: impl Into<String>) -> Self {
        let filter = HttpFilterKind::Domain(DomainFilter::new(domain));
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`DomainFilter`] filter to match as an alternative to the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`DomainFilter`] for more information.
    pub fn or_domain(mut self, domain: impl Into<String>) -> Self {
        let filter = HttpFilterKind::Domain(DomainFilter::new(domain));
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`VersionFilter`] filter.
    pub fn version(version: VersionFilter) -> Self {
        Self {
            kind: HttpFilterKind::Version(version),
            negate: false,
        }
    }

    /// Add a [`VersionFilter`] filter to filter on top of the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`VersionFilter`] for more information.
    pub fn and_version(mut self, version: VersionFilter) -> Self {
        let filter = HttpFilterKind::Version(version);
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`VersionFilter`] filter to match as an alternative to the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`VersionFilter`] for more information.
    pub fn or_version(mut self, version: VersionFilter) -> Self {
        let filter = HttpFilterKind::Version(version);
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`UriFilter`] filter.
    pub fn uri(re: impl AsRef<str>) -> Self {
        Self {
            kind: HttpFilterKind::Uri(UriFilter::new(re)),
            negate: false,
        }
    }

    /// Create a [`UriFilter`] filter to filter on top of the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`UriFilter`] for more information.
    pub fn and_uri(mut self, re: impl AsRef<str>) -> Self {
        let filter = HttpFilterKind::Uri(UriFilter::new(re));
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`UriFilter`] filter to match as an alternative to the existing set of [`HttpMatcher`] filters.
    ///    
    /// See [`UriFilter`] for more information.
    pub fn or_uri(mut self, re: impl AsRef<str>) -> Self {
        let filter = HttpFilterKind::Uri(UriFilter::new(re));
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`PathFilter`] filter.
    pub fn path(path: impl AsRef<str>) -> Self {
        Self {
            kind: HttpFilterKind::Path(PathFilter::new(path)),
            negate: false,
        }
    }

    /// Add a [`PathFilter`] to filter on top of the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`PathFilter`] for more information.
    pub fn and_path(mut self, path: impl AsRef<str>) -> Self {
        let filter = HttpFilterKind::Path(PathFilter::new(path));
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`PathFilter`] filter to match as an alternative to the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`PathFilter`] for more information.
    pub fn or_path(mut self, path: impl AsRef<str>) -> Self {
        let filter = HttpFilterKind::Path(PathFilter::new(path));
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderFilter`] filter.
    pub fn header(name: http::header::HeaderName, value: http::header::HeaderValue) -> Self {
        Self {
            kind: HttpFilterKind::Header(HeaderFilter::is(name, value)),
            negate: false,
        }
    }

    /// Add a [`HeaderFilter`] to filter on top of the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`HeaderFilter`] for more information.
    pub fn and_header(
        mut self,
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        let filter = HttpFilterKind::Header(HeaderFilter::is(name, value));
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderFilter`] filter to match as an alternative to the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`HeaderFilter`] for more information.
    pub fn or_header(
        mut self,
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        let filter = HttpFilterKind::Header(HeaderFilter::is(name, value));
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderFilter`] filter when the given header exists
    /// to filter on the existence of a header.
    pub fn header_exists(name: http::header::HeaderName) -> Self {
        Self {
            kind: HttpFilterKind::Header(HeaderFilter::exists(name)),
            negate: false,
        }
    }

    /// Add a [`HeaderFilter`] to filter when the given header exists
    /// on top of the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`HeaderFilter`] for more information.
    pub fn and_header_exists(mut self, name: http::header::HeaderName) -> Self {
        let filter = HttpFilterKind::Header(HeaderFilter::exists(name));
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderFilter`] filter to match when the given header exists
    /// as an alternative to the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`HeaderFilter`] for more information.
    pub fn or_header_exists(mut self, name: http::header::HeaderName) -> Self {
        let filter = HttpFilterKind::Header(HeaderFilter::exists(name));
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderFilter`] filter to filter on it containing the given value.
    pub fn header_contains(
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        Self {
            kind: HttpFilterKind::Header(HeaderFilter::contains(name, value)),
            negate: false,
        }
    }

    /// Add a [`HeaderFilter`] to filter when it contains the given value
    /// on top of the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`HeaderFilter`] for more information.
    pub fn and_header_contains(
        mut self,
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        let filter = HttpFilterKind::Header(HeaderFilter::contains(name, value));
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderFilter`] filter to match if it contains the given value
    /// as an alternative to the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`HeaderFilter`] for more information.
    pub fn or_header_contains(
        mut self,
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        let filter = HttpFilterKind::Header(HeaderFilter::contains(name, value));
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`SocketMatcher`] filter.
    pub fn socket(socket: SocketMatcher) -> Self {
        Self {
            kind: HttpFilterKind::Socket(socket),
            negate: false,
        }
    }

    /// Add a [`SocketMatcher`] filter to filter on top of the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`SocketMatcher`] for more information.
    pub fn and_socket(mut self, socket: SocketMatcher) -> Self {
        let filter = HttpFilterKind::Socket(socket);
        match &mut self.kind {
            HttpFilterKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`SocketMatcher`] filter to match as an alternative to the existing set of [`HttpMatcher`] filters.
    ///
    /// See [`SocketMatcher`] for more information.
    pub fn or_socket(mut self, socket: SocketMatcher) -> Self {
        let filter = HttpFilterKind::Socket(socket);
        match &mut self.kind {
            HttpFilterKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpFilterKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`PathFilter`] filter to match for a GET request.
    pub fn get(path: impl AsRef<str>) -> Self {
        Self::method_get().and_path(path)
    }

    /// Create a [`PathFilter`] filter to match for a POST request.
    pub fn post(path: impl AsRef<str>) -> Self {
        Self::method_post().and_path(path)
    }

    /// Create a [`PathFilter`] filter to match for a PUT request.
    pub fn put(path: impl AsRef<str>) -> Self {
        Self::method_put().and_path(path)
    }

    /// Create a [`PathFilter`] filter to match for a DELETE request.
    pub fn delete(path: impl AsRef<str>) -> Self {
        Self::method_delete().and_path(path)
    }

    /// Create a [`PathFilter`] filter to match for a PATCH request.
    pub fn patch(path: impl AsRef<str>) -> Self {
        Self::method_patch().and_path(path)
    }

    /// Create a [`PathFilter`] filter to match for a HEAD request.
    pub fn head(path: impl AsRef<str>) -> Self {
        Self::method_head().and_path(path)
    }

    /// Create a [`PathFilter`] filter to match for a OPTIONS request.
    pub fn options(path: impl AsRef<str>) -> Self {
        Self::method_options().and_path(path)
    }

    /// Create a [`PathFilter`] filter to match for a TRACE request.
    pub fn trace(path: impl AsRef<str>) -> Self {
        Self::method_trace().and_path(path)
    }

    /// Negate the current filter
    pub fn negate(self) -> Self {
        Self {
            kind: self.kind,
            negate: true,
        }
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for HttpMatcher {
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        let matches = self.kind.matches(ext, ctx, req);
        if self.negate {
            !matches
        } else {
            matches
        }
    }
}

impl<State, Body> crate::service::Matcher<State, Request<Body>> for HttpFilterKind {
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        match self {
            HttpFilterKind::All(all) => all.iter().matches_and(ext, ctx, req),
            HttpFilterKind::Method(method) => method.matches(ext, ctx, req),
            HttpFilterKind::Path(path) => path.matches(ext, ctx, req),
            HttpFilterKind::Domain(domain) => domain.matches(ext, ctx, req),
            HttpFilterKind::Version(version) => version.matches(ext, ctx, req),
            HttpFilterKind::Uri(uri) => uri.matches(ext, ctx, req),
            HttpFilterKind::Header(header) => header.matches(ext, ctx, req),
            HttpFilterKind::Socket(socket) => socket.matches(ext, ctx, req),
            HttpFilterKind::Any(all) => all.iter().matches_or(ext, ctx, req),
        }
    }
}
