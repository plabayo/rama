//! [`service::Matcher`]s implementations to match on [`http::Request`]s.
//!
//! See [`service::matcher` module] for more information.
//!
//! [`service::Matcher`]: crate::service::Matcher
//! [`http::Request`]: crate::http::Request
//! [`service::matcher` module]: crate::service::matcher

mod method;
#[doc(inline)]
pub use method::MethodMatcher;

mod domain;
#[doc(inline)]
pub use domain::DomainMatcher;

pub mod uri;
pub use uri::UriMatcher;

mod version;
#[doc(inline)]
pub use version::VersionMatcher;

mod path;
#[doc(inline)]
pub use path::{PathMatcher, UriParams, UriParamsDeserializeError};

mod header;
#[doc(inline)]
pub use header::HeaderMatcher;

use crate::{
    http::Request,
    service::{context::Extensions, matcher::IteratorMatcherExt, Context},
    stream::matcher::SocketMatcher,
};

#[derive(Debug, Clone)]
/// A matcher that is used to match an http [`Request`]
pub struct HttpMatcher {
    kind: HttpMatcherKind,
    negate: bool,
}

#[derive(Debug, Clone)]
/// A matcher that is used to match an http [`Request`]
pub enum HttpMatcherKind {
    /// zero or more [`HttpMatcherKind`]s that all need to match in order for the matcher to return `true`.
    All(Vec<HttpMatcherKind>),
    /// [`MethodMatcher`], a matcher that matches one or more HTTP methods.
    Method(MethodMatcher),
    /// [`PathMatcher`], a matcher based on the URI path.
    Path(PathMatcher),
    /// [`DomainMatcher`], a matcher based on the (sub)domain of the request's URI.
    Domain(DomainMatcher),
    /// [`VersionMatcher`], a matcher based on the HTTP version of the request.
    Version(VersionMatcher),
    /// zero or more [`HttpMatcherKind`]s that at least one needs to match in order for the matcher to return `true`.
    Any(Vec<HttpMatcherKind>),
    /// [`UriMatcher`], a matcher the request's URI, using a substring or regex pattern.
    Uri(UriMatcher),
    /// [`HeaderMatcher`], a matcher based on the [`Request`]'s headers.
    Header(HeaderMatcher),
    /// [`SocketMatcher`], a matcher that matches on the [`SocketAddr`] of the peer.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    Socket(SocketMatcher),
}

impl HttpMatcher {
    /// Create a new matcher that matches one or more HTTP methods.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn method(method: MethodMatcher) -> Self {
        Self {
            kind: HttpMatcherKind::Method(method),
            negate: false,
        }
    }

    /// Create a matcher that also matches one or more HTTP methods on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn and_method(mut self, method: MethodMatcher) -> Self {
        let filter = HttpMatcherKind::Method(method);
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a matcher that can also match one or more HTTP methods as an alternative to the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn or_method(mut self, method: MethodMatcher) -> Self {
        let filter = HttpMatcherKind::Method(method);
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new matcher that matches [`MethodMatcher::DELETE`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn method_delete() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::DELETE),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::DELETE`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn and_method_delete(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::DELETE);
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new matcher that can also match [`MethodMatcher::DELETE`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn or_method_delete(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::DELETE);
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new matcher that matches [`MethodMatcher::GET`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn method_get() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::GET),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::GET`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn and_method_get(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::GET);
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new matcher that can also match [`MethodMatcher::GET`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn or_method_get(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::GET);
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new matcher that matches [`MethodMatcher::HEAD`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn method_head() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::HEAD),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::HEAD`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn and_method_head(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::HEAD);
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new matcher that can also match [`MethodMatcher::HEAD`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn or_method_head(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::HEAD);
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new matcher that matches [`MethodMatcher::OPTIONS`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn method_options() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::OPTIONS),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::OPTIONS`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn and_method_options(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::OPTIONS);
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new matcher that can also match [`MethodMatcher::OPTIONS`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn or_method_options(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::OPTIONS);
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new matcher that matches [`MethodMatcher::PATCH`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn method_patch() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::PATCH),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::PATCH`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn and_method_patch(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::PATCH);
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new matcher that can also match [`MethodMatcher::PATCH`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn or_method_patch(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::PATCH);
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new matcher that matches [`MethodMatcher::POST`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn method_post() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::POST),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::POST`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn and_method_post(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::POST);
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new matcher that can also match [`MethodMatcher::POST`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn or_method_post(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::POST);
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new matcher that matches [`MethodMatcher::PUT`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn method_put() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::PUT),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::PUT`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn and_method_put(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::PUT);
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new matcher that can also match [`MethodMatcher::PUT`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn or_method_put(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::PUT);
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a new matcher that matches [`MethodMatcher::TRACE`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn method_trace() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::TRACE),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::TRACE`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn and_method_trace(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::TRACE);
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Add a new matcher that can also match [`MethodMatcher::TRACE`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    pub fn or_method_trace(mut self) -> Self {
        let filter = HttpMatcherKind::Method(MethodMatcher::TRACE);
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        };
        self
    }

    /// Create a [`DomainMatcher`] matcher.
    pub fn domain(domain: impl Into<String>) -> Self {
        Self {
            kind: HttpMatcherKind::Domain(DomainMatcher::new(domain)),
            negate: false,
        }
    }

    /// Create a [`DomainMatcher`] matcher to also match on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`DomainMatcher`] for more information.
    pub fn and_domain(mut self, domain: impl Into<String>) -> Self {
        let filter = HttpMatcherKind::Domain(DomainMatcher::new(domain));
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`DomainMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`DomainMatcher`] for more information.
    pub fn or_domain(mut self, domain: impl Into<String>) -> Self {
        let filter = HttpMatcherKind::Domain(DomainMatcher::new(domain));
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`VersionMatcher`] matcher.
    pub fn version(version: VersionMatcher) -> Self {
        Self {
            kind: HttpMatcherKind::Version(version),
            negate: false,
        }
    }

    /// Add a [`VersionMatcher`] matcher to filter on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`VersionMatcher`] for more information.
    pub fn and_version(mut self, version: VersionMatcher) -> Self {
        let filter = HttpMatcherKind::Version(version);
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`VersionMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`VersionMatcher`] for more information.
    pub fn or_version(mut self, version: VersionMatcher) -> Self {
        let filter = HttpMatcherKind::Version(version);
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`UriMatcher`] matcher.
    pub fn uri(re: impl AsRef<str>) -> Self {
        Self {
            kind: HttpMatcherKind::Uri(UriMatcher::new(re)),
            negate: false,
        }
    }

    /// Create a [`UriMatcher`] matcher to filter on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`UriMatcher`] for more information.
    pub fn and_uri(mut self, re: impl AsRef<str>) -> Self {
        let filter = HttpMatcherKind::Uri(UriMatcher::new(re));
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`UriMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///    
    /// See [`UriMatcher`] for more information.
    pub fn or_uri(mut self, re: impl AsRef<str>) -> Self {
        let filter = HttpMatcherKind::Uri(UriMatcher::new(re));
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`PathMatcher`] matcher.
    pub fn path(path: impl AsRef<str>) -> Self {
        Self {
            kind: HttpMatcherKind::Path(PathMatcher::new(path)),
            negate: false,
        }
    }

    /// Add a [`PathMatcher`] to filter on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`PathMatcher`] for more information.
    pub fn and_path(mut self, path: impl AsRef<str>) -> Self {
        let filter = HttpMatcherKind::Path(PathMatcher::new(path));
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`PathMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`PathMatcher`] for more information.
    pub fn or_path(mut self, path: impl AsRef<str>) -> Self {
        let filter = HttpMatcherKind::Path(PathMatcher::new(path));
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderMatcher`] matcher.
    pub fn header(name: http::header::HeaderName, value: http::header::HeaderValue) -> Self {
        Self {
            kind: HttpMatcherKind::Header(HeaderMatcher::is(name, value)),
            negate: false,
        }
    }

    /// Add a [`HeaderMatcher`] to filter on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    pub fn and_header(
        mut self,
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        let filter = HttpMatcherKind::Header(HeaderMatcher::is(name, value));
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    pub fn or_header(
        mut self,
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        let filter = HttpMatcherKind::Header(HeaderMatcher::is(name, value));
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderMatcher`] matcher when the given header exists
    /// to filter on the existence of a header.
    pub fn header_exists(name: http::header::HeaderName) -> Self {
        Self {
            kind: HttpMatcherKind::Header(HeaderMatcher::exists(name)),
            negate: false,
        }
    }

    /// Add a [`HeaderMatcher`] to filter when the given header exists
    /// on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    pub fn and_header_exists(mut self, name: http::header::HeaderName) -> Self {
        let filter = HttpMatcherKind::Header(HeaderMatcher::exists(name));
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderMatcher`] matcher to match when the given header exists
    /// as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    pub fn or_header_exists(mut self, name: http::header::HeaderName) -> Self {
        let filter = HttpMatcherKind::Header(HeaderMatcher::exists(name));
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderMatcher`] matcher to filter on it containing the given value.
    pub fn header_contains(
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        Self {
            kind: HttpMatcherKind::Header(HeaderMatcher::contains(name, value)),
            negate: false,
        }
    }

    /// Add a [`HeaderMatcher`] to filter when it contains the given value
    /// on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    pub fn and_header_contains(
        mut self,
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        let filter = HttpMatcherKind::Header(HeaderMatcher::contains(name, value));
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`HeaderMatcher`] matcher to match if it contains the given value
    /// as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    pub fn or_header_contains(
        mut self,
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        let filter = HttpMatcherKind::Header(HeaderMatcher::contains(name, value));
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`SocketMatcher`] matcher.
    pub fn socket(socket: SocketMatcher) -> Self {
        Self {
            kind: HttpMatcherKind::Socket(socket),
            negate: false,
        }
    }

    /// Add a [`SocketMatcher`] matcher to filter on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`SocketMatcher`] for more information.
    pub fn and_socket(mut self, socket: SocketMatcher) -> Self {
        let filter = HttpMatcherKind::Socket(socket);
        match &mut self.kind {
            HttpMatcherKind::All(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::All(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`SocketMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`SocketMatcher`] for more information.
    pub fn or_socket(mut self, socket: SocketMatcher) -> Self {
        let filter = HttpMatcherKind::Socket(socket);
        match &mut self.kind {
            HttpMatcherKind::Any(v) => {
                v.push(filter);
            }
            _ => {
                self.kind = HttpMatcherKind::Any(vec![self.kind, filter]);
            }
        }
        self
    }

    /// Create a [`PathMatcher`] matcher to match for a GET request.
    pub fn get(path: impl AsRef<str>) -> Self {
        Self::method_get().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a POST request.
    pub fn post(path: impl AsRef<str>) -> Self {
        Self::method_post().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a PUT request.
    pub fn put(path: impl AsRef<str>) -> Self {
        Self::method_put().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a DELETE request.
    pub fn delete(path: impl AsRef<str>) -> Self {
        Self::method_delete().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a PATCH request.
    pub fn patch(path: impl AsRef<str>) -> Self {
        Self::method_patch().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a HEAD request.
    pub fn head(path: impl AsRef<str>) -> Self {
        Self::method_head().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a OPTIONS request.
    pub fn options(path: impl AsRef<str>) -> Self {
        Self::method_options().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a TRACE request.
    pub fn trace(path: impl AsRef<str>) -> Self {
        Self::method_trace().and_path(path)
    }

    /// Negate the current matcher
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

impl<State, Body> crate::service::Matcher<State, Request<Body>> for HttpMatcherKind {
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        match self {
            HttpMatcherKind::All(all) => all.iter().matches_and(ext, ctx, req),
            HttpMatcherKind::Method(method) => method.matches(ext, ctx, req),
            HttpMatcherKind::Path(path) => path.matches(ext, ctx, req),
            HttpMatcherKind::Domain(domain) => domain.matches(ext, ctx, req),
            HttpMatcherKind::Version(version) => version.matches(ext, ctx, req),
            HttpMatcherKind::Uri(uri) => uri.matches(ext, ctx, req),
            HttpMatcherKind::Header(header) => header.matches(ext, ctx, req),
            HttpMatcherKind::Socket(socket) => socket.matches(ext, ctx, req),
            HttpMatcherKind::Any(all) => all.iter().matches_or(ext, ctx, req),
        }
    }
}
