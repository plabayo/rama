//! [`service::Matcher`]s implementations to match on [`rama_http_types::Request`]s.
//!
//! See [`service::matcher` module] for more information.
//!
//! [`service::Matcher`]: rama_core::matcher::Matcher
//! [`rama_http_types::Request`]: crate::Request
//! [`service::matcher` module]: rama_core
use crate::Request;
use rama_core::{Context, extensions::Extensions, matcher::IteratorMatcherExt};
use rama_net::{
    address::{AsDomainRef, Domain},
    stream::matcher::SocketMatcher,
};
use std::fmt;
use std::sync::Arc;

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

mod subdomain_trie;
#[doc(inline)]
pub use subdomain_trie::SubdomainTrieMatcher;

/// A matcher that is used to match an http [`Request`]
pub struct HttpMatcher<Body> {
    kind: HttpMatcherKind<Body>,
    negate: bool,
}

impl<Body> Clone for HttpMatcher<Body> {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind.clone(),
            negate: self.negate,
        }
    }
}

impl<Body> fmt::Debug for HttpMatcher<Body> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpMatcher")
            .field("kind", &self.kind)
            .field("negate", &self.negate)
            .finish()
    }
}

/// A matcher that is used to match an http [`Request`]
pub enum HttpMatcherKind<Body> {
    /// zero or more [`HttpMatcher`]s that all need to match in order for the matcher to return `true`.
    All(Vec<HttpMatcher<Body>>),
    /// [`MethodMatcher`], a matcher that matches one or more HTTP methods.
    Method(MethodMatcher),
    /// [`PathMatcher`], a matcher based on the URI path.
    Path(PathMatcher),
    /// [`DomainMatcher`], a matcher based on the (sub)domain of the request's URI.
    Domain(DomainMatcher),
    /// [`VersionMatcher`], a matcher based on the HTTP version of the request.
    Version(VersionMatcher),
    /// zero or more [`HttpMatcher`]s that at least one needs to match in order for the matcher to return `true`.
    Any(Vec<HttpMatcher<Body>>),
    /// [`UriMatcher`], a matcher the request's URI, using a substring or regex pattern.
    Uri(UriMatcher),
    /// [`HeaderMatcher`], a matcher based on the [`Request`]'s headers.
    Header(HeaderMatcher),
    /// [`SocketMatcher`], a matcher that matches on the [`SocketAddr`] of the peer.
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    Socket(SocketMatcher<Request<Body>>),
    /// [`SubdomainTrieMatcher`], a matcher based on domain and subdomains using a trie structure.
    SubdomainTrie(SubdomainTrieMatcher),
    /// A custom matcher that implements [`rama_core::matcher::Matcher`].
    Custom(Arc<dyn rama_core::matcher::Matcher<Request<Body>>>),
}

impl<Body> Clone for HttpMatcherKind<Body> {
    fn clone(&self) -> Self {
        match self {
            Self::All(inner) => Self::All(inner.clone()),
            Self::Method(inner) => Self::Method(*inner),
            Self::Path(inner) => Self::Path(inner.clone()),
            Self::Domain(inner) => Self::Domain(inner.clone()),
            Self::Version(inner) => Self::Version(*inner),
            Self::Any(inner) => Self::Any(inner.clone()),
            Self::Uri(inner) => Self::Uri(inner.clone()),
            Self::Header(inner) => Self::Header(inner.clone()),
            Self::Socket(inner) => Self::Socket(inner.clone()),
            Self::SubdomainTrie(inner) => Self::SubdomainTrie(inner.clone()),
            Self::Custom(inner) => Self::Custom(inner.clone()),
        }
    }
}

impl<Body> fmt::Debug for HttpMatcherKind<Body> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All(inner) => f.debug_tuple("All").field(inner).finish(),
            Self::Method(inner) => f.debug_tuple("Method").field(inner).finish(),
            Self::Path(inner) => f.debug_tuple("Path").field(inner).finish(),
            Self::Domain(inner) => f.debug_tuple("Domain").field(inner).finish(),
            Self::Version(inner) => f.debug_tuple("Version").field(inner).finish(),
            Self::Any(inner) => f.debug_tuple("Any").field(inner).finish(),
            Self::Uri(inner) => f.debug_tuple("Uri").field(inner).finish(),
            Self::Header(inner) => f.debug_tuple("Header").field(inner).finish(),
            Self::Socket(inner) => f.debug_tuple("Socket").field(inner).finish(),
            Self::SubdomainTrie(inner) => f.debug_tuple("SubdomainTrie").field(inner).finish(),
            Self::Custom(_) => f.debug_tuple("Custom").finish(),
        }
    }
}

impl<Body> HttpMatcher<Body> {
    /// Create a new matcher that matches one or more HTTP methods.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn method(method: MethodMatcher) -> Self {
        Self {
            kind: HttpMatcherKind::Method(method),
            negate: false,
        }
    }

    /// Create a matcher that also matches one or more HTTP methods on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn and_method(self, method: MethodMatcher) -> Self {
        self.and(Self::method(method))
    }

    /// Create a matcher that can also match one or more HTTP methods as an alternative to the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn or_method(self, method: MethodMatcher) -> Self {
        self.or(Self::method(method))
    }

    /// Create a new matcher that matches [`MethodMatcher::DELETE`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn method_delete() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::DELETE),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::DELETE`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn and_method_delete(self) -> Self {
        self.and(Self::method_delete())
    }

    /// Add a new matcher that can also match [`MethodMatcher::DELETE`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn or_method_delete(self) -> Self {
        self.or(Self::method_delete())
    }

    /// Create a new matcher that matches [`MethodMatcher::GET`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn method_get() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::GET),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::GET`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn and_method_get(self) -> Self {
        self.and(Self::method_get())
    }

    /// Add a new matcher that can also match [`MethodMatcher::GET`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn or_method_get(self) -> Self {
        self.or(Self::method_get())
    }

    /// Create a new matcher that matches [`MethodMatcher::HEAD`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn method_head() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::HEAD),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::HEAD`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn and_method_head(self) -> Self {
        self.and(Self::method_head())
    }

    /// Add a new matcher that can also match [`MethodMatcher::HEAD`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn or_method_head(self) -> Self {
        self.or(Self::method_head())
    }

    /// Create a new matcher that matches [`MethodMatcher::OPTIONS`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn method_options() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::OPTIONS),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::OPTIONS`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn and_method_options(self) -> Self {
        self.and(Self::method_options())
    }

    /// Add a new matcher that can also match [`MethodMatcher::OPTIONS`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn or_method_options(self) -> Self {
        self.or(Self::method_options())
    }

    /// Create a new matcher that matches [`MethodMatcher::PATCH`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn method_patch() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::PATCH),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::PATCH`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn and_method_patch(self) -> Self {
        self.and(Self::method_patch())
    }

    /// Add a new matcher that can also match [`MethodMatcher::PATCH`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn or_method_patch(self) -> Self {
        self.or(Self::method_patch())
    }

    /// Create a new matcher that matches [`MethodMatcher::POST`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn method_post() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::POST),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::POST`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn and_method_post(self) -> Self {
        self.and(Self::method_post())
    }

    /// Add a new matcher that can also match [`MethodMatcher::POST`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn or_method_post(self) -> Self {
        self.or(Self::method_post())
    }

    /// Create a new matcher that matches [`MethodMatcher::PUT`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn method_put() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::PUT),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::PUT`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn and_method_put(self) -> Self {
        self.and(Self::method_put())
    }

    /// Add a new matcher that can also match [`MethodMatcher::PUT`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn or_method_put(self) -> Self {
        self.or(Self::method_put())
    }

    /// Create a new matcher that matches [`MethodMatcher::TRACE`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn method_trace() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::TRACE),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::TRACE`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn and_method_trace(self) -> Self {
        self.and(Self::method_trace())
    }

    /// Add a new matcher that can also match [`MethodMatcher::TRACE`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn or_method_trace(self) -> Self {
        self.or(Self::method_trace())
    }

    /// Create a new matcher that matches [`MethodMatcher::CONNECT`] requests.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn method_connect() -> Self {
        Self {
            kind: HttpMatcherKind::Method(MethodMatcher::CONNECT),
            negate: false,
        }
    }

    /// Add a new matcher that also matches [`MethodMatcher::CONNECT`] on top of the existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn and_method_connect(self) -> Self {
        self.and(Self::method_connect())
    }

    /// Add a new matcher that can also match [`MethodMatcher::CONNECT`]
    /// as an alternative tothe existing [`HttpMatcher`] matchers.
    ///
    /// See [`MethodMatcher`] for more information.
    #[must_use]
    pub fn or_method_connect(self) -> Self {
        self.or(Self::method_connect())
    }

    /// Create a [`DomainMatcher`] matcher, matching on the exact given [`Domain`].
    #[must_use]
    pub fn domain(domain: Domain) -> Self {
        Self {
            kind: HttpMatcherKind::Domain(DomainMatcher::exact(domain)),
            negate: false,
        }
    }

    /// Create a [`DomainMatcher`] matcher, matching on the exact given [`Domain`]
    /// or a subdomain of it.
    #[must_use]
    pub fn subdomain(domain: Domain) -> Self {
        Self {
            kind: HttpMatcherKind::Domain(DomainMatcher::sub(domain)),
            negate: false,
        }
    }

    /// Create a [`DomainMatcher`] matcher to also match on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`Self::domain`] for more information.
    #[must_use]
    pub fn and_domain(self, domain: Domain) -> Self {
        self.and(Self::domain(domain))
    }

    /// Create a sub [`DomainMatcher`] matcher to also match on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`Self::subdomain`] for more information.
    #[must_use]
    pub fn and_subdomain(self, domain: Domain) -> Self {
        self.and(Self::subdomain(domain))
    }

    /// Create a [`DomainMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`Self::domain`] for more information.
    #[must_use]
    pub fn or_domain(self, domain: Domain) -> Self {
        self.or(Self::domain(domain))
    }

    /// Create a sub [`DomainMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`Self::subdomain`] for more information.
    #[must_use]
    pub fn or_subdomain(self, domain: Domain) -> Self {
        self.or(Self::subdomain(domain))
    }

    /// Create a [`VersionMatcher`] matcher.
    #[must_use]
    pub fn version(version: VersionMatcher) -> Self {
        Self {
            kind: HttpMatcherKind::Version(version),
            negate: false,
        }
    }

    /// Add a [`VersionMatcher`] matcher to matcher on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`VersionMatcher`] for more information.
    #[must_use]
    pub fn and_version(self, version: VersionMatcher) -> Self {
        self.and(Self::version(version))
    }

    /// Create a [`VersionMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`VersionMatcher`] for more information.
    #[must_use]
    pub fn or_version(self, version: VersionMatcher) -> Self {
        self.or(Self::version(version))
    }

    /// Create a [`UriMatcher`] matcher.
    #[must_use]
    pub fn uri(re: impl AsRef<str>) -> Self {
        Self {
            kind: HttpMatcherKind::Uri(UriMatcher::new(re)),
            negate: false,
        }
    }

    /// Create a [`UriMatcher`] matcher to match on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`UriMatcher`] for more information.
    #[must_use]
    pub fn and_uri(self, re: impl AsRef<str>) -> Self {
        self.and(Self::uri(re))
    }

    /// Create a [`UriMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`UriMatcher`] for more information.
    #[must_use]
    pub fn or_uri(self, re: impl AsRef<str>) -> Self {
        self.or(Self::uri(re))
    }

    /// Create a [`PathMatcher`] matcher.
    #[must_use]
    pub fn path(path: impl AsRef<str>) -> Self {
        Self {
            kind: HttpMatcherKind::Path(PathMatcher::new(path)),
            negate: false,
        }
    }

    /// Add a [`PathMatcher`] to match on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`PathMatcher`] for more information.
    #[must_use]
    pub fn and_path(self, path: impl AsRef<str>) -> Self {
        self.and(Self::path(path))
    }

    /// Create a [`PathMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`PathMatcher`] for more information.
    #[must_use]
    pub fn or_path(self, path: impl AsRef<str>) -> Self {
        self.or(Self::path(path))
    }

    /// Create a [`HeaderMatcher`] matcher.
    #[must_use]
    pub fn header(
        name: rama_http_types::header::HeaderName,
        value: rama_http_types::header::HeaderValue,
    ) -> Self {
        Self {
            kind: HttpMatcherKind::Header(HeaderMatcher::is(name, value)),
            negate: false,
        }
    }

    /// Add a [`HeaderMatcher`] to match on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    #[must_use]
    pub fn and_header(
        self,
        name: rama_http_types::header::HeaderName,
        value: rama_http_types::header::HeaderValue,
    ) -> Self {
        self.and(Self::header(name, value))
    }

    /// Create a [`HeaderMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    #[must_use]
    pub fn or_header(
        self,
        name: rama_http_types::header::HeaderName,
        value: rama_http_types::header::HeaderValue,
    ) -> Self {
        self.or(Self::header(name, value))
    }

    /// Create a [`HeaderMatcher`] matcher when the given header exists
    /// to match on the existence of a header.
    #[must_use]
    pub fn header_exists(name: rama_http_types::header::HeaderName) -> Self {
        Self {
            kind: HttpMatcherKind::Header(HeaderMatcher::exists(name)),
            negate: false,
        }
    }

    /// Add a [`HeaderMatcher`] to match when the given header exists
    /// on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    #[must_use]
    pub fn and_header_exists(self, name: rama_http_types::header::HeaderName) -> Self {
        self.and(Self::header_exists(name))
    }

    /// Create a [`HeaderMatcher`] matcher to match when the given header exists
    /// as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    #[must_use]
    pub fn or_header_exists(self, name: rama_http_types::header::HeaderName) -> Self {
        self.or(Self::header_exists(name))
    }

    /// Create a [`HeaderMatcher`] matcher to match on it containing the given value.
    #[must_use]
    pub fn header_contains(
        name: rama_http_types::header::HeaderName,
        value: rama_http_types::header::HeaderValue,
    ) -> Self {
        Self {
            kind: HttpMatcherKind::Header(HeaderMatcher::contains(name, value)),
            negate: false,
        }
    }

    /// Add a [`HeaderMatcher`] to match when it contains the given value
    /// on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    #[must_use]
    pub fn and_header_contains(
        self,
        name: rama_http_types::header::HeaderName,
        value: rama_http_types::header::HeaderValue,
    ) -> Self {
        self.and(Self::header_contains(name, value))
    }

    /// Create a [`HeaderMatcher`] matcher to match if it contains the given value
    /// as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`HeaderMatcher`] for more information.
    #[must_use]
    pub fn or_header_contains(
        self,
        name: rama_http_types::header::HeaderName,
        value: rama_http_types::header::HeaderValue,
    ) -> Self {
        self.or(Self::header_contains(name, value))
    }

    /// Create a [`SocketMatcher`] matcher.
    #[must_use]
    pub fn socket(socket: SocketMatcher<Request<Body>>) -> Self {
        Self {
            kind: HttpMatcherKind::Socket(socket),
            negate: false,
        }
    }

    /// Add a [`SocketMatcher`] matcher to match on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`SocketMatcher`] for more information.
    #[must_use]
    pub fn and_socket(self, socket: SocketMatcher<Request<Body>>) -> Self {
        self.and(Self::socket(socket))
    }

    /// Create a [`SocketMatcher`] matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`SocketMatcher`] for more information.
    #[must_use]
    pub fn or_socket(self, socket: SocketMatcher<Request<Body>>) -> Self {
        self.or(Self::socket(socket))
    }

    /// Create a [`PathMatcher`] matcher to match for a GET request.
    #[must_use]
    pub fn get(path: impl AsRef<str>) -> Self {
        Self::method_get().and_path(path)
    }

    /// Create a matcher that matches according to a custom predicate.
    ///
    /// See [`rama_core::matcher::Matcher`] for more information.
    #[must_use]
    pub fn custom<M>(matcher: M) -> Self
    where
        M: rama_core::matcher::Matcher<Request<Body>>,
    {
        Self {
            kind: HttpMatcherKind::Custom(Arc::new(matcher)),
            negate: false,
        }
    }

    /// Add a custom matcher to match on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`rama_core::matcher::Matcher`] for more information.
    #[must_use]
    pub fn and_custom<M>(self, matcher: M) -> Self
    where
        M: rama_core::matcher::Matcher<Request<Body>>,
    {
        self.and(Self::custom(matcher))
    }

    /// Create a custom matcher to match as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`rama_core::matcher::Matcher`] for more information.
    #[must_use]
    pub fn or_custom<M>(self, matcher: M) -> Self
    where
        M: rama_core::matcher::Matcher<Request<Body>>,
    {
        self.or(Self::custom(matcher))
    }

    /// Create a [`SubdomainTrieMatcher`] matcher that matches if the request domain is a subdomain of the provided domains.
    ///
    /// See [`SubdomainTrieMatcher`] for more information.
    #[must_use]
    pub fn any_subdomain<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsDomainRef,
    {
        Self {
            kind: HttpMatcherKind::SubdomainTrie(SubdomainTrieMatcher::new(domains)),
            negate: false,
        }
    }

    /// Add a [`SubdomainTrieMatcher`] matcher that matches if the request domain is a subdomain of the provided domains on top of the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`SubdomainTrieMatcher`] for more information.
    #[must_use]
    pub fn and_any_subdomain<I, S>(self, domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsDomainRef,
    {
        self.and(Self::any_subdomain(domains))
    }

    /// Create a [`SubdomainTrieMatcher`] matcher that matches if the request domain is a subdomain of the provided domains as an alternative to the existing set of [`HttpMatcher`] matchers.
    ///
    /// See [`SubdomainTrieMatcher`] for more information.
    #[must_use]
    pub fn or_any_subdomain<I, S>(self, domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsDomainRef,
    {
        self.or(Self::any_subdomain(domains))
    }

    /// Create a [`PathMatcher`] matcher to match for a POST request.
    #[must_use]
    pub fn post(path: impl AsRef<str>) -> Self {
        Self::method_post().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a PUT request.
    #[must_use]
    pub fn put(path: impl AsRef<str>) -> Self {
        Self::method_put().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a DELETE request.
    #[must_use]
    pub fn delete(path: impl AsRef<str>) -> Self {
        Self::method_delete().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a PATCH request.
    #[must_use]
    pub fn patch(path: impl AsRef<str>) -> Self {
        Self::method_patch().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a HEAD request.
    #[must_use]
    pub fn head(path: impl AsRef<str>) -> Self {
        Self::method_head().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a OPTIONS request.
    #[must_use]
    pub fn options(path: impl AsRef<str>) -> Self {
        Self::method_options().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a TRACE request.
    #[must_use]
    pub fn trace(path: impl AsRef<str>) -> Self {
        Self::method_trace().and_path(path)
    }

    /// Create a [`PathMatcher`] matcher to match for a CONNECT request.
    #[must_use]
    pub fn connect(path: impl AsRef<str>) -> Self {
        Self::method_connect().and_path(path)
    }

    /// Add a [`HttpMatcher`] to match on top of the existing set of [`HttpMatcher`] matchers.
    #[must_use]
    pub fn and(mut self, matcher: Self) -> Self {
        match (self.negate, &mut self.kind) {
            (false, HttpMatcherKind::All(v)) => {
                v.push(matcher);
                self
            }
            _ => Self {
                kind: HttpMatcherKind::All(vec![self, matcher]),
                negate: false,
            },
        }
    }

    /// Create a [`HttpMatcher`] matcher to match
    /// as an alternative to the existing set of [`HttpMatcher`] matchers.
    #[must_use]
    pub fn or(mut self, matcher: Self) -> Self {
        match (self.negate, &mut self.kind) {
            (false, HttpMatcherKind::Any(v)) => {
                v.push(matcher);
                self
            }
            _ => Self {
                kind: HttpMatcherKind::Any(vec![self, matcher]),
                negate: false,
            },
        }
    }

    /// Negate the current matcher
    #[must_use]
    pub fn negate(self) -> Self {
        Self {
            kind: self.kind,
            negate: true,
        }
    }
}

impl<Body> rama_core::matcher::Matcher<Request<Body>> for HttpMatcher<Body>
where
    Body: Send + 'static,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context, req: &Request<Body>) -> bool {
        let matches = self.kind.matches(ext, ctx, req);
        if self.negate { !matches } else { matches }
    }
}

impl<Body> rama_core::matcher::Matcher<Request<Body>> for HttpMatcherKind<Body>
where
    Body: Send + 'static,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context, req: &Request<Body>) -> bool {
        match self {
            Self::All(all) => all.iter().matches_and(ext, ctx, req),
            Self::Method(method) => method.matches(ext, ctx, req),
            Self::Path(path) => path.matches(ext, ctx, req),
            Self::Domain(domain) => domain.matches(ext, ctx, req),
            Self::Version(version) => version.matches(ext, ctx, req),
            Self::Uri(uri) => uri.matches(ext, ctx, req),
            Self::Header(header) => header.matches(ext, ctx, req),
            Self::Socket(socket) => socket.matches(ext, ctx, req),
            Self::Any(all) => all.iter().matches_or(ext, ctx, req),
            Self::SubdomainTrie(subdomain_trie) => subdomain_trie.matches(ext, ctx, req),
            Self::Custom(matcher) => matcher.matches(ext, ctx, req),
        }
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;

    use rama_core::matcher::Matcher;

    use super::*;

    struct BooleanMatcher(bool);

    impl Matcher<Request<()>> for BooleanMatcher {
        fn matches(
            &self,
            _ext: Option<&mut Extensions>,
            _ctx: &Context,
            _req: &Request<()>,
        ) -> bool {
            self.0
        }
    }

    #[test]
    fn test_matcher_and_combination() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = v[0] && v[1] && v[2];
            let a = HttpMatcher::custom(BooleanMatcher(v[0]));
            let b = HttpMatcher::custom(BooleanMatcher(v[1]));
            let c = HttpMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.and(b).and(c);
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({matcher:#?}).matches({req:#?})",
            );
        }
    }

    #[test]
    fn test_matcher_negation_with_and_combination() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = !v[0] && v[1] && v[2];
            let a = HttpMatcher::custom(BooleanMatcher(v[0]));
            let b = HttpMatcher::custom(BooleanMatcher(v[1]));
            let c = HttpMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.negate().and(b).and(c);
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({matcher:#?}).matches({req:#?})",
            );
        }
    }

    #[test]
    fn test_matcher_and_combination_negated() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = !(v[0] && v[1] && v[2]);
            let a = HttpMatcher::custom(BooleanMatcher(v[0]));
            let b = HttpMatcher::custom(BooleanMatcher(v[1]));
            let c = HttpMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.and(b).and(c).negate();
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({matcher:#?}).matches({req:#?})",
            );
        }
    }

    #[test]
    fn test_matcher_ors_combination() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = v[0] || v[1] || v[2];
            let a = HttpMatcher::custom(BooleanMatcher(v[0]));
            let b = HttpMatcher::custom(BooleanMatcher(v[1]));
            let c = HttpMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.or(b).or(c);
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({matcher:#?}).matches({req:#?})",
            );
        }
    }

    #[test]
    fn test_matcher_negation_with_ors_combination() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = !v[0] || v[1] || v[2];
            let a = HttpMatcher::custom(BooleanMatcher(v[0]));
            let b = HttpMatcher::custom(BooleanMatcher(v[1]));
            let c = HttpMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.negate().or(b).or(c);
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({matcher:#?}).matches({req:#?})",
            );
        }
    }

    #[test]
    fn test_matcher_ors_combination_negated() {
        for v in [true, false].into_iter().permutations(3) {
            let expected = !(v[0] || v[1] || v[2]);
            let a = HttpMatcher::custom(BooleanMatcher(v[0]));
            let b = HttpMatcher::custom(BooleanMatcher(v[1]));
            let c = HttpMatcher::custom(BooleanMatcher(v[2]));

            let matcher = a.or(b).or(c).negate();
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({matcher:#?}).matches({req:#?})",
            );
        }
    }

    #[test]
    fn test_matcher_or_and_or_and_negation() {
        for v in [true, false].into_iter().permutations(5) {
            let expected = (v[0] || v[1]) && (v[2] || v[3]) && !v[4];
            let a = HttpMatcher::custom(BooleanMatcher(v[0]));
            let b = HttpMatcher::custom(BooleanMatcher(v[1]));
            let c = HttpMatcher::custom(BooleanMatcher(v[2]));
            let d = HttpMatcher::custom(BooleanMatcher(v[3]));
            let e = HttpMatcher::custom(BooleanMatcher(v[4]));

            let matcher = (a.or(b)).and(c.or(d)).and(e.negate());
            let req = Request::builder().body(()).unwrap();
            assert_eq!(
                matcher.matches(None, &Context::default(), &req),
                expected,
                "({matcher:#?}).matches({req:#?})",
            );
        }
    }
}
