//! First-class URI support for rama.
//!
//! This module hosts the rama-native URI type. It works for **any RFC 3986
//! URI** — http(s), ws(s), ftp, mailto:, urn:, file:, custom schemes — not
//! just HTTP. HTTP-specific shapes (e.g. asterisk-form `*` from RFC 9112
//! §3.2.4) are supported but called out as such.
//!
//! Graceful by default, lossless on parse (no silent normalization),
//! preserves fragments, and lets you cheaply mutate components without
//! the `into_parts → from_parts` dance.
//!
//! ## HTTP request-target forms (RFC 9112 §3.2)
//!
//! All four shapes are reachable, but not through a single auto-detecting
//! entry point — the grammar is ambiguous (`host:port` parses validly
//! as both authority-form and `scheme:opaque-path`), and the RFC 3986
//! tie-break prefers the scheme reading. Callers handling HTTP request-
//! targets pick the entry point that matches their context:
//!
//! - **origin-form** (`/path?query`) — [`Uri::parse`]
//! - **absolute-form** (`scheme://...`) — [`Uri::parse`]
//! - **authority-form** (`host:port`, for CONNECT) — [`Uri::parse_authority_form`]
//! - **asterisk-form** (`*`, for OPTIONS) — [`Uri::parse`]
//!
//! ## Migrating from `http::Uri`
//!
//! Notable behavioural differences for code switching from `http::Uri`:
//!
//! - **CONNECT request-targets must use [`Uri::parse_authority_form`].**
//!   `http::Uri::from_str("example.com:443")` silently misparsed the
//!   target; rama's [`parse`](Uri::parse) follows RFC 3986 and reads
//!   it as `scheme=example.com / path=443`. Proxies handling CONNECT
//!   must route through the dedicated entry point or the
//!   tie-break will quietly route wrong.
//! - **Out-of-range port → `Err`.** `http::Uri` silently discards
//!   ports outside `u16`; rama returns
//!   [`ParseError::InvalidComponent`] tagged with [`Component::Port`].
//! - **Empty host with port (`http://:8080/`) → `Err`.** `http::Uri`
//!   accepted; rama doesn't.
//! - **Control bytes anywhere → `Err`.** Browsers strip CR/LF/Tab;
//!   rama refuses (smuggling defense).
//! - **Non-special schemes (`urn:`, `data:`, `mailto:`) parse
//!   correctly.** `http::Uri` either rejected them or misparsed
//!   `mailto:user@…` as authority-bearing. rama follows RFC 3986
//!   opaque-path semantics.
//!
//! # What lives where
//!
//! - [`Uri`] (this file) — the opaque public type
//! - URI-component borrowed views: [`PathRef`], [`QueryRef`], [`FragmentRef`]
//! - URI-component owned mutable types: [`Query`], [`Fragment`]
//! - Errors: [`ParseError`], [`UriError`]
//!
//! Host-related borrowed views live with their owned counterparts in
//! [`crate::address`] (`HostRef`, `DomainRef`).
//!
//! `Scheme` is [`Protocol`](crate::Protocol); authority is
//! [`Authority`](crate::address::Authority); host is
//! [`Host`](crate::address::Host) — `Uri` doesn't re-export these.

use std::{borrow::Cow, sync::Arc};

use rama_core::bytes::BytesMut;

mod error;
#[doc(inline)]
pub use error::{Component, ParseError, UriError};

mod component_input;
#[doc(inline)]
pub use component_input::IntoUriComponent;

mod encode;

mod input;
#[doc(inline)]
pub use input::IntoUriInput;

mod path;
#[doc(inline)]
pub use path::{PathMatchOptions, PathRef, PathSegment, PathSegments};

mod path_mut;
#[doc(inline)]
pub use path_mut::PathMut;

mod path_matcher;
#[doc(inline)]
pub use path_matcher::{
    PathCaptures, PathPattern, PathPatternSegmentKind, PathPatternSegmentSpecificity,
    PathRouteCaptures, PathRouteMatch, PathRouter, PathRouterError,
};

mod query;
#[doc(inline)]
pub use query::{Query, QueryDeserializeError, QueryPair, QueryPairRef, QueryPairs, QueryRef};

mod query_mut;
#[doc(inline)]
pub use query_mut::{Drain as QueryDrain, QueryMut};

mod canonicalize;

mod resolve;
#[doc(inline)]
pub use resolve::ResolveError;

mod wire;
#[doc(inline)]
pub use wire::WireError;

mod fragment;
#[doc(inline)]
pub use fragment::{Fragment, FragmentRef};

mod lazy;
mod owned;
pub(crate) mod parser;

use lazy::{LazyAuthority, LazyUriRef};
use owned::OwnedUriRef;
use parser::ParserMode;

use crate::address::{AuthorityRef, HostRef, UserInfoRef};

/// Preserved utility submodule (re-exports the `percent_encoding` crate).
///
/// Kept for source-compat with existing consumers via the
/// `rama_net::uri::util::percent_encoding::…` path.
pub mod util {
    pub use ::percent_encoding;
}

/// First-class URI value.
///
/// Represents any RFC 3986 URI-reference — an absolute URI
/// (`http://example.com/path`), a network-path (`//host/path`), an
/// origin-form path (`/path?query`), a relative reference (`../foo`,
/// `?y`, `#frag`), or the HTTP asterisk-form (`*`). Use
/// [`is_absolute`](Self::is_absolute) to check for the scheme-bearing case.
///
/// Opaque — fields are private. Construct via [`Uri::parse`] (strict
/// shapes only) or [`Uri::parse_reference`] (all URI-references including
/// relatives); inspect via typed accessors ([`scheme`](Self::scheme),
/// [`path`](Self::path), [`query`](Self::query), [`fragment`](Self::fragment),
/// [`host`](Self::host), [`port`](Self::port), [`userinfo`](Self::userinfo),
/// [`authority`](Self::authority)); mutate via the `set_*` / `clear_*`
/// methods.
///
/// `Clone` is cheap: `Asterisk` is zero-cost, `Lazy` / `Owned` clone is one
/// atomic refcount bump on the inner `Arc`.
///
/// # Logging safety
///
/// The [`Debug`](std::fmt::Debug) impl redacts the userinfo password
/// portion (anything after the first `:` inside `user:pass@host`),
/// rendering it as `"***"`. This is the safe default for tracing spans
/// and log lines — a raw `Debug`-print would otherwise leak credentials
/// into observability sinks. The username portion is rendered as-is.
/// [`Display`](std::fmt::Display) deliberately does **not** redact (it
/// is the wire-faithful form); use a dedicated wire writer such as
/// [`write_http_origin_form`](Self::write_http_origin_form) when
/// serializing for HTTP — those drop the userinfo entirely per RFC 9110
/// §4.2.4.
#[derive(Clone)]
pub struct Uri {
    pub(crate) inner: UriInner,
}

/// Internal representation.
///
/// Per-variant `Arc`-boxing keeps `Uri` itself small (one pointer + tag) and
/// makes the heap allocation match the actual variant's size.
///
/// `pub(crate)` so submodules (parser, tests, future M4 accessors) can
/// pattern-match. Still not exposed publicly — `Uri` stays opaque.
#[derive(Debug, Clone)]
pub(crate) enum UriInner {
    /// OPTIONS `*` request-target. No other components.
    Asterisk,
    /// Parsed-once form. Cheap clone, zero-copy reads.
    Lazy(Arc<LazyUriRef>),
    /// Mutated form. Decomposed components.
    Owned(Arc<OwnedUriRef>),
}

impl Uri {
    /// Maximum input length accepted by any of the `Uri::parse*` entry
    /// points. Inputs longer than this fail with [`ParseError::TooLong`].
    /// Capped at `u16::MAX - 1` (component offsets are `u16`).
    pub const MAX_LEN: usize = parser::MAX_URI_LEN;

    /// Parse a URI. **Graceful**: accepts what browsers and curl accept
    /// (e.g. unreserved chars outside RFC 3986's `pchar`, raw UTF-8 in
    /// path/query/fragment). Rejects: ASCII control bytes anywhere,
    /// empty input, and inputs longer than the internal cap.
    pub fn parse<T: IntoUriInput>(input: T) -> Result<Self, ParseError> {
        parser::parse(input::into_uri_input(input), ParserMode::Graceful)
    }

    /// Parse a URI in RFC 3986 strict mode. Inputs that would parse
    /// under [`Uri::parse`] but violate the strict grammar return
    /// [`ParseError::StrictViolation`].
    pub fn parse_strict<T: IntoUriInput>(input: T) -> Result<Self, ParseError> {
        parser::parse(input::into_uri_input(input), ParserMode::Strict)
    }

    /// Parse any RFC 3986 URI-reference — absolute URI or relative-ref.
    ///
    /// Accepts everything [`parse`](Self::parse) accepts, plus the
    /// relative-ref grammar from §4.2:
    /// - empty input (same-document reference)
    /// - `//host/path` (network-path reference)
    /// - `g`, `g/h`, `../g` (path-noscheme)
    /// - `?y` (query-only)
    /// - `#s` (fragment-only)
    ///
    /// Use this when parsing a reference to feed into
    /// [`resolve`](Self::resolve).
    pub fn parse_reference<T: IntoUriInput>(input: T) -> Result<Self, ParseError> {
        parser::parse_uri_reference(input::into_uri_input(input), ParserMode::Graceful)
    }

    /// Strict variant of [`parse_reference`](Self::parse_reference).
    pub fn parse_reference_strict<T: IntoUriInput>(input: T) -> Result<Self, ParseError> {
        parser::parse_uri_reference(input::into_uri_input(input), ParserMode::Strict)
    }

    /// Parse a `&'static str` URI, panicking on invalid input. Convenient
    /// for compile-time-known URIs (constants, defaults, tests, examples)
    /// where the failure mode is "this binary contains a typo" rather
    /// than runtime input handling.
    ///
    /// Uses the graceful parser — same shape as [`parse`](Self::parse),
    /// just without the `Result`. Use [`parse`](Self::parse) for any
    /// runtime / user-supplied input.
    ///
    /// # Panics
    ///
    /// Panics with the underlying [`ParseError`] if `s` is not a valid
    /// URI.
    #[must_use]
    #[expect(
        clippy::panic,
        reason = "static-str invariant: panic at runtime for what's intended to be a compile-time-known URI string"
    )]
    pub fn from_static(s: &'static str) -> Self {
        match Self::parse(rama_core::bytes::Bytes::from_static(s.as_bytes())) {
            Ok(uri) => uri,
            Err(e) => panic!("Uri::from_static: invalid URI {s:?}: {e}"),
        }
    }

    /// Parse the HTTP authority-form request-target used by `CONNECT`
    /// (RFC 9112 §3.2.3).
    ///
    /// Dedicated entry point because [`parse`](Self::parse) cannot
    /// disambiguate authority-form from `scheme:opaque-path` —
    /// `example.com:443` is grammatically both
    /// `authority(example.com:443)` and `scheme(example.com) +
    /// opaque-path(443)`, and RFC 3986 prefers the scheme reading. HTTP
    /// proxies and clients handling CONNECT **must** route those
    /// targets through this function instead.
    ///
    /// # Graceful grammar (this method): `[userinfo@]host[:port]`
    ///
    /// Userinfo and a missing port are accepted as graceful conveniences
    /// for HTTP tooling — userinfo is preserved on the value but
    /// stripped by [`write_http_authority_form`](Self::write_http_authority_form)
    /// before serialization, and the missing port is treated as "fill
    /// in from the scheme" by the HTTP layer. Wire output remains RFC
    /// 9112-compliant.
    ///
    /// For a parser that rejects everything outside `host:port`, use
    /// [`parse_authority_form_strict`](Self::parse_authority_form_strict).
    ///
    /// The returned [`Uri`] has no scheme, no path, no query, and no
    /// fragment — only the authority components ([`host`](Self::host),
    /// [`port`](Self::port), [`userinfo`](Self::userinfo)).
    ///
    /// Returns [`ParseError::InvalidComponent`] for inputs that contain
    /// any of `/`, `?`, or `#` — those bytes indicate a non-authority
    /// shape and the caller should use [`parse`](Self::parse) instead.
    pub fn parse_authority_form<T: IntoUriInput>(input: T) -> Result<Self, ParseError> {
        parser::parse_authority_form(input::into_uri_input(input), ParserMode::Graceful)
    }

    /// Strict-mode variant of [`parse_authority_form`](Self::parse_authority_form):
    /// enforces RFC 9112 §3.2.3 exactly.
    ///
    /// Grammar: `host ":" port`. Userinfo and a missing port both
    /// return [`ParseError::StrictViolation`]; everything else matches
    /// [`parse_authority_form`](Self::parse_authority_form).
    pub fn parse_authority_form_strict<T: IntoUriInput>(input: T) -> Result<Self, ParseError> {
        parser::parse_authority_form(input::into_uri_input(input), ParserMode::Strict)
    }

    /// Build an HTTP **authority-form** URI (`[userinfo@]host[:port]`, the
    /// CONNECT request-target shape) directly from an already-parsed
    /// [`Authority`](crate::address::Authority).
    ///
    /// Unlike [`parse_authority_form`](Self::parse_authority_form) this skips
    /// re-parsing and re-validating a `host:port` string: the host/port are
    /// moved in as values and only the canonical bytes are rendered (needed for
    /// the lazy representation). Use it whenever you already hold an
    /// [`Authority`](crate::address::Authority) instead of round-tripping
    /// through `Authority::to_string()` + `parse_authority_form`.
    #[must_use]
    pub fn from_authority_form(authority: crate::address::Authority) -> Self {
        use std::fmt::Write as _;

        let crate::address::Authority { user_info, address } = authority;

        // Render the canonical authority bytes once, tracking the userinfo span
        // as we write it — the lazy form needs the raw bytes, but the host/port
        // are carried as already-parsed values so nothing is re-scanned.
        let mut s = String::new();
        let userinfo_range = match &user_info {
            Some(ui) => {
                _ = write!(s, "{ui}");
                let end = u16::try_from(s.len()).unwrap_or(u16::MAX);
                s.push('@');
                Some((0, end))
            }
            None => None,
        };
        _ = write!(s, "{address}");
        let crate::address::HostWithOptPort { host, port } = address;

        let bytes = rama_core::bytes::Bytes::from(s);
        // Empty path anchored at the end, matching `parse_authority_form`.
        let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);

        Self::from_lazy(LazyUriRef {
            scheme: None,
            authority: Some(LazyAuthority {
                userinfo_range,
                host,
                port,
            }),
            path: (len, len),
            query: None,
            fragment: None,
            bytes,
        })
    }

    /// Project this URI to HTTP **authority-form** (`[userinfo@]host[:port]`),
    /// the CONNECT request-target shape — keeping only the authority and
    /// dropping the scheme, path, query and fragment.
    ///
    /// Returns `None` when there is no authority component (e.g. an
    /// origin-form `/path` or the asterisk-form `*`). This is the companion
    /// to [`parse_authority_form`](Self::parse_authority_form) for an
    /// already-parsed URI, so callers need not round-trip through a manual
    /// `host:port` string.
    #[must_use]
    pub fn as_authority_form(&self) -> Option<Self> {
        Some(Self::from_authority_form(self.authority()?.into_owned()))
    }

    /// Build an **absolute** URI (`scheme://[userinfo@]host[:port]`) from a
    /// scheme and anything convertible into an
    /// [`Authority`](crate::address::Authority) — a
    /// [`Domain`](crate::address::Domain), [`IpAddr`](std::net::IpAddr),
    /// [`Host`](crate::address::Host), [`SocketAddr`](std::net::SocketAddr),
    /// a `(host, port)` tuple, an [`Authority`](crate::address::Authority)
    /// itself, and so on.
    ///
    /// This is the structured, allocation-light replacement for the
    /// `format!("http://{host}").parse()` idiom: the already-typed host /
    /// port are moved straight into the value (no re-parsing) and the
    /// canonical bytes are rendered exactly once. The result has the given
    /// scheme and authority, an empty path, and no query or fragment —
    /// matching what `Uri::parse("http://example.com")` produces.
    ///
    /// For a string host that still needs parsing, use
    /// [`try_from_authority`](Self::try_from_authority). For the scheme-less
    /// CONNECT request-target shape, use
    /// [`from_authority_form`](Self::from_authority_form).
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::{Protocol, address::Domain, uri::Uri};
    ///
    /// let uri = Uri::from_authority(Protocol::HTTP, Domain::from_static("example.com"));
    /// assert_eq!(uri.to_string(), "http://example.com");
    ///
    /// let addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    /// let uri = Uri::from_authority(Protocol::HTTPS, addr);
    /// assert_eq!(uri.to_string(), "https://127.0.0.1:8080");
    /// ```
    #[must_use]
    pub fn from_authority(
        scheme: impl Into<crate::Protocol>,
        authority: impl Into<crate::address::Authority>,
    ) -> Self {
        Self::from_scheme_and_authority(scheme.into(), authority.into())
    }

    /// Fallible [`from_authority`](Self::from_authority) for inputs that must
    /// be parsed into an [`Authority`](crate::address::Authority) first —
    /// typically a `&str` / `String` host (`"example.com"`,
    /// `"user@example.com:8080"`).
    ///
    /// This is the one-shot replacement for the
    /// `format!("http://{s}").parse()` round-trip when `s` is a string; for
    /// already-typed hosts prefer the infallible
    /// [`from_authority`](Self::from_authority).
    ///
    /// Returns [`UriError::ComponentConversion`] tagged with
    /// [`Component::Authority`] when the input cannot be read as an
    /// authority — the boxed cause carries the original error.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::{Protocol, uri::Uri};
    ///
    /// let uri = Uri::try_from_authority(Protocol::HTTP, "user@example.com:8080").unwrap();
    /// assert_eq!(uri.to_string(), "http://user@example.com:8080");
    /// ```
    pub fn try_from_authority<A>(
        scheme: impl Into<crate::Protocol>,
        authority: A,
    ) -> Result<Self, UriError>
    where
        A: TryInto<crate::address::Authority>,
        A::Error: Into<rama_core::error::BoxError>,
    {
        let authority = authority
            .try_into()
            .map_err(|e| UriError::ComponentConversion {
                component: Component::Authority,
                cause: e.into(),
            })?;
        Ok(Self::from_scheme_and_authority(scheme.into(), authority))
    }

    /// Monomorphic core shared by [`from_authority`](Self::from_authority)
    /// and [`try_from_authority`](Self::try_from_authority) — renders the
    /// absolute lazy form once from owned scheme + authority values.
    fn from_scheme_and_authority(
        scheme: crate::Protocol,
        authority: crate::address::Authority,
    ) -> Self {
        use std::fmt::Write as _;

        let crate::address::Authority { user_info, address } = authority;

        // Render the canonical `scheme://[userinfo@]host[:port]` bytes once,
        // tracking the userinfo span as we go — the lazy form needs the raw
        // bytes, but the host/port are carried as already-parsed values so
        // nothing is re-scanned.
        let mut s = String::new();
        _ = write!(s, "{scheme}://");
        let userinfo_range = match &user_info {
            Some(ui) => {
                let start = u16::try_from(s.len()).unwrap_or(u16::MAX);
                _ = write!(s, "{ui}");
                let end = u16::try_from(s.len()).unwrap_or(u16::MAX);
                s.push('@');
                Some((start, end))
            }
            None => None,
        };
        _ = write!(s, "{address}");
        let crate::address::HostWithOptPort { host, port } = address;

        let bytes = rama_core::bytes::Bytes::from(s);
        // Empty path anchored at the end, matching `Uri::parse("scheme://host")`.
        let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);

        Self::from_lazy(LazyUriRef {
            scheme: Some(scheme),
            authority: Some(LazyAuthority {
                userinfo_range,
                host,
                port,
            }),
            path: (len, len),
            query: None,
            fragment: None,
            bytes,
        })
    }

    /// View this [`Uri`] as a str.
    ///
    /// This method may allocate, and can also contain
    /// sensitive credentials. Do not use it for hot paths or logging purposes.
    /// Nor is it intended for encoding purposes.
    ///
    /// It is mostly used for where you need a string representation,
    /// but wish to borrow if possible and only allocate to a string if
    /// you must, as a possibly cheaper alternative compared to `to_string`.
    pub fn as_str(&self) -> Cow<'_, str> {
        match &self.inner {
            UriInner::Asterisk => Cow::Borrowed("*"),
            UriInner::Lazy(lazy_uri_ref) => {
                // Safety: parser invariant — the source buffer is valid UTF-8
                // (graceful mode) or ASCII (strict mode).
                let s = unsafe { std::str::from_utf8_unchecked(&lazy_uri_ref.bytes) };
                Cow::Borrowed(s)
            }
            UriInner::Owned(_) => Cow::Owned(self.to_string()),
        }
    }

    /// Append this URI's canonical wire bytes to `buf`, without going
    /// through [`std::fmt`].
    ///
    /// Parsed (lazy) and asterisk URIs copy their stored bytes in directly
    /// (no re-render); the mutated (owned) form — rare on an encode path,
    /// which normally carries a parsed request-target — falls back to
    /// [`Display`](std::fmt::Display).
    ///
    /// This writes the wire-faithful **full** form (matching `Display`),
    /// so it does not strip userinfo/fragment. To project a richer URI to
    /// a specific HTTP request-target form, use the dedicated
    /// [`write_http_origin_form`](Self::write_http_origin_form) family.
    pub fn encode_to(&self, buf: &mut Vec<u8>) {
        match &self.inner {
            UriInner::Asterisk => buf.push(b'*'),
            UriInner::Lazy(lazy) => buf.extend_from_slice(&lazy.bytes),
            UriInner::Owned(_) => buf.extend_from_slice(self.to_string().as_bytes()),
        }
    }

    /// Returns `true` if this is the OPTIONS-`*` request-target.
    #[must_use]
    pub fn is_asterisk(&self) -> bool {
        matches!(self.inner, UriInner::Asterisk)
    }

    /// Returns `true` if this is an absolute URI — has a scheme. Inverse
    /// case is a URI-reference without a scheme (relative reference,
    /// origin-form path, or the asterisk).
    #[must_use]
    pub fn is_absolute(&self) -> bool {
        self.scheme().is_some()
    }

    /// Returns the scheme component, or `None` if the URI has none
    /// (origin-form URIs and the asterisk-form).
    #[must_use]
    pub fn scheme(&self) -> Option<&crate::Protocol> {
        match &self.inner {
            UriInner::Asterisk => None,
            UriInner::Lazy(arc) => arc.scheme.as_ref(),
            UriInner::Owned(arc) => arc.scheme.as_ref(),
        }
    }

    /// Returns the path component, or `None` for the asterisk-form
    /// (which has no path — the request-target *is* `*`).
    ///
    /// For every other form (origin, absolute with or without authority)
    /// a path is always present per RFC 3986 §3.3 — possibly empty
    /// (e.g. `http://example.com` has an empty path-abempty).
    #[must_use]
    pub fn path(&self) -> Option<PathRef<'_>> {
        match &self.inner {
            UriInner::Asterisk => None,
            UriInner::Lazy(arc) => {
                let (s, e) = arc.path;
                Some(PathRef::new(&arc.bytes[s as usize..e as usize]))
            }
            UriInner::Owned(arc) => Some(PathRef::new(&arc.path)),
        }
    }

    /// Returns the query component, or `None` if the URI has no `?`
    /// delimiter on the wire.
    ///
    /// `Some(empty)` vs `None` matters — `?` followed by nothing is
    /// distinct from no `?` at all (load-bearing for SigV4 / cache
    /// keys / proxy fidelity).
    #[must_use]
    pub fn query(&self) -> Option<QueryRef<'_>> {
        match &self.inner {
            UriInner::Asterisk => None,
            UriInner::Lazy(arc) => {
                let (s, e) = arc.query?;
                Some(QueryRef::new(&arc.bytes[s as usize..e as usize]))
            }
            UriInner::Owned(arc) => arc.query.as_ref().map(|q| q.view()),
        }
    }

    /// Returns the fragment component, or `None` if the URI has no `#`
    /// delimiter on the wire. Same `Some(empty)` vs `None` distinction
    /// as [`query`](Self::query).
    ///
    /// Note: the wire writer for HTTP request-targets strips the
    /// fragment per RFC 9110 §7.1. This accessor returns it for
    /// inspection / logging / preservation purposes.
    #[must_use]
    pub fn fragment(&self) -> Option<FragmentRef<'_>> {
        match &self.inner {
            UriInner::Asterisk => None,
            UriInner::Lazy(arc) => {
                let (s, e) = arc.fragment?;
                Some(FragmentRef::new(&arc.bytes[s as usize..e as usize]))
            }
            UriInner::Owned(arc) => arc.fragment.as_ref().map(|f| f.view()),
        }
    }

    /// Returns the authority's host, or `None` if the URI has no
    /// authority (origin-form `/foo`, asterisk-form `*`, opaque-path
    /// `urn:isbn:0`, etc.).
    ///
    /// This is a shortcut for accessing just the host component;
    /// [`Uri::authority`](Self::authority) gives the full bundle
    /// (host + port + userinfo).
    #[must_use]
    pub fn host(&self) -> Option<crate::address::HostRef<'_>> {
        match &self.inner {
            UriInner::Asterisk => None,
            UriInner::Lazy(arc) => arc.authority.as_ref().map(|a| (&a.host).into()),
            UriInner::Owned(arc) => arc.authority.as_ref().map(|a| (&a.address.host).into()),
        }
    }

    /// Returns the port as an [`OptPort`](crate::address::OptPort) —
    /// `Unset` / `Empty` / `Set(u16)`.
    ///
    /// **Most callers want [`port_u16`](Self::port_u16) instead** — it
    /// returns `Option<u16>` and collapses the wire-only `Empty`
    /// distinction. Use `port()` only when you need to preserve the
    /// difference between `host` (no colon) and `host:` (colon with
    /// no digits) on the wire.
    ///
    /// Scheme default ports are NOT substituted — that's a
    /// canonicalization policy decision the caller makes (e.g.
    /// `Protocol::default_port()` if the URI's scheme is known).
    #[must_use]
    pub fn port(&self) -> crate::address::OptPort {
        match &self.inner {
            UriInner::Asterisk => crate::address::OptPort::Unset,
            UriInner::Lazy(arc) => arc
                .authority
                .as_ref()
                .map(|a| a.port)
                .unwrap_or(crate::address::OptPort::Unset),
            UriInner::Owned(arc) => arc
                .authority
                .as_ref()
                .map(|a| a.address.port)
                .unwrap_or(crate::address::OptPort::Unset),
        }
    }

    /// Relaxed view of the port — `Set(n) → Some(n)`, `Unset` /
    /// `Empty` both → `None`. Use when the wire distinction between
    /// "no colon" and "empty colon" doesn't matter (e.g. dialing).
    #[must_use]
    #[inline]
    pub fn port_u16(&self) -> Option<u16> {
        self.port().as_u16()
    }

    /// Returns the userinfo component, or `None` if the URI has no
    /// authority OR the authority has no `@`.
    ///
    /// `Some("")` (the `@host` form — empty userinfo before `@`) is
    /// distinct from `None` (no `@` at all). Wire fidelity preserved.
    #[must_use]
    pub fn userinfo(&self) -> Option<crate::address::UserInfoRef<'_>> {
        match &self.inner {
            UriInner::Asterisk => None,
            UriInner::Lazy(arc) => {
                let auth = arc.authority.as_ref()?;
                let (s, e) = auth.userinfo_range?;
                Some(UserInfoRef::new(&arc.bytes[s as usize..e as usize]))
            }
            UriInner::Owned(arc) => arc
                .authority
                .as_ref()
                .and_then(|a| a.user_info.as_ref())
                .map(|ui| ui.view()),
        }
    }

    /// Returns the full authority component (host + port + userinfo)
    /// as a borrowed view, or `None` if the URI has no authority
    /// (origin-form, asterisk-form, opaque-path schemes).
    ///
    /// For just the host or just the port, [`Uri::host`] and
    /// [`Uri::port`] are slightly cheaper shortcuts (no extra struct).
    #[must_use]
    pub fn authority(&self) -> Option<crate::address::AuthorityRef<'_>> {
        match &self.inner {
            UriInner::Asterisk => None,
            UriInner::Lazy(arc) => {
                let auth = arc.authority.as_ref()?;
                let userinfo = auth
                    .userinfo_range
                    .map(|(s, e)| UserInfoRef::new(&arc.bytes[s as usize..e as usize]));
                Some(AuthorityRef::new(
                    userinfo,
                    HostRef::from(&auth.host),
                    auth.port,
                ))
            }
            UriInner::Owned(arc) => {
                let auth = arc.authority.as_ref()?;
                let userinfo = auth.user_info.as_ref().map(|ui| ui.view());
                Some(AuthorityRef::new(
                    userinfo,
                    HostRef::from(&auth.address.host),
                    auth.address.port,
                ))
            }
        }
    }

    /// The percent-encoded path as a string, defaulting to `"/"` when the
    /// path is absent or empty (the effective origin-form path). Shortcut for
    /// `uri.path().map(PathRef::as_encoded_str).filter(|p| !p.is_empty()).unwrap_or("/")`.
    #[must_use]
    pub fn path_or_root(&self) -> Cow<'_, str> {
        self.path()
            .and_then(|p| {
                let s = p.as_encoded_str();
                (!s.is_empty()).then_some(s)
            })
            .unwrap_or(Cow::Borrowed("/"))
    }

    /// The path as a typed borrowed view, defaulting to `"/"` when the path is
    /// absent or empty (the effective origin-form path).
    #[must_use]
    pub fn path_ref_or_root(&self) -> PathRef<'_> {
        self.path()
            .filter(|p| !p.encoded_bytes_unchecked().is_empty())
            .unwrap_or_else(|| PathRef::from_raw_str("/"))
    }

    /// The percent-encoded query as a string, defaulting to `""` when absent.
    /// Shortcut for `uri.query().map(|q| q.as_encoded_str()).unwrap_or_default()`.
    #[must_use]
    pub fn query_or_empty(&self) -> Cow<'_, str> {
        self.query()
            .map(QueryRef::as_encoded_str)
            .unwrap_or(Cow::Borrowed(""))
    }

    /// The scheme as a `&str`, or `None`. Shortcut for
    /// `uri.scheme().map(|p| p.as_str())`.
    #[must_use]
    pub fn scheme_str(&self) -> Option<&str> {
        self.scheme().map(crate::Protocol::as_str)
    }

    /// The host rendered as a string, or `None`. Shortcut for
    /// `uri.host().map(|h| h.to_str())`.
    #[must_use]
    pub fn host_str(&self) -> Option<Cow<'_, str>> {
        self.host().map(|h| h.to_str())
    }

    /// The HTTP origin-form request-target: [`path_or_root`](Self::path_or_root)
    /// followed by `?` + query when a query is present. Borrows when there
    /// is no query (zero-alloc), otherwise allocates the joined string.
    #[must_use]
    pub fn request_target(&self) -> Cow<'_, str> {
        // OPTIONS `*` is its own request-target form (not origin-form); without
        // this, `path_or_root()` would render it as `/`.
        if self.is_asterisk() {
            return Cow::Borrowed("*");
        }
        match self.query() {
            Some(q) => Cow::Owned(format!("{}?{}", self.path_or_root(), q.as_encoded_str())),
            None => self.path_or_root(),
        }
    }

    /// `true` when the path begins with `prefix` — matched at `/` segment
    /// boundaries with percent-decoded comparison (default [`PathMatchOptions`]).
    /// See [`has_path_prefix_with_opts`](Self::has_path_prefix_with_opts) for
    /// partial / raw / case-insensitive matching, and [`PathMut::strip_prefix`]
    /// to remove it.
    #[must_use]
    pub fn has_path_prefix(&self, prefix: impl IntoUriComponent) -> bool {
        self.path().is_some_and(|p| p.has_prefix(prefix))
    }

    /// [`has_path_prefix`](Self::has_path_prefix) with explicit [`PathMatchOptions`].
    #[must_use]
    pub fn has_path_prefix_with_opts(
        &self,
        prefix: impl IntoUriComponent,
        opts: PathMatchOptions,
    ) -> bool {
        self.path()
            .is_some_and(|p| p.has_prefix_with_opts(prefix, opts))
    }

    /// `true` when the path ends with `suffix` — matched at `/` segment
    /// boundaries with percent-decoded comparison (default [`PathMatchOptions`]).
    #[must_use]
    pub fn has_path_suffix(&self, suffix: impl IntoUriComponent) -> bool {
        self.path().is_some_and(|p| p.has_suffix(suffix))
    }

    /// [`has_path_suffix`](Self::has_path_suffix) with explicit [`PathMatchOptions`].
    #[must_use]
    pub fn has_path_suffix_with_opts(
        &self,
        suffix: impl IntoUriComponent,
        opts: PathMatchOptions,
    ) -> bool {
        self.path()
            .is_some_and(|p| p.has_suffix_with_opts(suffix, opts))
    }

    /// `true` when `path` matches given [`PathPattern`].
    ///
    /// Shortcut for [`PathRef::is_pattern_match`].
    #[must_use]
    #[inline(always)]
    pub fn is_pattern_match(&self, pattern: &PathPattern) -> bool {
        self.path_ref_or_root().is_pattern_match(pattern)
    }

    /// Match using the given [`PathPattern`]
    /// and return captured values, or `None` when `path` doesn't
    /// match. May allocate a small `Vec` for the bindings.
    ///
    /// Shortcut for [`PathPattern::captures`].
    #[must_use]
    #[inline(always)]
    pub fn pattern_captures<'a, 'b>(
        &'a self,
        pattern: &'b PathPattern,
    ) -> Option<PathCaptures<'b, 'a>> {
        self.path_ref_or_root().pattern_captures(pattern)
    }

    /// The `n`-th path segment (0-indexed, `/`-delimited, leading `/`
    /// ignored), or `None`. Shortcut for `uri.path()?.segments().nth(n)`.
    #[must_use]
    pub fn path_segment(&self, n: usize) -> Option<PathSegment<'_>> {
        self.path().and_then(|p| p.segments().nth(n))
    }

    /// The first segment Shortcut for `uri.path_segment(0)`.
    #[must_use]
    #[inline(always)]
    pub fn first_path_segment(&self) -> Option<PathSegment<'_>> {
        self.path_segment(0)
    }

    /// Deserialize the query string into `T` via `serde` (an absent query
    /// deserializes as empty). Shortcut over [`Uri::query`] +
    /// [`QueryRef::deserialize`].
    pub fn query_params<'de, T>(&'de self) -> Result<T, QueryDeserializeError>
    where
        T: serde::de::Deserialize<'de>,
    {
        let query = self.query().unwrap_or_else(|| QueryRef::new(b""));
        query.deserialize()
    }

    /// Ensure the path ends with exactly one trailing `/` (appended when
    /// missing; an empty path becomes `/`). Scheme, authority and query
    /// are preserved.
    pub fn ensure_path_trailing_slash(&mut self) -> &mut Self {
        self.path_mut().ensure_trailing_slash();
        self
    }

    /// Internal constructor for the asterisk variant.
    #[must_use]
    pub(crate) fn from_asterisk() -> Self {
        Self {
            inner: UriInner::Asterisk,
        }
    }

    /// Internal constructor for the lazy variant.
    pub(crate) fn from_lazy(lazy: LazyUriRef) -> Self {
        Self {
            inner: UriInner::Lazy(Arc::new(lazy)),
        }
    }

    // ---- Mutation -------------------------------------------------------

    /// Promote to [`UriInner::Owned`] if needed and return mutable access
    /// to the decomposed components. Cheap when already `Owned` and the
    /// inner `Arc` is uniquely held.
    fn to_mut(&mut self) -> &mut OwnedUriRef {
        if !matches!(self.inner, UriInner::Owned(_)) {
            let owned = self.as_owned_components();
            self.inner = UriInner::Owned(Arc::new(owned));
        }
        match &mut self.inner {
            UriInner::Owned(arc) => Arc::make_mut(arc),
            // SAFETY: the preceding `if` block guarantees `self.inner` is the
            // `Owned` variant. Borrowck can't see across the conditional
            // assignment, so we have to tell it explicitly.
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    /// Snapshot the current URI as an [`OwnedUriRef`]. Used by `to_mut`
    /// to materialise components when promoting from Lazy / Asterisk,
    /// and by [`resolve`](Self::resolve) to take owned snapshots of
    /// base / reference for component-level recomposition.
    pub(super) fn as_owned_components(&self) -> OwnedUriRef {
        match &self.inner {
            UriInner::Asterisk => OwnedUriRef::default(),
            UriInner::Lazy(arc) => {
                let l = arc.as_ref();
                let authority = l.authority.as_ref().map(|la| {
                    let user_info = la.userinfo_range.map(|(s, e)| {
                        crate::address::UserInfo::from_bytes_unchecked(
                            l.bytes.slice(s as usize..e as usize),
                        )
                    });
                    crate::address::Authority {
                        user_info,
                        address: crate::address::HostWithOptPort {
                            host: la.host.clone(),
                            port: la.port,
                        },
                    }
                });
                let slice = |(s, e): (u16, u16)| &l.bytes[s as usize..e as usize];
                OwnedUriRef {
                    scheme: l.scheme.clone(),
                    authority,
                    path: BytesMut::from(slice(l.path)),
                    query: l.query.map(|r| Query {
                        bytes: BytesMut::from(slice(r)),
                    }),
                    fragment: l.fragment.map(|r| Fragment {
                        bytes: BytesMut::from(slice(r)),
                    }),
                }
            }
            UriInner::Owned(arc) => arc.as_ref().clone(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Replace the path. Bytes outside RFC 3986 `pchar ∪ {'/'}` are
        /// percent-encoded — pass raw (decoded) values, the library
        /// serializes them correctly. Already-legal owned inputs move
        /// without allocating.
        pub fn path(mut self, path: impl IntoUriComponent) -> Self {
            self.to_mut().path = encode::encode_path(path);
            self
        }
    }

    /// Clear the path (empty bytes — no leading `/`). Path is never
    /// absent in the URI grammar, so this is the canonical "no path"
    /// state, not a removal.
    pub fn unset_path(&mut self) -> &mut Self {
        self.to_mut().path = BytesMut::new();
        self
    }

    /// Consuming form of [`unset_path`](Self::unset_path).
    #[must_use]
    pub fn without_path(mut self) -> Self {
        self.unset_path();
        self
    }

    /// Returns a [`PathMut`] guard for incremental path mutation —
    /// `push_segment`, `pop_segment`, `clear`.
    pub fn path_mut(&mut self) -> PathMut<'_> {
        PathMut::new(self.to_mut())
    }

    rama_utils::macros::generate_set_and_with! {
        /// Append an additional `/`-delimited path segment, inserting a
        /// `/` separator first if the current path doesn't already end
        /// with one. Shortcut for [`path_mut().push_segment(..)`](PathMut::push_segment) —
        /// see that method for the full encoding policy (bytes outside
        /// the RFC 3986 path-segment set are percent-encoded; pass
        /// decoded values, not pre-encoded ones).
        ///
        /// Empty path + `"x"` → `/x`; `/foo` + `"bar"` → `/foo/bar`;
        /// `/foo/` + `"bar"` → `/foo/bar` (no double slash).
        pub fn additional_path_segment(mut self, segment: impl IntoUriComponent) -> Self {
            self.path_mut().push_segment(segment);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Remove the final `/`-delimited path segment. Shortcut for
        /// [`path_mut().pop_segment()`](PathMut::pop_segment) when you
        /// want the shortened [`Uri`] back and don't need the removed
        /// bytes (use the guard directly if you do).
        ///
        /// This pops one wire segment — **not** a `Path::parent`-style
        /// "go up a directory". A trailing `/` is its own empty segment,
        /// so `/foo/bar/` → `/foo/bar` (the trailing slash is dropped),
        /// `/foo/bar` → `/foo`, and `/foo` → empty. An empty or opaque
        /// (no `/`) path collapses to empty.
        pub fn path_without_last_segment(mut self) -> Self {
            self.path_mut().pop_segment();
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set, clear, or assign the query. Bytes taken as-is — no
        /// re-encoding. Pair with [`set_query_from_bytes`](Self::set_query_from_bytes)
        /// when you have raw bytes that need pct-encoding.
        pub fn query(mut self, query: Option<Query>) -> Self {
            self.to_mut().query = query;
            self
        }
    }

    /// Encode raw bytes into a [`Query`] and assign. Bytes outside
    /// `pchar ∪ {'/', '?'}` are percent-encoded (including `#`).
    pub fn set_query_from_bytes(&mut self, query: impl IntoUriComponent) -> &mut Self {
        self.to_mut().query = Some(Query {
            bytes: encode::encode_query(query),
        });
        self
    }

    /// Consuming form of [`set_query_from_bytes`](Self::set_query_from_bytes).
    #[must_use]
    pub fn with_query_from_bytes(mut self, query: impl IntoUriComponent) -> Self {
        self.set_query_from_bytes(query);
        self
    }

    /// Returns a [`QueryMut`] guard for incremental query mutation —
    /// `push_pair`, `push_key`, `pop`, `drain`.
    pub fn query_mut(&mut self) -> QueryMut<'_> {
        QueryMut::new(self.to_mut())
    }

    /// Set the scheme. Accepts any [`Into<Protocol>`] — most usefully
    /// [`Protocol`](crate::Protocol) itself, but also `&str` / `String`
    /// (via the existing `Protocol::From<&str>` chain that's used
    /// throughout rama's HTTP / SOCKS5 / TLS plumbing).
    ///
    /// The scheme is a presentation-only component for the parsed URI
    /// — `canonicalize` lowercases custom schemes per RFC 3986
    /// §6.2.2.1, known schemes (`http`, `https`, `ws`, `wss`,
    /// `socks5`, `socks5h`) are already case-normalised at construction.
    pub fn set_scheme(&mut self, scheme: impl Into<crate::Protocol>) -> &mut Self {
        let scheme = scheme.into();
        self.to_mut().scheme = Some(scheme);
        self
    }

    /// Consuming form of [`set_scheme`](Self::set_scheme).
    #[must_use]
    pub fn with_scheme(mut self, scheme: impl Into<crate::Protocol>) -> Self {
        self.set_scheme(scheme);
        self
    }

    /// Clear the scheme — turns an absolute-form URI into a
    /// relative-reference. Shortcut for the `None` arm of
    /// [`maybe_set_scheme`](Self::maybe_set_scheme).
    pub fn unset_scheme(&mut self) -> &mut Self {
        self.to_mut().scheme = None;
        self
    }

    /// Consuming form of [`unset_scheme`](Self::unset_scheme).
    #[must_use]
    pub fn without_scheme(mut self) -> Self {
        self.unset_scheme();
        self
    }

    /// Set or clear the scheme in one call. `Some(scheme)` is equivalent
    /// to [`set_scheme`](Self::set_scheme); `None` is equivalent to
    /// [`unset_scheme`](Self::unset_scheme).
    pub fn maybe_set_scheme(&mut self, scheme: impl Into<Option<crate::Protocol>>) -> &mut Self {
        self.to_mut().scheme = scheme.into();
        self
    }

    /// Consuming form of [`maybe_set_scheme`](Self::maybe_set_scheme).
    #[must_use]
    pub fn maybe_with_scheme(mut self, scheme: impl Into<Option<crate::Protocol>>) -> Self {
        self.maybe_set_scheme(scheme);
        self
    }

    // ---- Canonicalization (RFC 3986 §6.2.2) ------------------------------

    /// Apply RFC 3986 §6.2.2 syntax-based normalization. Returns a new
    /// [`Uri`] with:
    ///
    /// - Host promoted from [`Host::Uninterpreted`](crate::address::Host)
    ///   to typed [`Domain`](crate::address::Domain) / [`IpAddr`](std::net::IpAddr) when the
    ///   bytes decode to one (`%6D` → `m`; pct-encoded UTF-8 → IDN→ACE
    ///   under the `idna` feature). Sub-delim reg-name and IPvFuture
    ///   stay `Uninterpreted` — no canonical typed form exists.
    /// - Pct-encoded octets that map to unreserved characters
    ///   (`%41` → `A`, `%7E` → `~`) decoded in path / query / fragment.
    ///   Reserved / sub-delim octets stay encoded; their hex digits are
    ///   uppercased per §6.2.2.1.
    /// - Default port dropped (`http://example.com:80/` → `http://example.com/`).
    /// - Empty path replaced with `/` when an authority is present.
    /// - Dot-segments (`.`, `..`) removed from the path per §6.2.2.3.
    ///
    /// **Wire-fidelity is lost.** Use this when you specifically want a
    /// canonical form — typically client-side, building HTTP requests
    /// from user input. Server / proxy / forwarding code that needs to
    /// preserve received bytes should leave the URI unmodified.
    #[must_use]
    pub fn canonicalize(self) -> Self {
        canonicalize::canonicalize_uri(self)
    }

    /// Parse `input` and immediately apply [`canonicalize`](Self::canonicalize).
    /// One-shot convenience for client-side URI construction from user
    /// input.
    pub fn parse_canonical<T: IntoUriInput>(input: T) -> Result<Self, ParseError> {
        Self::parse(input).map(Self::canonicalize)
    }

    /// Strict variant of [`parse_canonical`](Self::parse_canonical) —
    /// rejects RFC 3986 grammar violations before canonicalizing.
    pub fn parse_canonical_strict<T: IntoUriInput>(input: T) -> Result<Self, ParseError> {
        Self::parse_strict(input).map(Self::canonicalize)
    }

    // ---- Reference resolution (RFC 3986 §5.2) ----------------------------

    /// Resolve `reference` against `self` (the base URI).
    ///
    /// Graceful — matches browser / curl behaviour:
    /// - If the reference shares the base's scheme, the scheme is
    ///   treated as inherited (RFC 3986 §5.2.2 non-strict loophole).
    /// - Excess `..` segments past the path root are silently clamped.
    ///
    /// Use [`resolve_strict`](Self::resolve_strict) to reject both.
    ///
    /// Errors when the base has no scheme, the base or reference is
    /// the asterisk-form, or the resolved URI exceeds the internal cap.
    pub fn resolve(&self, reference: &Self) -> Result<Self, ResolveError> {
        resolve::resolve(self, reference, resolve::ResolveMode::Graceful)
    }

    /// Resolve `reference` against `self` in strict mode (RFC 3986 §5.2.2):
    /// - No scheme-matching loophole — a reference with a scheme stays
    ///   absolute even if its scheme matches the base's.
    /// - A `..` segment that would traverse past the path root is an
    ///   error ([`ResolveError::DotSegmentTraversalPastRoot`]).
    pub fn resolve_strict(&self, reference: &Self) -> Result<Self, ResolveError> {
        resolve::resolve(self, reference, resolve::ResolveMode::Strict)
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the fragment. Leading `#` is implicit. Bytes outside
        /// `pchar ∪ {'/', '?'}` are percent-encoded.
        pub fn fragment(mut self, fragment: impl IntoUriComponent) -> Self {
            self.to_mut().fragment = Some(Fragment {
                bytes: encode::encode_fragment(fragment),
            });
            self
        }
    }

    /// Remove the fragment entirely (no `#` on the wire — distinct from
    /// an empty-fragment `#` per §3.5).
    pub fn unset_fragment(&mut self) -> &mut Self {
        self.to_mut().fragment = None;
        self
    }

    /// Consuming form of [`unset_fragment`](Self::unset_fragment).
    #[must_use]
    pub fn without_fragment(mut self) -> Self {
        self.unset_fragment();
        self
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set or remove the authority (userinfo + host + port).
        pub fn authority(mut self, authority: Option<crate::address::Authority>) -> Self {
            self.to_mut().authority = authority;
            self
        }
    }

    /// Set just the host, preserving any existing userinfo and port.
    ///
    /// Accepts any [`Into<Host>`] — [`Host`](crate::address::Host),
    /// [`Domain`](crate::address::Domain), [`IpAddr`](std::net::IpAddr),
    /// [`Ipv4Addr`](std::net::Ipv4Addr), or
    /// [`Ipv6Addr`](std::net::Ipv6Addr). For inputs that need
    /// parsing (`&str` / `String`), use
    /// [`try_set_host`](Self::try_set_host) instead.
    ///
    /// If the URI has no authority yet, one is created with the given
    /// host and no userinfo / port. Existing authority parts are
    /// preserved otherwise.
    pub fn set_host(&mut self, host: impl Into<crate::address::Host>) -> &mut Self {
        let host = host.into();
        let owned = self.to_mut();
        match &mut owned.authority {
            Some(authority) => {
                authority.address.host = host;
            }
            None => {
                owned.authority = Some(crate::address::Authority {
                    user_info: None,
                    address: crate::address::HostWithOptPort {
                        host,
                        port: crate::address::OptPort::Unset,
                    },
                });
            }
        }
        self
    }

    /// Consuming form of [`set_host`](Self::set_host).
    #[must_use]
    pub fn with_host(mut self, host: impl Into<crate::address::Host>) -> Self {
        self.set_host(host);
        self
    }

    /// Fallible host setter. Accepts any [`TryInto<Host>`] — typically
    /// `&str` / `String` / `&[u8]` / [`Vec<u8>`].
    ///
    /// Routes through [`Host::try_from`](crate::address::Host) which
    /// does IP-first, then [`Domain::try_from`](crate::address::Domain)
    /// (IDN-normalising non-ASCII to ACE under the `idna` feature). So
    /// `try_set_host("münchen.de")` ends up with a canonical
    /// `Host::Name(Domain("xn--mnchen-3ya.de"))` — exactly what
    /// client-side code building URIs from user input expects.
    ///
    /// Returns [`UriError::ComponentConversion`] tagged with
    /// [`Component::Host`] when the upstream conversion fails — the
    /// inner boxed cause carries the original error.
    pub fn try_set_host<H>(&mut self, host: H) -> Result<&mut Self, UriError>
    where
        H: TryInto<crate::address::Host>,
        H::Error: Into<rama_core::error::BoxError>,
    {
        let host: crate::address::Host =
            host.try_into().map_err(|e| UriError::ComponentConversion {
                component: Component::Host,
                cause: e.into(),
            })?;
        Ok(self.set_host(host))
    }

    /// Consuming form of [`try_set_host`](Self::try_set_host).
    pub fn try_with_host<H>(mut self, host: H) -> Result<Self, UriError>
    where
        H: TryInto<crate::address::Host>,
        H::Error: Into<rama_core::error::BoxError>,
    {
        self.try_set_host(host)?;
        Ok(self)
    }

    /// Set just the port, preserving the rest of the authority.
    ///
    /// `Some(port)` sets the explicit port; `None` clears any
    /// existing `:port` suffix (scheme default ports are not
    /// substituted — they remain implicit). If the URI has no
    /// authority yet, one is created with the loopback IPv4 host
    /// as a placeholder — callers building a URI from scratch should
    /// set the host before the port for clarity.
    pub fn set_port(&mut self, port: impl Into<crate::address::OptPort>) -> &mut Self {
        let port = port.into();
        let owned = self.to_mut();
        match &mut owned.authority {
            Some(authority) => {
                authority.address.port = port;
            }
            None => {
                owned.authority = Some(crate::address::Authority {
                    user_info: None,
                    address: crate::address::HostWithOptPort {
                        host: crate::address::Host::LOCALHOST_IPV4,
                        port,
                    },
                });
            }
        }
        self
    }

    /// Consuming form of [`set_port`](Self::set_port).
    #[must_use]
    pub fn with_port(mut self, port: impl Into<crate::address::OptPort>) -> Self {
        self.set_port(port);
        self
    }

    /// Set just the user-info, preserving the rest of the authority.
    ///
    /// `Some(user_info)` sets the `user[:pass]@` prefix; `None` clears
    /// any existing user-info. If the URI has no authority yet, one is
    /// created with the loopback IPv4 host as a placeholder — see
    /// [`set_port`](Self::set_port) for the same caveat.
    pub fn set_user_info(
        &mut self,
        user_info: impl Into<Option<crate::address::UserInfo>>,
    ) -> &mut Self {
        let user_info = user_info.into();
        let owned = self.to_mut();
        match &mut owned.authority {
            Some(authority) => {
                authority.user_info = user_info;
            }
            None => {
                owned.authority = Some(crate::address::Authority {
                    user_info,
                    address: crate::address::HostWithOptPort {
                        host: crate::address::Host::LOCALHOST_IPV4,
                        port: crate::address::OptPort::Unset,
                    },
                });
            }
        }
        self
    }

    /// Consuming form of [`set_user_info`](Self::set_user_info).
    #[must_use]
    pub fn with_user_info(
        mut self,
        user_info: impl Into<Option<crate::address::UserInfo>>,
    ) -> Self {
        self.set_user_info(user_info);
        self
    }

    /// Clear the user-info. Shortcut for `set_user_info(None)`.
    pub fn unset_user_info(&mut self) -> &mut Self {
        self.set_user_info(None)
    }

    /// Consuming form of [`unset_user_info`](Self::unset_user_info).
    #[must_use]
    pub fn without_user_info(mut self) -> Self {
        self.unset_user_info();
        self
    }

    /// Fallible user-info setter. Accepts any [`TryInto<UserInfo>`] —
    /// typically `&str` / `String`. Routes through
    /// [`UserInfo::try_from`](crate::address::UserInfo) which enforces
    /// the RFC 3986 §3.2.1 userinfo grammar.
    pub fn try_set_user_info<U>(&mut self, user_info: U) -> Result<&mut Self, UriError>
    where
        U: TryInto<crate::address::UserInfo>,
        U::Error: Into<rama_core::error::BoxError>,
    {
        let user_info: crate::address::UserInfo =
            user_info
                .try_into()
                .map_err(|e| UriError::ComponentConversion {
                    component: Component::UserInfo,
                    cause: e.into(),
                })?;
        Ok(self.set_user_info(Some(user_info)))
    }

    /// Consuming form of [`try_set_user_info`](Self::try_set_user_info).
    pub fn try_with_user_info<U>(mut self, user_info: U) -> Result<Self, UriError>
    where
        U: TryInto<crate::address::UserInfo>,
        U::Error: Into<rama_core::error::BoxError>,
    {
        self.try_set_user_info(user_info)?;
        Ok(self)
    }
}

// `FromStr` and `TryFrom<…>` both route through [`Uri::parse`]. `FromStr`
// is the entry generic code (e.g. clap argument parsers) uses; `TryFrom`
// is the standard idiom `Uri::try_from(input)?` and gives consistency
// with `Host`, `Authority`, `Domain` which also expose `TryFrom`.
impl std::str::FromStr for Uri {
    type Err = ParseError;

    #[inline(always)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

macro_rules! uri_try_from {
    ($($t:ty),* $(,)?) => {
        $(
            impl TryFrom<$t> for Uri {
                type Error = ParseError;
                #[inline(always)]
                fn try_from(input: $t) -> Result<Self, Self::Error> {
                    Self::parse(input)
                }
            }
        )*
    };
}

uri_try_from!(&str, String, &[u8], Vec<u8>, rama_core::bytes::Bytes,);

// Serde routes through `Display` / `Uri::parse`. Graceful mode on the
// deserialize side matches the input grace of every other rama type that
// implements `Deserialize` via `FromStr`. URIs constructed via
// [`Uri::parse_authority_form`] or [`Uri::parse_reference`] are out of
// scope for round-trip — those forms aren't reachable through `parse`.
use rama_utils::macros::serde_str::impl_serde_str;

impl_serde_str!(display Uri);

impl Uri {
    /// Shared walker for [`Display`](std::fmt::Display) and
    /// [`Debug`](std::fmt::Debug). With `redact_userinfo = true` the
    /// password portion of any userinfo (everything after the first `:`
    /// inside the userinfo bytes) is emitted as `"***"`; with `false`
    /// the URI is rendered wire-faithfully.
    ///
    /// Single source of truth so the two trait impls cannot diverge on
    /// component ordering or delimiter choices.
    fn fmt_uri(&self, f: &mut std::fmt::Formatter<'_>, redact_userinfo: bool) -> std::fmt::Result {
        match &self.inner {
            UriInner::Asterisk => f.write_str("*"),
            UriInner::Lazy(arc) => {
                // Safety: parser invariant — the source buffer is valid UTF-8
                // (graceful mode) or ASCII (strict mode).
                let s = unsafe { std::str::from_utf8_unchecked(&arc.bytes) };
                if redact_userinfo
                    && let Some(auth) = &arc.authority
                    && let Some((u_s, u_e)) = auth.userinfo_range
                {
                    f.write_str(&s[..u_s as usize])?;
                    write_redacted_userinfo(&s[u_s as usize..u_e as usize], f)?;
                    return f.write_str(&s[u_e as usize..]);
                }
                f.write_str(s)
            }
            UriInner::Owned(arc) => {
                if let Some(scheme) = &arc.scheme {
                    write!(f, "{scheme}:")?;
                }
                if let Some(auth) = &arc.authority {
                    f.write_str("//")?;
                    if let Some(ui) = &auth.user_info {
                        if redact_userinfo {
                            write_redacted_userinfo(ui.as_str(), f)?;
                        } else {
                            write!(f, "{ui}")?;
                        }
                        f.write_str("@")?;
                    }
                    write!(f, "{}", auth.address)?;
                }

                write!(
                    f,
                    "{}",
                    PathRef::from_raw_str({
                        // Safety: parser invariant on the path bytes.
                        unsafe { std::str::from_utf8_unchecked(&arc.path) }
                    })
                )?;

                if let Some(query) = &arc.query {
                    write!(f, "?{query}")?;
                }

                if let Some(fragment) = &arc.fragment {
                    write!(f, "#{fragment}")?;
                }

                Ok(())
            }
        }
    }
}

/// Emit `user:***` (or just `user` if no `:` is present) — shared by
/// [`Uri::fmt_uri`]'s Debug branch and any other site that wants the
/// inline-URI redaction shape (distinct from the structured
/// `UserInfo` `Debug` rendering, which uses `debug_struct`).
fn write_redacted_userinfo(s: &str, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match s.bytes().position(|b| b == b':') {
        Some(i) => write!(f, "{}:***", &s[..i]),
        None => f.write_str(s),
    }
}

impl std::fmt::Display for Uri {
    /// Writes the canonical URI string: `[scheme:][//authority][path][?query][#fragment]`.
    /// `Lazy` URIs round-trip byte-for-byte through their source buffer; `Owned`
    /// URIs reassemble from components.
    ///
    /// **Not the HTTP wire form.** This includes userinfo and fragment and
    /// preserves the original port — none of which belong on an HTTP request
    /// line or in HTTP/2 pseudo-headers. Use the dedicated `write_*_form`
    /// helpers (landing with the relative-resolution work) when serializing
    /// for HTTP. Logging a [`Uri`] via [`Display`](std::fmt::Display) may leak
    /// userinfo — use [`Debug`](std::fmt::Debug) (password-redacted) if the
    /// destination is a tracing sink, or strip the userinfo explicitly.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_uri(f, false)
    }
}

impl std::fmt::Debug for Uri {
    /// `Uri("…")` rendering of the canonical URI form, with the
    /// password portion of any userinfo redacted as `***`. See the
    /// type-level "Logging safety" docs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Uri(\"")?;
        self.fmt_uri(f, true)?;
        f.write_str("\")")
    }
}

// ---- PartialEq / Eq / Hash / Ord — structural over components -------------
//
// All four impls compare the URI's *components* (scheme, authority,
// path, query, fragment) directly through the public accessors. The
// accessors return cheap borrowed views (`Option<&Protocol>`,
// `Option<AuthorityRef>`, `Option<PathRef>`, …) whose own Eq/Hash/Ord
// impls carry the right RFC 3986 semantics — case-insensitive on scheme
// + host (§6.2.2.1), pct-encoded/decoded equivalence on host bytes
// (§6.2.2.2 — via `UninterpretedHostRef` and `DomainRef`), strict on
// userinfo / path / query / fragment.
//
// Zero allocation per call: no Display materialization, no string
// scratch buffers. Identity fast paths (same `Asterisk` tag, or
// `Arc::ptr_eq` on the inner Arcs) skip the component walk in the
// common "comparing against self / a clone" case.
//
// **Not** raw wire-bytes equality. Two URIs that Display differently
// can still compare equal here — e.g. `https://EXAMPLE.com/` and
// `https://example.com/` are equal under §6.2.2.1 case normalisation.
// If you need stricter byte-by-byte equality, compare the rendered
// `Display` strings explicitly.

impl PartialEq for Uri {
    fn eq(&self, other: &Self) -> bool {
        match (&self.inner, &other.inner) {
            (UriInner::Asterisk, UriInner::Asterisk) => return true,
            (UriInner::Asterisk, _) | (_, UriInner::Asterisk) => return false,
            (UriInner::Lazy(a), UriInner::Lazy(b)) if Arc::ptr_eq(a, b) => return true,
            (UriInner::Owned(a), UriInner::Owned(b)) if Arc::ptr_eq(a, b) => return true,
            _ => {}
        }
        // Component-by-component. All sub-types are `Copy` + `Eq` so
        // this stays allocation-free on every path.
        self.scheme() == other.scheme()
            && self.authority() == other.authority()
            && self.path() == other.path()
            && self.query() == other.query()
            && self.fragment() == other.fragment()
    }
}

impl Eq for Uri {}

/// `Uri::default()` is the implicit origin-form `/`, matching `http::Uri`.
impl Default for Uri {
    fn default() -> Self {
        Self::from_static("/")
    }
}

// String equality compares the canonical (`Display`/`as_str`) form. A native
// `Uri` round-trips its source faithfully, so this is a plain string compare
// (allocation-free on the borrowed path).
impl PartialEq<str> for Uri {
    fn eq(&self, other: &str) -> bool {
        *self.as_str() == *other
    }
}
impl PartialEq<&str> for Uri {
    fn eq(&self, other: &&str) -> bool {
        *self.as_str() == **other
    }
}
impl PartialEq<String> for Uri {
    fn eq(&self, other: &String) -> bool {
        *self.as_str() == **other
    }
}

impl Ord for Uri {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        // Lex order over `(scheme, authority, path, query, fragment)`.
        // Matches the natural URI grammar order so sort output reads
        // intuitively (`a.example/p < b.example/p`, `…/a < …/b`, …).
        match (&self.inner, &other.inner) {
            (UriInner::Asterisk, UriInner::Asterisk) => return Ordering::Equal,
            // Asterisk has no scheme/authority/path — sort it before
            // anything else by treating it as a unique smallest value.
            (UriInner::Asterisk, _) => return Ordering::Less,
            (_, UriInner::Asterisk) => return Ordering::Greater,
            _ => {}
        }
        self.scheme()
            .cmp(&other.scheme())
            .then_with(|| self.authority().cmp(&other.authority()))
            .then_with(|| self.path().cmp(&other.path()))
            .then_with(|| self.query().cmp(&other.query()))
            .then_with(|| self.fragment().cmp(&other.fragment()))
    }
}

impl PartialOrd for Uri {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for Uri {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // A discriminant byte per "section" so a present-but-empty query
        // (`Some(empty)`) doesn't hash the same as no query at all
        // (`None`), and so `Uri("?")` ≠ `Uri("#")`. All other distinctness
        // comes from the sub-type Hash impls below.
        match &self.inner {
            UriInner::Asterisk => {
                state.write_u8(0);
                return;
            }
            UriInner::Lazy(_) | UriInner::Owned(_) => state.write_u8(1),
        }
        self.scheme().hash(state);
        self.authority().hash(state);
        self.path().hash(state);
        // Tag query/fragment presence explicitly so Option::hash's own
        // discriminant stays consistent across Lazy/Owned (Option<T>::hash
        // already does this, but pinning a marker future-proofs against
        // any subtype Hash impl that might forget to length-disambiguate).
        match self.query() {
            Some(q) => {
                state.write_u8(0xff);
                q.hash(state);
            }
            None => state.write_u8(0),
        }
        match self.fragment() {
            Some(f) => {
                state.write_u8(0xff);
                f.hash(state);
            }
            None => state.write_u8(0),
        }
    }
}

// ---- UriRef: borrowed snapshot of a `Uri` -------------------------------

/// Borrowed snapshot of a [`Uri`]'s components.
///
/// A single match-once walk caches `Option<&Protocol>`,
/// `Option<AuthorityRef<'_>>`, `Option<PathRef<'_>>`,
/// `Option<QueryRef<'_>>`, and `Option<FragmentRef<'_>>` so downstream
/// code that wants to inspect several components without re-walking
/// the `UriInner` enum per accessor gets them in one shot. The
/// asterisk-form is preserved as a single boolean — every component
/// accessor on an asterisk view returns `None`.
///
/// `Display` and `Debug` delegate back through the `Uri` they were
/// minted from, so logging surface is identical.
#[derive(Debug, Clone, Copy)]
pub struct UriRef<'a> {
    /// The source URI — used by `Display`/`Debug` to render. All other
    /// accessors read from the cached component fields directly so
    /// they're branch-free (one struct-field load instead of a
    /// per-call `match` on `UriInner`).
    source: &'a Uri,
    scheme: Option<&'a crate::Protocol>,
    authority: Option<crate::address::AuthorityRef<'a>>,
    path: Option<PathRef<'a>>,
    query: Option<QueryRef<'a>>,
    fragment: Option<FragmentRef<'a>>,
    is_asterisk: bool,
}

impl<'a> UriRef<'a> {
    /// Returns the scheme component, or `None` for origin-form /
    /// asterisk-form URIs.
    #[must_use]
    #[inline]
    pub const fn scheme(&self) -> Option<&'a crate::Protocol> {
        self.scheme
    }

    /// Returns the authority bundle (host + port + userinfo), or
    /// `None` for asterisk-form / opaque-path / origin-form URIs.
    #[must_use]
    #[inline]
    pub const fn authority(&self) -> Option<crate::address::AuthorityRef<'a>> {
        self.authority
    }

    /// Returns the path component, or `None` for asterisk-form
    /// (which has no path — the request-target *is* `*`).
    #[must_use]
    #[inline]
    pub const fn path(&self) -> Option<PathRef<'a>> {
        self.path
    }

    /// Returns the query component, or `None` if the URI has no `?`.
    #[must_use]
    #[inline]
    pub const fn query(&self) -> Option<QueryRef<'a>> {
        self.query
    }

    /// Returns the fragment component, or `None` if the URI has no `#`.
    #[must_use]
    #[inline]
    pub const fn fragment(&self) -> Option<FragmentRef<'a>> {
        self.fragment
    }

    /// Returns the host shortcut, or `None` if no authority.
    #[must_use]
    #[inline]
    pub fn host(&self) -> Option<crate::address::HostRef<'a>> {
        self.authority.map(|a| a.host())
    }

    /// Returns the port as an [`OptPort`](crate::address::OptPort).
    /// **Most callers want [`port_u16`](Self::port_u16)** — it returns
    /// `Option<u16>` and collapses the wire-only `Empty` distinction.
    #[must_use]
    #[inline]
    pub fn port(&self) -> crate::address::OptPort {
        self.authority
            .map(|a| a.port())
            .unwrap_or(crate::address::OptPort::Unset)
    }

    /// Relaxed view of the port — `Set(n) → Some(n)`, everything else
    /// `None`. Use when the `Unset` vs `Empty` distinction doesn't matter.
    #[must_use]
    #[inline]
    pub fn port_u16(&self) -> Option<u16> {
        self.port().as_u16()
    }

    /// Returns the userinfo shortcut, or `None` if no authority OR
    /// no `@` on the wire.
    #[must_use]
    #[inline]
    pub fn userinfo(&self) -> Option<crate::address::UserInfoRef<'a>> {
        self.authority.and_then(|a| a.userinfo())
    }

    /// Returns `true` for the OPTIONS-`*` request-target.
    #[must_use]
    #[inline]
    pub const fn is_asterisk(&self) -> bool {
        self.is_asterisk
    }

    /// Returns `true` if the URI has a scheme (absolute URI per
    /// RFC 3986 §4.3).
    #[must_use]
    #[inline]
    pub const fn is_absolute(&self) -> bool {
        self.scheme.is_some()
    }

    /// Promote this borrowed view to an owned [`Uri`] — cheap, just
    /// clones the source `Uri` (which is Arc-backed).
    #[must_use]
    #[inline]
    pub fn into_owned(self) -> Uri {
        self.source.clone()
    }
}

impl std::fmt::Display for UriRef<'_> {
    /// Renders the canonical URI string — same output as the source
    /// [`Uri`]'s `Display`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.source, f)
    }
}

impl Uri {
    /// Borrow this URI as a [`UriRef`] — a single match-once snapshot
    /// of every component accessor.
    ///
    /// Most useful for code that inspects three-or-more components in
    /// a row: each `Uri::scheme()` / `host()` / `path()` etc. re-walks
    /// the internal `match &self.inner { … }` per call; `view()` does
    /// the walk once and exposes the results as struct fields.
    #[must_use]
    pub fn view(&self) -> UriRef<'_> {
        UriRef {
            source: self,
            scheme: self.scheme(),
            authority: self.authority(),
            path: self.path(),
            query: self.query(),
            fragment: self.fragment(),
            is_asterisk: self.is_asterisk(),
        }
    }
}

#[cfg(test)]
mod request_target_fix_tests {
    use super::*;

    #[test]
    fn asterisk_request_target_is_star_not_root() {
        let uri = Uri::parse("*").unwrap();
        assert!(uri.is_asterisk());
        assert_eq!(uri.request_target(), "*");
    }

    #[test]
    fn origin_form_request_target_unchanged() {
        assert_eq!(Uri::parse("/a?b=c").unwrap().request_target(), "/a?b=c");
        assert_eq!(Uri::parse("/a").unwrap().request_target(), "/a");
    }
}

#[cfg(test)]
mod from_authority_form_tests {
    use super::*;
    use crate::address::Authority;

    /// `from_authority_form(auth)` must produce exactly what
    /// `parse_authority_form(auth.to_string())` would — same wire form, same
    /// decomposed components — but without re-parsing.
    #[test]
    fn matches_parse_authority_form() {
        for s in [
            "example.com:443",
            "example.com",
            "user:pass@example.com:8080",
            "user@host.example",
            "[::1]:443",
            "[2001:db8::1]",
            "127.0.0.1:80",
        ] {
            let auth = Authority::try_from(s).unwrap();
            let canonical = auth.to_string();
            let from_ctor = Uri::from_authority_form(auth);
            let from_parse = Uri::parse_authority_form(canonical.as_str()).unwrap();

            assert_eq!(
                from_ctor.to_string(),
                from_parse.to_string(),
                "wire form: {s}"
            );
            // authority-form, never network-path — no `//` prefix.
            assert!(!from_ctor.to_string().starts_with("//"), "no `//`: {s}");
            assert_eq!(from_ctor.host(), from_parse.host(), "host: {s}");
            assert_eq!(from_ctor.port(), from_parse.port(), "port: {s}");
            assert_eq!(
                from_ctor.userinfo().map(|u| u.to_string()),
                from_parse.userinfo().map(|u| u.to_string()),
                "userinfo: {s}"
            );
            assert!(from_ctor.scheme().is_none(), "no scheme: {s}");
        }
    }
}

#[cfg(test)]
mod from_authority_tests {
    use super::*;
    use crate::Protocol;
    use crate::address::{Authority, Domain, Host};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// `from_authority(scheme, auth)` must be byte-identical to parsing the
    /// equivalent `scheme://authority` absolute form — same wire output and
    /// same decomposed components — but without re-parsing.
    #[test]
    fn matches_parse_of_absolute_form() {
        for (auth_str, expected) in [
            ("example.com", "http://example.com"),
            ("example.com:8080", "http://example.com:8080"),
            ("user@example.com", "http://user@example.com"),
            (
                "user:pass@example.com:8080",
                "http://user:pass@example.com:8080",
            ),
            ("127.0.0.1:80", "http://127.0.0.1:80"),
            ("[::1]:443", "http://[::1]:443"),
            ("[2001:db8::1]", "http://[2001:db8::1]"),
        ] {
            let auth = Authority::try_from(auth_str).unwrap();
            let from_ctor = Uri::from_authority(Protocol::HTTP, auth);
            let from_parse = Uri::parse(expected).unwrap();

            assert_eq!(from_ctor.to_string(), expected, "wire form: {auth_str}");
            assert_eq!(
                from_ctor.to_string(),
                from_parse.to_string(),
                "parse parity: {auth_str}"
            );
            assert!(from_ctor.is_absolute(), "absolute: {auth_str}");
            assert_eq!(
                from_ctor.scheme_str(),
                from_parse.scheme_str(),
                "scheme: {auth_str}"
            );
            assert_eq!(
                from_ctor.host_str(),
                from_parse.host_str(),
                "host: {auth_str}"
            );
            assert_eq!(from_ctor.port(), from_parse.port(), "port: {auth_str}");
            assert_eq!(
                from_ctor.userinfo().map(|u| u.to_string()),
                from_parse.userinfo().map(|u| u.to_string()),
                "userinfo: {auth_str}"
            );
            // Authority-only absolute URI: empty path, no query / fragment.
            assert_eq!(
                from_ctor.path().map(|p| p.as_encoded_str()),
                from_parse.path().map(|p| p.as_encoded_str()),
                "path: {auth_str}"
            );
            assert!(from_ctor.query().is_none(), "query: {auth_str}");
            assert!(from_ctor.fragment().is_none(), "fragment: {auth_str}");
        }
    }

    /// Anything convertible into an [`Authority`] is accepted — bare domain /
    /// IP / host values (no port) plus `(host, port)` tuples and `SocketAddr`.
    #[test]
    fn accepts_into_authority_inputs() {
        assert_eq!(
            Uri::from_authority(Protocol::HTTP, Domain::from_static("example.com")).to_string(),
            "http://example.com"
        );
        assert_eq!(
            Uri::from_authority(Protocol::HTTPS, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
                .to_string(),
            "https://127.0.0.1"
        );
        assert_eq!(
            Uri::from_authority(Protocol::HTTP, Ipv4Addr::new(10, 0, 0, 1)).to_string(),
            "http://10.0.0.1"
        );
        assert_eq!(
            Uri::from_authority(Protocol::HTTP, Ipv6Addr::LOCALHOST).to_string(),
            "http://[::1]"
        );
        assert_eq!(
            Uri::from_authority(Protocol::HTTP, Host::Name(Domain::from_static("h.example")))
                .to_string(),
            "http://h.example"
        );
        assert_eq!(
            Uri::from_authority(
                Protocol::HTTP,
                (Domain::from_static("example.com"), 8080u16)
            )
            .to_string(),
            "http://example.com:8080"
        );
        let addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            Uri::from_authority(Protocol::HTTPS, addr).to_string(),
            "https://127.0.0.1:8080"
        );
    }

    /// Works for any URI scheme, not just HTTP.
    #[test]
    fn supports_custom_and_non_http_schemes() {
        let redis = Protocol::try_from("redis").unwrap();
        assert_eq!(
            Uri::from_authority(redis, Authority::try_from("localhost:6379").unwrap()).to_string(),
            "redis://localhost:6379"
        );
        assert_eq!(
            Uri::from_authority(Protocol::WSS, Domain::from_static("example.com")).to_string(),
            "wss://example.com"
        );
    }

    /// `try_from_authority` parses string hosts (the `format!("http://{s}")`
    /// replacement) and surfaces a tagged error on invalid input.
    #[test]
    fn try_from_authority_parses_strings() {
        assert_eq!(
            Uri::try_from_authority(Protocol::HTTP, "example.com")
                .unwrap()
                .to_string(),
            "http://example.com"
        );
        assert_eq!(
            Uri::try_from_authority(Protocol::HTTPS, "user@example.com:8080")
                .unwrap()
                .to_string(),
            "https://user@example.com:8080"
        );
        assert_eq!(
            Uri::try_from_authority(Protocol::HTTP, String::from("[::1]:443"))
                .unwrap()
                .to_string(),
            "http://[::1]:443"
        );

        let err = Uri::try_from_authority(Protocol::HTTP, ":80").unwrap_err();
        assert!(
            matches!(
                err,
                UriError::ComponentConversion {
                    component: Component::Authority,
                    ..
                }
            ),
            "expected ComponentConversion(Authority), got {err:?}"
        );
    }

    /// The constructed URI is the cheap lazy form and stays mutable through
    /// the normal builder API (promotes to owned on first mutation).
    #[test]
    fn is_mutable_after_construction() {
        let uri = Uri::from_authority(Protocol::HTTP, Domain::from_static("example.com"))
            .with_path("/v1/ping")
            .with_query_from_bytes("a=1");
        assert_eq!(uri.to_string(), "http://example.com/v1/ping?a=1");
    }
}

#[cfg(test)]
mod encode_to_tests {
    use super::*;

    /// `encode_to` writes the wire-faithful full form, so its output must
    /// equal `Display` for every URI shape and representation.
    #[test]
    fn encode_to_matches_display() {
        let lazy = [
            Uri::parse("/path?q=1").unwrap(),
            Uri::parse("https://user@example.com:8443/a/b?c#frag").unwrap(),
            Uri::from_authority_form(
                crate::address::Authority::try_from("example.com:443").unwrap(),
            ),
            Uri::parse("*").unwrap(),
            Uri::from_static("http://example.com/"),
        ];
        for uri in lazy {
            let mut buf = Vec::new();
            uri.encode_to(&mut buf);
            assert_eq!(buf, uri.to_string().as_bytes(), "uri: {uri}");
        }

        // Mutated (Owned) representation still round-trips.
        let owned = Uri::parse("http://example.com/p?x#f")
            .unwrap()
            .with_port(8080u16);
        let mut buf = Vec::new();
        owned.encode_to(&mut buf);
        assert_eq!(buf, owned.to_string().as_bytes());
    }
}
