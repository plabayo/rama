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
//! # Design (skeleton — implementation arrives in M3–M9)
//!
//! - [`Uri`] is an **opaque** struct. Internally it holds a private
//!   `UriInner` enum:
//!
//!   ```text
//!   UriInner = Asterisk
//!            | Lazy(Arc<LazyUriRef>)
//!            | Owned(Arc<OwnedUriRef>)
//!   ```
//!
//! - **Asterisk** is the OPTIONS-`*` request-target — a separate variant so
//!   we can't represent impossible states like `*?foo=bar`.
//! - **Lazy** is the cheap-to-clone parsed-once form (single `Bytes` buffer
//!   plus offset markers and pre-parsed scalars). Reads are zero-copy.
//! - **Owned** is the mutated form. First mutation upgrades Lazy → Owned
//!   via `Arc::make_mut` + a `LazyUriRef → OwnedUriRef` conversion.
//!
//! ## What lives where
//!
//! - [`Uri`] (this file) — the opaque public type
//! - URI-component borrowed views: [`PathRef`], [`QueryRef`], [`FragmentRef`]
//! - URI-component owned mutable types: [`Query`], [`Fragment`]
//! - Errors: [`ParseError`], [`UriError`]
//!
//! Host-related borrowed views live with their owned counterparts in
//! [`crate::address`] (`HostRef`, `DomainRef`) — they have utility beyond
//! URIs (e.g. header parsing, DNS scanners).
//!
//! The `Scheme` for a `Uri` is the existing [`Protocol`](crate::Protocol);
//! the authority is the existing [`Authority`](crate::address::Authority);
//! the host is the existing [`Host`](crate::address::Host). No new
//! re-exports are added — use those types directly.

use std::sync::Arc;

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
pub use path::{PathRef, PathSegment, PathSegments};

mod path_mut;
#[doc(inline)]
pub use path_mut::PathMut;

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
mod parser;

use lazy::LazyUriRef;
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
#[derive(Debug, Clone)]
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

    /// Parse the HTTP authority-form request-target —
    /// `[userinfo@]host[:port]` only (RFC 9112 §3.2.3).
    ///
    /// This is the request-target shape used by the `CONNECT` method.
    /// It must be a dedicated entry point because [`parse`](Self::parse)
    /// cannot disambiguate it from `scheme:opaque-path` — e.g.
    /// `example.com:443` is grammatically both `authority(example.com:443)`
    /// and `scheme(example.com) + opaque-path(443)`, and RFC 3986 prefers
    /// the scheme reading. HTTP proxies and clients handling CONNECT
    /// **must** route those targets through this function instead.
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

    /// Strict variant of [`parse_authority_form`](Self::parse_authority_form).
    pub fn parse_authority_form_strict<T: IntoUriInput>(input: T) -> Result<Self, ParseError> {
        parser::parse_authority_form(input::into_uri_input(input), ParserMode::Strict)
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
            UriInner::Owned(arc) => arc.query.as_ref().map(|q| QueryRef::new(q.as_bytes())),
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
            UriInner::Owned(arc) => arc
                .fragment
                .as_ref()
                .map(|f| FragmentRef::new(f.as_bytes())),
        }
    }

    /// Returns the authority's host, or `None` if the URI has no
    /// authority (origin-form `/foo`, asterisk-form `*`, opaque-path
    /// `urn:isbn:0`, etc.).
    ///
    /// This is a shortcut for accessing just the host component;
    /// [`Uri::authority`](crate::uri::Uri) (lands with M4 (c)) gives
    /// the full bundle.
    #[must_use]
    pub fn host(&self) -> Option<crate::address::HostRef<'_>> {
        match &self.inner {
            UriInner::Asterisk => None,
            UriInner::Lazy(arc) => arc.authority.as_ref().map(|a| (&a.host).into()),
            UriInner::Owned(arc) => arc.authority.as_ref().map(|a| (&a.address.host).into()),
        }
    }

    /// Returns the authority's port, or `None` if the URI has no
    /// authority OR the authority has no explicit port.
    ///
    /// We never substitute scheme default ports here — that's a
    /// canonicalisation policy decision the caller makes (e.g.
    /// `Protocol::default_port()` if the URI's scheme is known).
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        match &self.inner {
            UriInner::Asterisk => None,
            UriInner::Lazy(arc) => arc.authority.as_ref().and_then(|a| a.port),
            UriInner::Owned(arc) => arc.authority.as_ref().and_then(|a| a.address.port),
        }
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
                .map(|ui| ui.as_ref()),
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
                let userinfo = auth.user_info.as_ref().map(|ui| ui.as_ref());
                Some(AuthorityRef::new(
                    userinfo,
                    HostRef::from(&auth.address.host),
                    auth.address.port,
                ))
            }
        }
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

    /// Returns a [`PathMut`] guard for incremental path mutation —
    /// `push_segment`, `pop_segment`, `clear`.
    pub fn path_mut(&mut self) -> PathMut<'_> {
        PathMut::new(self.to_mut())
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the query. Leading `?` is implicit. Bytes outside
        /// `pchar ∪ {'/', '?'}` are percent-encoded (including `#`).
        pub fn query(mut self, query: impl IntoUriComponent) -> Self {
            self.to_mut().query = Some(Query {
                bytes: encode::encode_query(query),
            });
            self
        }
    }

    /// Returns a [`QueryMut`] guard for incremental query mutation —
    /// `push_pair`, `push_key`, `pop`, `drain`.
    pub fn query_mut(&mut self) -> QueryMut<'_> {
        QueryMut::new(self.to_mut())
    }

    /// Assign a pre-built [`Query`] directly. The query's bytes are
    /// taken as-is, with no re-encoding — useful when collecting from
    /// an iterator (e.g. `let q: Query = pairs.collect(); uri.set_query_value(q);`).
    pub fn set_query_value(&mut self, query: Query) -> &mut Self {
        self.to_mut().query = Some(query);
        self
    }

    /// Consuming form of [`set_query_value`](Self::set_query_value).
    #[must_use]
    pub fn with_query_value(mut self, query: Query) -> Self {
        self.set_query_value(query);
        self
    }

    // ---- Canonicalization (RFC 3986 §6.2.2) ------------------------------

    /// Apply RFC 3986 §6.2.2 syntax-based normalization. Returns a new
    /// [`Uri`] with:
    ///
    /// - Host promoted from [`Host::Uninterpreted`](crate::address::Host)
    ///   to typed [`Domain`](crate::address::Domain) / [`IpAddr`] when the
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

    /// Remove the query entirely (no `?` on the wire — distinct from
    /// an empty-query `?` per §3.4).
    pub fn unset_query(&mut self) -> &mut Self {
        self.to_mut().query = None;
        self
    }

    /// Consuming form of [`unset_query`](Self::unset_query).
    #[must_use]
    pub fn without_query(mut self) -> Self {
        self.unset_query();
        self
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
        /// Set or remove the scheme. Removing yields a relative
        /// reference — origin-form when the authority is also absent.
        pub fn scheme(mut self, scheme: Option<crate::Protocol>) -> Self {
            self.to_mut().scheme = scheme;
            self
        }
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
    /// [`Domain`](crate::address::Domain), [`IpAddr`],
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
                    address: crate::address::HostWithOptPort { host, port: None },
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
    pub fn try_set_host<H>(&mut self, host: H) -> Result<&mut Self, rama_core::error::BoxError>
    where
        H: TryInto<crate::address::Host>,
        H::Error: Into<rama_core::error::BoxError>,
    {
        let host: crate::address::Host = host.try_into().map_err(Into::into)?;
        Ok(self.set_host(host))
    }

    /// Consuming form of [`try_set_host`](Self::try_set_host).
    pub fn try_with_host<H>(mut self, host: H) -> Result<Self, rama_core::error::BoxError>
    where
        H: TryInto<crate::address::Host>,
        H::Error: Into<rama_core::error::BoxError>,
    {
        self.try_set_host(host)?;
        Ok(self)
    }
}

// `FromStr` kept because it's the only way to satisfy `T: FromStr`
// bounds (e.g. clap argument parsers). `TryFrom` impls are not — the
// `IntoUriInput`-bound `Uri::parse` covers the same ground with one
// function call and no `?`-ladder.
impl std::str::FromStr for Uri {
    type Err = ParseError;

    #[inline(always)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
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
    /// userinfo — strip it explicitly if that matters for your call site.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            UriInner::Asterisk => f.write_str("*"),
            UriInner::Lazy(arc) => {
                // Safety: parser invariant — the source buffer is valid UTF-8
                // (graceful mode) or ASCII (strict mode).
                f.write_str(unsafe { std::str::from_utf8_unchecked(&arc.bytes) })
            }
            UriInner::Owned(arc) => {
                if let Some(scheme) = &arc.scheme {
                    write!(f, "{scheme}:")?;
                }
                if let Some(auth) = &arc.authority {
                    write!(f, "//{auth}")?;
                }
                // Safety: parser invariant on the path bytes.
                f.write_str(unsafe { std::str::from_utf8_unchecked(&arc.path) })?;
                if let Some(query) = &arc.query {
                    write!(f, "?{}", query.as_raw_str())?;
                }
                if let Some(fragment) = &arc.fragment {
                    write!(f, "#{}", fragment.as_raw_str())?;
                }
                Ok(())
            }
        }
    }
}
