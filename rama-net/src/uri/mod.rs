//! First-class URI support for rama.
//!
//! This module hosts the rama-native URI type. It works for **any RFC 3986
//! URI** — http(s), ws(s), ftp, mailto:, urn:, file:, custom schemes — not
//! just HTTP. HTTP-specific shapes (e.g. asterisk-form `*` from RFC 9112
//! §3.2.4) are supported but called out as such.
//!
//! Graceful by default, lossless on parse (no silent normalization),
//! supports all four HTTP request-target forms (origin, absolute,
//! authority, asterisk) plus the broader RFC 3986 URI / URI-reference set,
//! preserves fragments, and lets you cheaply mutate components without
//! the `into_parts → from_parts` dance.
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
pub use query::{Query, QueryDeserializeError, QueryPair, QueryPairs, QueryRef};

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
/// Opaque — fields are private. Construct via [`Uri::parse`] /
/// [`Uri::parse_strict`]; inspect via typed accessors ([`scheme`](Self::scheme),
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

    /// Returns `true` if this is the OPTIONS-`*` request-target.
    #[must_use]
    pub fn is_asterisk(&self) -> bool {
        matches!(self.inner, UriInner::Asterisk)
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
    /// to materialise components when promoting from Lazy / Asterisk.
    fn as_owned_components(&self) -> OwnedUriRef {
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
