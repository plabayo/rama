//! First-class URI support for rama.
//!
//! This module hosts a rama-native URI type designed to replace `http::Uri`
//! across the rama tree. It is graceful by default, lossless on parse (no
//! silent normalization), supports all four HTTP request-target forms
//! (origin, absolute, authority, asterisk), preserves fragments, and lets
//! you cheaply mutate components without the `into_parts → from_parts`
//! dance.
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

mod error;
#[doc(inline)]
pub use error::{Component, ParseError, UriError};

mod path;
#[doc(inline)]
pub use path::PathRef;

mod query;
#[doc(inline)]
pub use query::{Query, QueryRef};

mod fragment;
#[doc(inline)]
pub use fragment::{Fragment, FragmentRef};

mod lazy;
mod owned;

use lazy::LazyUriRef;
use owned::OwnedUriRef;

/// Preserved utility submodule (re-exports the `percent_encoding` crate).
///
/// Kept for source-compat with existing consumers via the
/// `rama_net::uri::util::percent_encoding::…` path.
pub mod util {
    pub use ::percent_encoding;
}

/// First-class URI value.
///
/// Opaque — fields are private. Construct via parsers (M3) or the
/// builder (M5); inspect via typed accessors (M4); mutate via setters and
/// RAII guards (M5).
///
/// `Clone` is cheap: `Asterisk` is zero-cost, `Lazy` / `Owned` clone is one
/// atomic refcount bump on the inner `Arc`.
#[derive(Debug, Clone)]
pub struct Uri {
    inner: UriInner,
}

/// Internal representation.
///
/// Per-variant `Arc`-boxing keeps `Uri` itself small (one pointer + tag) and
/// makes the heap allocation match the actual variant's size.
#[derive(Debug, Clone)]
#[expect(
    dead_code,
    reason = "M2 skeleton: variant payloads consumed by M3 (parser) and M5 (mutation)"
)]
enum UriInner {
    /// OPTIONS `*` request-target. No other components.
    Asterisk,
    /// Parsed-once form. Cheap clone, zero-copy reads.
    Lazy(Arc<LazyUriRef>),
    /// Mutated form. Decomposed components.
    Owned(Arc<OwnedUriRef>),
}

impl Uri {
    /// Returns `true` if this is the OPTIONS-`*` request-target.
    #[must_use]
    pub fn is_asterisk(&self) -> bool {
        matches!(self.inner, UriInner::Asterisk)
    }

    /// Internal constructor for the asterisk variant. Wired up by the parser
    /// landing in M3.
    #[must_use]
    #[expect(dead_code, reason = "M2 skeleton: consumed by M3 (parser)")]
    pub(crate) fn from_asterisk() -> Self {
        Self {
            inner: UriInner::Asterisk,
        }
    }

    /// Internal constructor for the lazy variant. Wired up by the parser
    /// landing in M3.
    #[expect(dead_code, reason = "M2 skeleton: consumed by M3 (parser)")]
    pub(crate) fn from_lazy(lazy: LazyUriRef) -> Self {
        Self {
            inner: UriInner::Lazy(Arc::new(lazy)),
        }
    }

    /// Internal constructor for the owned variant. Wired up by the builder
    /// landing in M5.
    #[expect(dead_code, reason = "M2 skeleton: consumed by M5 (builder)")]
    pub(crate) fn from_owned(owned: OwnedUriRef) -> Self {
        Self {
            inner: UriInner::Owned(Arc::new(owned)),
        }
    }
}
