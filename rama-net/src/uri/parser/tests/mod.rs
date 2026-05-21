//! Parser test corpus.
//!
//! Organized by category:
//! - [`origin_form`] — request-target style `/path?q#f` (HTTP origin-form)
//! - [`absolute_form`] — full URIs `scheme:hier-part`
//! - [`non_http_schemes`] — corpus of non-HTTP URIs (urn, mailto, ftp, ws,
//!   git, ssh, redis, mongodb, coap, geo, magnet, custom)
//! - [`rfc3986_examples`] — RFC 3986 §1.1.2 canonical examples
//! - [`strict_mode`] — graceful-vs-strict difference coverage
//! - [`adversarial`] — security-class inputs (smuggling, SSRF, injection)
//! - [`smoke`] — structured-input smoke tests (deterministic random, boundary
//!   patterns) — every reachable byte must not crash either parser
//! - [`whatwg_corpus`] — runs the WHATWG URL test corpus in
//!   *crash-resistance* mode (Mode A) plus a hand-curated policy override
//!   table for the security-relevant divergences (see module docs)
//! - [`path_segments`] — `PathRef::segments()` iterator
//! - [`query_pairs`] — `QueryRef::pairs()` iterator
//! - [`query_deserialize`] — `QueryRef::deserialize` / `Query::deserialize`
//! - [`fragment`] — `FragmentRef` / `Fragment` views
//!
//! Shared helpers live in this file.

use super::super::UriInner;
use super::super::lazy::LazyUriRef;
use crate::uri::{ParseError, Uri};

pub(super) mod absolute_form;
pub(super) mod accessors;
pub(super) mod adversarial;
pub(super) mod display;
pub(super) mod fragment;
pub(super) mod mutation;
pub(super) mod non_http_schemes;
pub(super) mod origin_form;
pub(super) mod path_mut;
pub(super) mod path_segments;
pub(super) mod query_collect;
pub(super) mod query_deserialize;
pub(super) mod query_mut;
pub(super) mod query_pairs;
pub(super) mod rfc3986_examples;
pub(super) mod smoke;
pub(super) mod strict_mode;
pub(super) mod whatwg_corpus;

/// Parse in graceful mode via the public API.
pub(super) fn parse_graceful(s: &str) -> Result<Uri, ParseError> {
    Uri::parse(s)
}

/// Parse in strict mode via the public API.
pub(super) fn parse_strict(s: &str) -> Result<Uri, ParseError> {
    Uri::parse_strict(s)
}

/// Parse from raw bytes. Used by smoke and corpus runners feeding
/// arbitrary byte sequences (incl. non-UTF-8).
pub(super) fn parse_graceful_bytes(b: &[u8]) -> Result<Uri, ParseError> {
    Uri::parse(b)
}

pub(super) fn parse_strict_bytes(b: &[u8]) -> Result<Uri, ParseError> {
    Uri::parse_strict(b)
}

/// Zero-copy variants for inputs known at compile time. Wraps the
/// static slice in [`Bytes::from_static`] before handing it to the
/// parser — skips the `copy_from_slice` step that `&[u8]` triggers.
pub(super) fn parse_graceful_static(b: &'static [u8]) -> Result<Uri, ParseError> {
    Uri::parse(rama_core::bytes::Bytes::from_static(b))
}

pub(super) fn parse_strict_static(b: &'static [u8]) -> Result<Uri, ParseError> {
    Uri::parse_strict(rama_core::bytes::Bytes::from_static(b))
}

/// Pull the [`LazyUriRef`] out of a [`Uri`], panicking if the variant isn't
/// `Lazy`. Lets test cases work in terms of concrete component data.
pub(super) fn lazy(u: &Uri) -> &LazyUriRef {
    match &u.inner {
        UriInner::Lazy(arc) => arc.as_ref(),
        other => panic!("expected Lazy variant, got {other:?}"),
    }
}

/// `Option<(start, end)>` → `Option<&str>` slice of the lazy buffer.
pub(super) fn range_str(l: &LazyUriRef, r: Option<(u16, u16)>) -> Option<&str> {
    r.map(|(s, e)| std::str::from_utf8(&l.bytes[s as usize..e as usize]).unwrap())
}

/// `&str` view of the path range.
pub(super) fn path_str(l: &LazyUriRef) -> &str {
    std::str::from_utf8(&l.bytes[l.path.0 as usize..l.path.1 as usize]).unwrap()
}

/// `&str` view of the userinfo range, or `None` if no `@` was present in
/// the authority. Note that `Some("")` is a valid value — `http://@host/`
/// has an empty-but-present userinfo, which is distinct from
/// `http://host/` (no userinfo).
///
/// TODO(M4): this reaches into raw byte offsets because we don't yet
/// have a borrowed-userinfo accessor. The proper API will land with the
/// rest of the read-side accessors in M4. Note that the eventual
/// `UserInfoRef<'a>` cannot just be a thin `&[u8]` wrapper — it has to
/// handle both shapes the wire delivers:
/// - **raw bytes** (the RFC 3986 §3.2.1 view: opaque userinfo string
///   that may contain pct-encoded bytes and the convention-only `:`
///   separator)
/// - **split user / password parts** (the everyday `user[:password]`
///   shape consumers expect, parsed lazily, percent-decoded on
///   demand)
///
/// That design call belongs with the rest of the read-API in M4, not
/// here. For now, tests use this helper.
pub(super) fn userinfo_str(l: &LazyUriRef) -> Option<&str> {
    let (s, e) = l.authority.as_ref()?.userinfo_range?;
    Some(std::str::from_utf8(&l.bytes[s as usize..e as usize]).unwrap())
}

/// Asserts a `Uri` is in `Lazy` form with the given origin-form components
/// (scheme = None, authority = None, exact path/query/fragment).
pub(super) fn assert_origin_form(
    u: &Uri,
    expected_path: &str,
    expected_query: Option<&str>,
    expected_fragment: Option<&str>,
) {
    let l = lazy(u);
    assert!(
        l.scheme.is_none(),
        "scheme: expected None, got {:?}",
        l.scheme
    );
    assert!(
        l.authority.is_none(),
        "authority: expected None in origin-form"
    );
    assert_eq!(path_str(l), expected_path, "path");
    assert_eq!(range_str(l, l.query), expected_query, "query");
    assert_eq!(range_str(l, l.fragment), expected_fragment, "fragment");
}
