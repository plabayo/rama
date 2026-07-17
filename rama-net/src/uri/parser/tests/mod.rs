//! Parser test corpus.
//!
//! Organized by category:
//! - [`origin_form`] — request-target style `/path?q#f` (HTTP origin-form)
//! - [`absolute_form`] — full URIs `scheme:hier-part`
//! - [`authority_form`] — HTTP CONNECT `[userinfo@]host[:port]` shape
//! - [`non_http_schemes`] — corpus of non-HTTP URIs (urn, mailto, ftp, ws,
//!   git, ssh, redis, mongodb, coap, geo, magnet, custom)
//! - [`rfc3986_examples`] — RFC 3986 §1.1.2 canonical examples
//! - [`strict_mode`] — graceful-vs-strict difference coverage
//! - [`utf8`] — well-formed-UTF-8 enforcement on graceful parses
//! - [`host`] — host-component edge cases (pct-encoded reg-name, IPvFuture)
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
//! - [`idna`] — IDN / UTS #46 host normalisation and strict-mode rejection
//! - [`canonicalize`] — RFC 3986 §6.2.2 canonical-form pipeline (host
//!   promotion, pct-decode unreserved, default-port drop, dot-segment
//!   removal, scheme lowercase) and `set_host` / `try_set_host`
//! - [`accessors`], [`mutation`], [`display`], [`wire`], [`resolve`],
//!   [`query_collect`], [`query_mut`], [`path_mut`] — per-API surface
//!
//! All files use the subject-based naming convention (the component or
//! API surface being exercised). Form-specific shapes
//! (`origin_form` / `absolute_form` / `authority_form`) are also
//! subject-based — the subject is "this form's parser path."
//!
//! Shared helpers live in this file.

use super::super::UriInner;
use super::super::lazy::LazyUriRef;
use crate::uri::{ParseError, Uri};

pub(super) mod absolute_form;
pub(super) mod accessors;
pub(super) mod adversarial;
pub(super) mod authority_form;
pub(super) mod canonicalize;
pub(super) mod display;
pub(super) mod eq_hash_ord;
pub(super) mod fragment;
pub(super) mod host;
pub(super) mod idna;
pub(super) mod mutation;
pub(super) mod non_http_schemes;
pub(super) mod origin_form;
pub(super) mod path_matcher;
pub(super) mod path_mut;
pub(super) mod path_segments;
pub(super) mod query_collect;
#[cfg(feature = "std")]
pub(super) mod query_deserialize;
pub(super) mod query_mut;
pub(super) mod query_pairs;
pub(super) mod request_target;
pub(super) mod resolve;
pub(super) mod rfc3986_examples;
pub(super) mod serde;
pub(super) mod smoke;
pub(super) mod strict_mode;
pub(super) mod utf8;
pub(super) mod whatwg_corpus;
pub(super) mod wire;

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
    r.map(|(s, e)| core::str::from_utf8(&l.bytes[s as usize..e as usize]).unwrap())
}

/// `&str` view of the path range.
pub(super) fn path_str(l: &LazyUriRef) -> &str {
    core::str::from_utf8(&l.bytes[l.path.0 as usize..l.path.1 as usize]).unwrap()
}

/// `&str` view of the userinfo range, or `None` if no `@` was present in
/// the authority. Note that `Some("")` is a valid value — `http://@host/`
/// has an empty-but-present userinfo, which is distinct from
/// `http://host/` (no userinfo).
///
/// Reads the raw byte offsets on purpose: these parser-level tests pin
/// the wire ranges independently of the higher-level
/// [`Uri::userinfo`](crate::uri::Uri::userinfo) accessor built on top.
pub(super) fn userinfo_str(l: &LazyUriRef) -> Option<&str> {
    let (s, e) = l.authority.as_ref()?.userinfo_range?;
    Some(core::str::from_utf8(&l.bytes[s as usize..e as usize]).unwrap())
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

// ---- Compile-time `Send + Sync` assertions ---------------------
//
// `Uri` clones cheap by sharing an `Arc<…>`; the wrapped types and the
// borrowed views must stay `Send + Sync` so the whole graph can flow
// across task boundaries in proxy / routing code. A future field
// addition that silently breaks this would only surface at a downstream
// `tokio::spawn` call — the assertions below catch it at this crate's
// own build.
#[cfg(test)]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}

    use crate::address::{
        Authority, AuthorityRef, Host, HostRef, UninterpretedHost, UninterpretedHostRef, UserInfo,
        UserInfoRef,
    };
    #[cfg(feature = "std")]
    use crate::uri::QueryDeserializeError;
    use crate::uri::{
        Fragment, FragmentRef, ParseError, PathCaptures, PathPattern, PathRef, Query, QueryPair,
        QueryPairRef, QueryRef, ResolveError, Uri, UriError, WireError,
    };
    assert_send_sync::<Uri>();
    assert_send_sync::<UriError>();
    assert_send_sync::<ParseError>();
    assert_send_sync::<ResolveError>();
    assert_send_sync::<WireError>();
    #[cfg(feature = "std")]
    assert_send_sync::<QueryDeserializeError>();

    assert_send_sync::<Query>();
    assert_send_sync::<QueryRef<'static>>();
    assert_send_sync::<QueryPair>();
    assert_send_sync::<QueryPairRef<'static>>();
    assert_send_sync::<Fragment>();
    assert_send_sync::<FragmentRef<'static>>();
    assert_send_sync::<PathRef<'static>>();
    assert_send_sync::<PathPattern>();
    assert_send_sync::<PathCaptures<'static, 'static>>();

    assert_send_sync::<Authority>();
    assert_send_sync::<AuthorityRef<'static>>();
    assert_send_sync::<Host>();
    assert_send_sync::<HostRef<'static>>();
    assert_send_sync::<UserInfo>();
    assert_send_sync::<UserInfoRef<'static>>();
    assert_send_sync::<UninterpretedHost>();
    assert_send_sync::<UninterpretedHostRef<'static>>();
};
