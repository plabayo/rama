//! Internal parser engine for [`crate::uri::Uri`].
//!
//! `Uri` is for *any* RFC 3986 URI — http(s), ws(s), ftp, mailto:, urn:,
//! file:, custom schemes — not just HTTP. HTTP-specific shapes (e.g. the
//! asterisk request-target from RFC 9112 §3.2.4) are called out in docs
//! and tests, but the parser itself is protocol-neutral.
//!
//! Two modes, one engine:
//!
//! - **Graceful** (`Uri::parse`) — accepts what real wire traffic looks like
//!   inside the differential-parse-safe envelope. Rejects: ASCII control
//!   chars (smuggling/header-injection vectors). Accepts: every non-control
//!   byte in path/query/fragment, even bytes RFC 3986 puts outside `pchar`
//!   (`{`, `}`, `^`, `|`, raw UTF-8, etc.). Browsers and curl do the same.
//!
//! - **Strict** (`Uri::parse_strict`) — RFC 3986 grammar. Anything outside
//!   the per-component byte set is [`ParseError::StrictViolation`].
//!
//! Things never accepted in either mode:
//!
//! - Any ASCII control byte (`< 0x20` or `0x7F`) anywhere in the input
//! - Inputs longer than [`MAX_URI_LEN`] (forced by 16-bit offsets in
//!   [`LazyUriRef`])
//!
//! Per-form scanners detect control chars inline during their walk — no
//! separate pre-pass.
//!
//! ## Forms currently parsed
//!
//! - Asterisk-form `*` — HTTP-only per RFC 9112 §3.2.4
//! - Origin-form `/path?query#fragment`
//! - Absolute-form `scheme:hier-part [ "?" query ] [ "#" fragment ]`, both
//!   shapes: `scheme://authority/path` and opaque `scheme:opaque-path`
//!
//! Not yet supported: HTTP authority-form (`host:port` for CONNECT) and
//! relative refs with path-noscheme.
//!
//! ## File layout
//!
//! - [`mod.rs`](self) — `ParserMode`, [`parse`] entry, `MAX_URI_LEN`,
//!   tiny shared helpers ([`check_pct_encoded`], [`bytes_to_str`])
//! - [`byte_sets`] — `[bool; 256]` lookup tables + `is_*` predicates
//! - [`scheme`] — scheme-end scanner
//! - [`path`] — single-pass walker for path / query / fragment
//! - [`authority`] — authority / host / port / userinfo parsing
//! - [`tests`](mod@tests) — large multi-file corpus

use rama_core::bytes::{Bytes, BytesMut};

use super::lazy::LazyUriRef;
use super::owned::OwnedUriRef;
use super::{Component, Fragment, ParseError, Query, Uri, UriInner};

use authority::ParsedAuthority;

mod authority;
mod byte_sets;
mod path;
mod scheme;

/// Re-exported for the URI component setters' fast-path check.
pub(in crate::uri) use byte_sets::{is_path_byte, is_query_fragment_byte};

#[cfg(test)]
mod tests;

/// Maximum input length the parser accepts.
///
/// Capped because [`LazyUriRef`] stores component offsets as `u16`. The
/// `- 1` keeps `u16::MAX` available as an internal sentinel if we ever
/// need one.
pub(in crate::uri) const MAX_URI_LEN: usize = u16::MAX as usize - 1;

/// Which parser mode is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ParserMode {
    /// Browser/curl-compatible. Rejects only smuggling-class inputs.
    Graceful,
    /// RFC 3986 syntax only.
    Strict,
}

/// Engine entry point. All `Uri::parse*` methods funnel through here.
pub(super) fn parse(bytes: Bytes, mode: ParserMode) -> Result<Uri, ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::Empty);
    }
    if bytes.len() > MAX_URI_LEN {
        return Err(ParseError::TooLong { len: bytes.len() });
    }

    // Asterisk-form: the whole input is the single byte `*`. HTTP-specific
    // (RFC 9112 §3.2.4); harmless for other protocols since it's just one
    // variant.
    if bytes.as_ref() == b"*" {
        return Ok(Uri::from_asterisk());
    }

    // Origin-form: starts with `/`. No scheme, no authority.
    if bytes[0] == b'/' {
        let scan = path::scan_path_query_fragment(&bytes, 0, mode)?;
        return Ok(Uri::from_lazy(LazyUriRef {
            scheme: None,
            authority: None,
            path: (0, scan.path_end),
            query: scan.query,
            fragment: scan.fragment,
            bytes,
        }));
    }

    // Absolute-form: `scheme ":" hier-part [ "?" query ] [ "#" fragment ]`
    // (RFC 3986 §3). hier-part is either `//authority path-abempty` or an
    // opaque path-absolute / path-rootless (e.g. `urn:isbn:0`, `mailto:a@b`).
    if let Some(colon) = scheme::find_scheme_end(&bytes) {
        let scheme_str = bytes_to_str(&bytes[..colon]);
        let Ok(scheme) = crate::Protocol::try_from(scheme_str) else {
            return Err(ParseError::InvalidComponent(Component::Scheme));
        };

        let after_colon = colon + 1;
        let auth_scan = authority::parse_optional_authority(&bytes, after_colon, mode)?;
        let path_start = auth_scan.path_start;
        let path_scan = path::scan_path_query_fragment(&bytes, path_start, mode)?;

        return Ok(build_uri(
            Some(scheme),
            auth_scan.authority,
            (path_start as u16, path_scan.path_end),
            path_scan.query,
            path_scan.fragment,
            bytes,
        ));
    }

    // Anything else (relative refs with path-noscheme, HTTP authority-form
    // `host:port`, etc.) is not accepted by [`parse`]. Callers that need
    // to parse a relative URI-reference should use [`parse_uri_reference`].
    Err(ParseError::InvalidComponent(Component::Scheme))
}

/// Parse any RFC 3986 URI-reference — absolute URI or relative-ref.
///
/// Accepts everything [`parse`] accepts, plus the relative-ref grammar
/// from §4.2: empty input (same-document), `//host/...` (network-path),
/// `g/h` (path-noscheme), `?query` (query-only), `#frag` (fragment-only).
///
/// Used by [`super::Uri::resolve`] to materialise the reference operand.
pub(super) fn parse_uri_reference(bytes: Bytes, mode: ParserMode) -> Result<Uri, ParseError> {
    if bytes.len() > MAX_URI_LEN {
        return Err(ParseError::TooLong { len: bytes.len() });
    }

    // Empty input → empty same-document reference. No host means no IDN
    // possible — Lazy is always correct.
    if bytes.is_empty() {
        return Ok(Uri::from_lazy(LazyUriRef {
            scheme: None,
            authority: None,
            path: (0, 0),
            query: None,
            fragment: None,
            bytes,
        }));
    }

    // Asterisk-form.
    if bytes.as_ref() == b"*" {
        return Ok(Uri::from_asterisk());
    }

    // Absolute-form (scheme present).
    if let Some(colon) = scheme::find_scheme_end(&bytes) {
        let scheme_str = bytes_to_str(&bytes[..colon]);
        let Ok(scheme) = crate::Protocol::try_from(scheme_str) else {
            return Err(ParseError::InvalidComponent(Component::Scheme));
        };
        let after_colon = colon + 1;
        let auth_scan = authority::parse_optional_authority(&bytes, after_colon, mode)?;
        let path_start = auth_scan.path_start;
        let path_scan = path::scan_path_query_fragment(&bytes, path_start, mode)?;
        return Ok(build_uri(
            Some(scheme),
            auth_scan.authority,
            (path_start as u16, path_scan.path_end),
            path_scan.query,
            path_scan.fragment,
            bytes,
        ));
    }

    // Relative-ref. Per RFC 3986 §4.2, the disambiguation is:
    //   relative-part = "//" authority path-abempty
    //                 / path-absolute   (starts with `/` but not `//`)
    //                 / path-noscheme   (no `/`, no `:` in first segment)
    //                 / path-empty      (path starts with `?` / `#` / EOF)
    let auth_scan = authority::parse_optional_authority(&bytes, 0, mode)?;
    let path_start = auth_scan.path_start;
    let path_scan = path::scan_path_query_fragment(&bytes, path_start, mode)?;

    Ok(build_uri(
        None,
        auth_scan.authority,
        (path_start as u16, path_scan.path_end),
        path_scan.query,
        path_scan.fragment,
        bytes,
    ))
}

/// Assemble parsed parts into a [`Uri`]. The authority variant decides
/// the storage shape: `Lazy` keeps zero-copy projection into `bytes`;
/// `Owned` short-circuits to [`OwnedUriRef`] because UTS #46 rewrote the
/// host, so the raw buffer no longer agrees with the typed view.
///
/// The Owned path still slices path / query / fragment out of `bytes`
/// into fresh `BytesMut` buffers — that's the same copy cost the
/// upgrade-on-mutation path pays, just done eagerly here so we skip the
/// throwaway `Arc<LazyUriRef>` allocation.
fn build_uri(
    scheme: Option<crate::Protocol>,
    authority: Option<ParsedAuthority>,
    path: (u16, u16),
    query: Option<(u16, u16)>,
    fragment: Option<(u16, u16)>,
    bytes: Bytes,
) -> Uri {
    match authority {
        None => Uri::from_lazy(LazyUriRef {
            scheme,
            authority: None,
            path,
            query,
            fragment,
            bytes,
        }),
        Some(ParsedAuthority::Lazy(lazy_auth)) => Uri::from_lazy(LazyUriRef {
            scheme,
            authority: Some(lazy_auth),
            path,
            query,
            fragment,
            bytes,
        }),
        Some(ParsedAuthority::Owned(authority)) => {
            let slice = |(s, e): (u16, u16)| BytesMut::from(&bytes[s as usize..e as usize]);
            let owned = OwnedUriRef {
                scheme,
                authority: Some(authority),
                path: slice(path),
                query: query.map(|r| Query { bytes: slice(r) }),
                fragment: fragment.map(|r| Fragment { bytes: slice(r) }),
            };
            Uri {
                inner: UriInner::Owned(std::sync::Arc::new(owned)),
            }
        }
    }
}

// --- Small shared helpers used by sibling modules --------------------------

/// `bytes` is assumed to be valid UTF-8 (caller is responsible). Used for
/// scheme conversion, where the parser has already validated the byte set
/// is a subset of ASCII.
pub(super) fn bytes_to_str(bytes: &[u8]) -> &str {
    // Safety: scheme bytes are validated as ASCII alpha + digit + + - .
    unsafe { std::str::from_utf8_unchecked(bytes) }
}

/// Verifies a `%XX` percent-escape at `i`. Caller has confirmed
/// `bytes[i] == b'%'`.
pub(super) fn check_pct_encoded(bytes: &[u8], i: usize) -> Result<(), ParseError> {
    let h1 = bytes.get(i + 1).copied();
    let h2 = bytes.get(i + 2).copied();
    match (h1, h2) {
        (Some(a), Some(b)) if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() => Ok(()),
        _ => Err(ParseError::InvalidPercentEncoding { at: i }),
    }
}
