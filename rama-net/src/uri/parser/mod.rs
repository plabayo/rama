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

use rama_core::bytes::Bytes;

use super::lazy::LazyUriRef;
use super::{Component, ParseError, Uri};

mod authority;
mod byte_sets;
mod path;
mod scheme;

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
        let (auth, hier_start) = authority::parse_optional_authority(&bytes, after_colon, mode)?;
        let scan = path::scan_path_query_fragment(&bytes, hier_start, mode)?;

        return Ok(Uri::from_lazy(LazyUriRef {
            scheme: Some(scheme),
            authority: auth,
            path: (hier_start as u16, scan.path_end),
            query: scan.query,
            fragment: scan.fragment,
            bytes,
        }));
    }

    // Anything else (relative refs with path-noscheme, HTTP authority-form
    // `host:port`, etc.) is not yet supported.
    Err(ParseError::InvalidComponent(Component::Scheme))
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
