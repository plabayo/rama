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
//! ## Forms parsed
//!
//! - Asterisk-form `*` — HTTP-only per RFC 9112 §3.2.4. Via [`parse`].
//! - Origin-form `/path?query#fragment`. Via [`parse`].
//! - Absolute-form `scheme:hier-part [ "?" query ] [ "#" fragment ]`, both
//!   shapes: `scheme://authority/path` and opaque `scheme:opaque-path`.
//!   Via [`parse`].
//! - Authority-form `[userinfo@]host[:port]` — HTTP CONNECT request-target
//!   per RFC 9112 §3.2.3. Via the dedicated [`parse_authority_form`]
//!   entry point, because the grammar is ambiguous with `scheme:opaque-path`
//!   and RFC 3986 picks the scheme reading.
//! - URI-reference grammar (relative refs, network-path, query-only,
//!   fragment-only). Via [`parse_uri_reference`].
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

use super::lazy::{LazyAuthority, LazyUriRef};
use super::{Component, ParseError, Uri};

use rama_core::bytes::Bytes;

pub(crate) mod authority;
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
    if let Some(uri) = try_parse_absolute(&bytes, mode)? {
        return Ok(uri);
    }

    // Anything else (relative refs with path-noscheme, the HTTP CONNECT
    // authority-form `host:port`, etc.) is not accepted by [`parse`].
    // Use [`parse_uri_reference`] for relative refs or
    // [`parse_authority_form`] for HTTP CONNECT targets.
    Err(ParseError::InvalidComponent(Component::Scheme))
}

/// Try the absolute-form (scheme-bearing) branch of RFC 3986 §3.
///
/// - `Ok(Some(uri))` when `bytes` starts with a valid scheme and the
///   rest parses.
/// - `Ok(None)` when no scheme is present (caller decides whether to
///   continue with origin-form / relative-ref handling).
/// - `Err(_)` when a scheme is present but invalid (unknown
///   [`crate::Protocol`]), or the body fails the per-component checks.
///
/// Shared by [`parse`] and [`parse_uri_reference`] so the scheme +
/// hier-part walk has a single definition.
fn try_parse_absolute(bytes: &Bytes, mode: ParserMode) -> Result<Option<Uri>, ParseError> {
    let Some(colon) = scheme::find_scheme_end(bytes) else {
        return Ok(None);
    };
    let scheme_str = bytes_to_str(&bytes[..colon]);
    let Ok(scheme) = crate::Protocol::try_from(scheme_str) else {
        return Err(ParseError::InvalidComponent(Component::Scheme));
    };
    let after_colon = colon + 1;
    let auth_scan = authority::parse_optional_authority(bytes, after_colon, mode)?;
    let path_start = auth_scan.path_start;
    let path_scan = path::scan_path_query_fragment(bytes, path_start, mode)?;
    Ok(Some(build_uri(
        Some(scheme),
        auth_scan.authority,
        (path_start as u16, path_scan.path_end),
        path_scan.query,
        path_scan.fragment,
        // `Bytes::clone` is one atomic refcount bump — only paid on
        // the commit path; no clone if we return None earlier.
        bytes.clone(),
    )))
}

/// Parse an HTTP authority-form request-target. Used for the CONNECT
/// method (RFC 9112 §3.2.3).
///
/// Distinct entry point because [`parse`] cannot disambiguate authority-
/// form from `scheme:opaque-path` — `example.com:443` is grammatically
/// valid as both, and RFC 3986 prefers the scheme reading.
///
/// # Grammar by mode
///
/// - **Graceful** ([`Uri::parse_authority_form`](super::super::Uri::parse_authority_form)):
///   `[userinfo@]host[:port]`. Userinfo and bare-host (no port) are
///   accepted — the latter so callers without a port handy (e.g. HTTP
///   tooling that derives the port from the scheme) can still go
///   through this entry point. The wire writer ([`super::super::wire`])
///   strips userinfo before serializing, so wire RFC 9112 compliance
///   is preserved regardless.
/// - **Strict** ([`Uri::parse_authority_form_strict`](super::super::Uri::parse_authority_form_strict)):
///   exactly `host:port`. Userinfo and bare-host are
///   [`ParseError::StrictViolation`] — RFC 9112 §3.2.3 says
///   "The request-target consists of the host and port number of the
///   tunnel destination", no optional parts.
pub(super) fn parse_authority_form(bytes: Bytes, mode: ParserMode) -> Result<Uri, ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::Empty);
    }
    if bytes.len() > MAX_URI_LEN {
        return Err(ParseError::TooLong { len: bytes.len() });
    }

    // Reject anything that obviously isn't pure authority bytes — any
    // path/query/fragment delimiter means the caller handed us the
    // wrong shape and should have used [`parse`] instead.
    if let Some(at) = bytes.iter().position(|&b| matches!(b, b'/' | b'?' | b'#')) {
        let _ = at;
        return Err(ParseError::InvalidComponent(Component::Authority));
    }

    let len = bytes.len();
    let auth = authority::parse_authority(&bytes, 0, len, mode)?;

    // RFC 9112 §3.2.3 in strict mode: CONNECT authority-form is exactly
    // `host:port`. Userinfo and bare-host (port-less) are documented as
    // graceful-only conveniences, so reject them here.
    if matches!(mode, ParserMode::Strict) {
        if auth.userinfo_range.is_some() {
            return Err(ParseError::StrictViolation);
        }
        // RFC 9112 §3.2.3 requires `host ":" port` — `Empty` and `Unset`
        // both fail the explicit-port requirement.
        if !matches!(auth.port, crate::address::OptPort::Set(_)) {
            return Err(ParseError::StrictViolation);
        }
    }

    Ok(build_uri(
        None,
        Some(auth),
        // Path is empty by construction — authority-form has no path.
        (len as u16, len as u16),
        None,
        None,
        bytes,
    ))
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

    // Absolute-form (scheme present). Falls through to the relative-ref
    // grammar below when there's no scheme.
    if let Some(uri) = try_parse_absolute(&bytes, mode)? {
        return Ok(uri);
    }

    // Relative-ref. Per RFC 3986 §4.2, the disambiguation is:
    //   relative-part = "//" authority path-abempty
    //                 / path-absolute   (starts with `/` but not `//`)
    //                 / path-noscheme   (no `/`, no `:` in first segment)
    //                 / path-empty      (path starts with `?` / `#` / EOF)
    let auth_scan = authority::parse_optional_authority(&bytes, 0, mode)?;
    let path_start = auth_scan.path_start;
    let path_scan = path::scan_path_query_fragment(&bytes, path_start, mode)?;

    // RFC 3986 §3.3 `segment-nz-nc`: a path-noscheme reference can't have
    // `:` in its first segment — otherwise the input would parse as a
    // scheme reading. Strict mode enforces; graceful continues to accept
    // (curl/browsers do).
    if matches!(mode, ParserMode::Strict)
        && auth_scan.authority.is_none()
        && path_scan.path_end as usize > path_start
        && !bytes[path_start..].starts_with(b"/")
    {
        let first_seg_end = bytes[path_start..path_scan.path_end as usize]
            .iter()
            .position(|&b| matches!(b, b'/' | b'?' | b'#'))
            .map(|i| path_start + i)
            .unwrap_or(path_scan.path_end as usize);
        if bytes[path_start..first_seg_end].contains(&b':') {
            return Err(ParseError::StrictViolation);
        }
    }

    Ok(build_uri(
        None,
        auth_scan.authority,
        (path_start as u16, path_scan.path_end),
        path_scan.query,
        path_scan.fragment,
        bytes,
    ))
}

/// Assemble parsed parts into a [`Uri`]. Always emits the `Lazy` shape —
/// without parser-time canonicalization (M7 reversed: pct-encoded /
/// IDN host bytes are now preserved verbatim via
/// [`Host::Uninterpreted`](crate::address::Host::Uninterpreted)), the
/// typed view never diverges from the source buffer.
fn build_uri(
    scheme: Option<crate::Protocol>,
    authority: Option<LazyAuthority>,
    path: (u16, u16),
    query: Option<(u16, u16)>,
    fragment: Option<(u16, u16)>,
    bytes: Bytes,
) -> Uri {
    Uri::from_lazy(LazyUriRef {
        scheme,
        authority,
        path,
        query,
        fragment,
        bytes,
    })
}

// --- Small shared helpers used by sibling modules --------------------------

/// `bytes` is assumed to be valid UTF-8 (caller is responsible). Used for
/// scheme conversion, where the parser has already validated the byte set
/// is a subset of ASCII.
pub(super) fn bytes_to_str(bytes: &[u8]) -> &str {
    // Safety: scheme bytes are validated as ASCII alpha + digit + + - .
    unsafe { core::str::from_utf8_unchecked(bytes) }
}

/// Validate the UTF-8 sequence starting at `bytes[i]`. Caller has verified
/// `bytes[i] >= 0x80`; anything else is single-byte ASCII and bypasses
/// this function. Returns the sequence length on success (2, 3, or 4) or
/// the offset of the first invalid byte on failure.
///
/// Full well-formed-UTF-8 validation (RFC 3629 §4, Unicode 13 Table 3-7):
/// rejects overlong encodings, surrogate code points (U+D800..=U+DFFF),
/// and code points beyond U+10FFFF. The four lead bytes with a *tighter*
/// first-continuation-byte range — `E0` (overlong 3), `ED` (surrogates),
/// `F0` (overlong 4), `F4` (>U+10FFFF) — are special-cased; the rest use
/// the canonical `0x80..=0xBF` continuation range.
///
/// Perf notes:
/// - `#[inline]` so the per-byte branch in the caller's loop folds in.
/// - Slice the sequence once via `bytes.get(i..i+len)` so the inner
///   continuation walk skips per-byte bounds checks.
/// - Continuation-byte test is the bit-mask form `(b & 0xC0) == 0x80`,
///   one op instead of two range compares.
/// - All-ASCII inputs never enter this function — that fast path pays
///   nothing.
#[inline]
pub(super) fn check_utf8_sequence(bytes: &[u8], i: usize) -> Result<usize, ParseError> {
    let b1 = bytes[i];
    let len: usize = match b1 {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return Err(ParseError::NonUtf8 { at: i }),
    };
    let Some(seq) = bytes.get(i..i + len) else {
        return Err(ParseError::NonUtf8 { at: i });
    };
    // First continuation byte: tighter range for the four edge-case
    // leads, canonical bit-mask for the rest.
    let b2 = seq[1];
    let b2_ok = match b1 {
        0xE0 => (0xA0..=0xBF).contains(&b2),
        0xED => (0x80..=0x9F).contains(&b2),
        0xF0 => (0x90..=0xBF).contains(&b2),
        0xF4 => (0x80..=0x8F).contains(&b2),
        _ => (b2 & 0xC0) == 0x80,
    };
    if !b2_ok {
        return Err(ParseError::NonUtf8 { at: i + 1 });
    }
    // Remaining continuation bytes — slice-iter so LLVM doesn't emit
    // per-iteration bounds checks (the slice length is known).
    for (k, &b) in seq[2..].iter().enumerate() {
        if (b & 0xC0) != 0x80 {
            return Err(ParseError::NonUtf8 { at: i + 2 + k });
        }
    }
    Ok(len)
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
