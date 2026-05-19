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
//! ## Scope of this file in M3 sub-commit (b)
//!
//! - Asterisk-form (`*`) detection — HTTP-only per RFC 9112 §3.2.4
//! - Origin-form (`/path?query#fragment`) parsing
//!
//! Authority-form, absolute-form, and the host parser arrive in sub-commit
//! (c).

use rama_core::bytes::Bytes;

use super::lazy::LazyUriRef;
use super::{Component, ParseError, Uri};

/// Maximum input length the parser accepts.
///
/// Capped because [`LazyUriRef`] stores component offsets as `u16`. The
/// `- 1` keeps `u16::MAX` available as an internal sentinel if we ever
/// need one.
pub(super) const MAX_URI_LEN: usize = u16::MAX as usize - 1;

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

    // Dispatch by leading byte. `/` is unambiguous: only origin-form starts
    // with it. Each form-specific parser does its own single-pass walk
    // and is responsible for control-char detection within its bytes.
    if bytes[0] == b'/' {
        parse_origin_form(bytes, mode)
    } else {
        // TODO(M3-c): absolute-form (`scheme:…`) and authority-form
        // (`host:port`). Until then anything not starting with `/` is
        // reported as a scheme-component failure.
        Err(ParseError::InvalidComponent(Component::Scheme))
    }
}

/// Parse an origin-form request-target: `path [ "?" query ] [ "#" fragment ]`.
///
/// `bytes[0] == b'/'` is the caller's responsibility.
///
/// Single-pass: walks the buffer once, simultaneously detecting control
/// chars, locating the `?`/`#` delimiters, and (in strict mode) validating
/// each byte against the active component's grammar.
fn parse_origin_form(bytes: Bytes, mode: ParserMode) -> Result<Uri, ParseError> {
    let len = bytes.len();
    let strict = mode == ParserMode::Strict;

    // Section tracking. `Section::Path` until `?` or `#` is seen, then
    // either Query or Fragment.
    enum Section {
        Path,
        Query,
        Fragment,
    }
    let mut section = Section::Path;
    let mut path_end = len;
    let mut query_start: Option<usize> = None;
    let mut fragment_start: Option<usize> = None;

    let mut i = 0;
    while i < len {
        let b = bytes[i];

        // Control chars: always fatal.
        if b < 0x20 || b == 0x7F {
            return Err(ParseError::ControlCharInUri { at: i, byte: b });
        }

        // Section transitions.
        match section {
            Section::Path => {
                if b == b'?' {
                    path_end = i;
                    query_start = Some(i + 1);
                    section = Section::Query;
                    i += 1;
                    continue;
                }
                if b == b'#' {
                    path_end = i;
                    fragment_start = Some(i + 1);
                    section = Section::Fragment;
                    i += 1;
                    continue;
                }
            }
            Section::Query => {
                if b == b'#' {
                    fragment_start = Some(i + 1);
                    section = Section::Fragment;
                    i += 1;
                    continue;
                }
            }
            Section::Fragment => {}
        }

        // Strict-mode byte-set check + percent-encoding validation.
        if strict {
            if b == b'%' {
                check_pct_encoded(&bytes, i)?;
                i += 3;
                continue;
            }
            let ok = match section {
                Section::Path => is_path_byte(b),
                Section::Query | Section::Fragment => is_query_fragment_byte(b),
            };
            if !ok {
                return Err(ParseError::StrictViolation);
            }
        }
        i += 1;
    }

    // Materialize query/fragment ranges. `fragment_start` (if set) marks
    // the byte after `#`; the query (if any) ends at `fragment_start - 1`.
    let query_range = query_start.map(|qs| {
        let qe = fragment_start.map_or(len, |fs| fs - 1);
        (qs as u16, qe as u16)
    });
    let fragment_range = fragment_start.map(|fs| (fs as u16, len as u16));

    Ok(Uri::from_lazy(LazyUriRef {
        bytes,
        scheme: None,
        authority: None,
        path: (0, path_end as u16),
        query: query_range,
        fragment: fragment_range,
    }))
}

/// Verifies a `%XX` percent-escape at `i`. Caller has confirmed
/// `bytes[i] == b'%'`.
fn check_pct_encoded(bytes: &[u8], i: usize) -> Result<(), ParseError> {
    let h1 = bytes.get(i + 1).copied();
    let h2 = bytes.get(i + 2).copied();
    match (h1, h2) {
        (Some(a), Some(b)) if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() => Ok(()),
        _ => Err(ParseError::InvalidPercentEncoding { at: i }),
    }
}

/// True if `b` is in the strict RFC 3986 path byte set
/// (`pchar` ∪ `/` ∪ literal `%`).
const fn is_path_byte(b: u8) -> bool {
    is_unreserved(b) || is_sub_delim(b) || matches!(b, b':' | b'@' | b'/' | b'%')
}

/// True if `b` is in the strict RFC 3986 query / fragment byte set.
const fn is_query_fragment_byte(b: u8) -> bool {
    is_path_byte(b) || b == b'?'
}

const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

const fn is_sub_delim(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_graceful(s: &str) -> Result<Uri, ParseError> {
        parse(Bytes::copy_from_slice(s.as_bytes()), ParserMode::Graceful)
    }

    fn parse_strict(s: &str) -> Result<Uri, ParseError> {
        parse(Bytes::copy_from_slice(s.as_bytes()), ParserMode::Strict)
    }

    // ----------------------------------------------------------------------
    // Asterisk
    // ----------------------------------------------------------------------

    #[test]
    fn asterisk_only() {
        let u = parse_graceful("*").unwrap();
        assert!(u.is_asterisk());
    }

    #[test]
    fn asterisk_strict() {
        let u = parse_strict("*").unwrap();
        assert!(u.is_asterisk());
    }

    #[test]
    fn asterisk_with_extra_bytes_is_not_asterisk() {
        // `*foo` is not an asterisk-form — should NOT match.
        let result = parse_graceful("*foo");
        // (b) doesn't parse absolute-form yet; just verify it's not Asterisk.
        if let Ok(u) = result {
            assert!(!u.is_asterisk());
        }
    }

    // ----------------------------------------------------------------------
    // Origin-form basics
    // ----------------------------------------------------------------------

    #[test]
    fn origin_path_only() {
        let u = parse_graceful("/foo").unwrap();
        assert!(!u.is_asterisk());
    }

    #[test]
    fn origin_path_with_query() {
        let u = parse_graceful("/foo?bar=baz").unwrap();
        assert!(!u.is_asterisk());
    }

    #[test]
    fn origin_path_with_fragment() {
        let u = parse_graceful("/foo#section").unwrap();
        assert!(!u.is_asterisk());
    }

    #[test]
    fn origin_path_with_query_and_fragment() {
        let u = parse_graceful("/foo?bar=baz#frag").unwrap();
        assert!(!u.is_asterisk());
    }

    #[test]
    fn origin_empty_query() {
        // `/foo?` is distinct from `/foo` — Some(empty range) vs None.
        let u = parse_graceful("/foo?").unwrap();
        assert!(!u.is_asterisk());
    }

    #[test]
    fn origin_root_only() {
        let u = parse_graceful("/").unwrap();
        assert!(!u.is_asterisk());
    }

    // ----------------------------------------------------------------------
    // Unconditional rejections
    // ----------------------------------------------------------------------

    #[test]
    fn rejects_empty() {
        assert!(matches!(parse_graceful(""), Err(ParseError::Empty)));
    }

    #[test]
    fn rejects_control_char_cr() {
        let r = parse_graceful("/foo\r/bar");
        assert!(matches!(
            r,
            Err(ParseError::ControlCharInUri { byte: b'\r', .. })
        ));
    }

    #[test]
    fn rejects_control_char_lf() {
        let r = parse_graceful("/foo\n/bar");
        assert!(matches!(
            r,
            Err(ParseError::ControlCharInUri { byte: b'\n', .. })
        ));
    }

    #[test]
    fn rejects_control_char_nul() {
        let r = parse_graceful("/foo\0bar");
        assert!(matches!(
            r,
            Err(ParseError::ControlCharInUri { byte: 0, .. })
        ));
    }

    #[test]
    fn rejects_tab() {
        let r = parse_graceful("/foo\tbar");
        assert!(matches!(
            r,
            Err(ParseError::ControlCharInUri { byte: b'\t', .. })
        ));
    }

    #[test]
    fn rejects_del() {
        let r = parse_graceful("/foo\x7Fbar");
        assert!(matches!(
            r,
            Err(ParseError::ControlCharInUri { byte: 0x7F, .. })
        ));
    }

    #[test]
    fn rejects_too_long() {
        let big = "/".to_owned() + &"a".repeat(MAX_URI_LEN);
        let r = parse_graceful(&big);
        assert!(matches!(r, Err(ParseError::TooLong { .. })));
    }

    // ----------------------------------------------------------------------
    // Graceful accepts more than strict
    // ----------------------------------------------------------------------

    #[test]
    fn graceful_accepts_unreserved_extras_in_path() {
        // `{`, `}`, `|`, `^` are not in RFC 3986 pchar — graceful accepts,
        // strict rejects.
        for s in ["/path{x}", "/p|q", "/p^q", "/p<x>"] {
            assert!(parse_graceful(s).is_ok(), "graceful should accept {s}");
            assert!(
                matches!(parse_strict(s), Err(ParseError::StrictViolation)),
                "strict should reject {s}"
            );
        }
    }

    #[test]
    fn strict_accepts_pchar_path() {
        // Every byte here is in the pchar set.
        for s in ["/foo", "/a/b/c", "/a-b.c_d~e", "/a%20b", "/foo?bar"] {
            assert!(parse_strict(s).is_ok(), "strict should accept {s}");
        }
    }

    #[test]
    fn strict_rejects_bad_percent_encoding() {
        for s in ["/foo%", "/foo%a", "/foo%zz"] {
            let r = parse_strict(s);
            assert!(
                matches!(r, Err(ParseError::InvalidPercentEncoding { .. })),
                "got {r:?} for {s}"
            );
        }
    }
}
