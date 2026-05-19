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
    use super::super::UriInner;
    use super::super::lazy::LazyUriRef;
    use super::*;

    fn parse_graceful(s: &str) -> Result<Uri, ParseError> {
        parse(Bytes::copy_from_slice(s.as_bytes()), ParserMode::Graceful)
    }

    fn parse_strict(s: &str) -> Result<Uri, ParseError> {
        parse(Bytes::copy_from_slice(s.as_bytes()), ParserMode::Strict)
    }

    /// Pull the LazyUriRef out of a Uri, panicking if the variant isn't Lazy.
    /// Lets the rest of the tests work in terms of concrete component data.
    fn lazy(u: &Uri) -> &LazyUriRef {
        match &u.inner {
            UriInner::Lazy(arc) => arc.as_ref(),
            other => panic!("expected Lazy variant, got {other:?}"),
        }
    }

    fn range_str(l: &LazyUriRef, r: Option<(u16, u16)>) -> Option<&str> {
        r.map(|(s, e)| std::str::from_utf8(&l.bytes[s as usize..e as usize]).unwrap())
    }

    /// Asserts the lazy `u`'s scheme/authority/path/query/fragment match.
    /// Path is required (RFC 3986 §3.3 — always present); query and
    /// fragment are `Option<&str>` to distinguish `None` from `Some("")`.
    fn assert_lazy(
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
        let path = std::str::from_utf8(&l.bytes[l.path.0 as usize..l.path.1 as usize]).unwrap();
        assert_eq!(path, expected_path, "path");
        assert_eq!(range_str(l, l.query), expected_query, "query");
        assert_eq!(range_str(l, l.fragment), expected_fragment, "fragment");
    }

    // ----------------------------------------------------------------------
    // Asterisk (HTTP-specific, RFC 9112 §3.2.4)
    // ----------------------------------------------------------------------

    #[test]
    fn asterisk_only() {
        let u = parse_graceful("*").unwrap();
        assert!(matches!(u.inner, UriInner::Asterisk));
    }

    #[test]
    fn asterisk_strict() {
        let u = parse_strict("*").unwrap();
        assert!(matches!(u.inner, UriInner::Asterisk));
    }

    #[test]
    fn asterisk_only_matches_exactly() {
        // `*foo` is NOT asterisk-form. (b) doesn't accept it yet;
        // verify it returns the placeholder scheme error.
        let r = parse_graceful("*foo");
        assert!(matches!(
            r,
            Err(ParseError::InvalidComponent(Component::Scheme))
        ));
    }

    // ----------------------------------------------------------------------
    // Origin-form: assert exact component content
    // ----------------------------------------------------------------------

    #[test]
    fn origin_path_only() {
        let u = parse_graceful("/foo").unwrap();
        assert_lazy(&u, "/foo", None, None);
    }

    #[test]
    fn origin_root_only() {
        let u = parse_graceful("/").unwrap();
        assert_lazy(&u, "/", None, None);
    }

    #[test]
    fn origin_multi_segment_path() {
        let u = parse_graceful("/a/b/c").unwrap();
        assert_lazy(&u, "/a/b/c", None, None);
    }

    #[test]
    fn origin_path_with_query() {
        let u = parse_graceful("/foo?bar=baz").unwrap();
        assert_lazy(&u, "/foo", Some("bar=baz"), None);
    }

    #[test]
    fn origin_path_with_fragment() {
        let u = parse_graceful("/foo#section").unwrap();
        assert_lazy(&u, "/foo", None, Some("section"));
    }

    #[test]
    fn origin_path_with_query_and_fragment() {
        let u = parse_graceful("/foo?bar=baz#frag").unwrap();
        assert_lazy(&u, "/foo", Some("bar=baz"), Some("frag"));
    }

    #[test]
    fn origin_empty_query_distinct_from_none() {
        let with = parse_graceful("/foo?").unwrap();
        assert_lazy(&with, "/foo", Some(""), None);

        let without = parse_graceful("/foo").unwrap();
        assert_lazy(&without, "/foo", None, None);
    }

    #[test]
    fn origin_empty_fragment_distinct_from_none() {
        let with = parse_graceful("/foo#").unwrap();
        assert_lazy(&with, "/foo", None, Some(""));

        let without = parse_graceful("/foo").unwrap();
        assert_lazy(&without, "/foo", None, None);
    }

    #[test]
    fn origin_empty_query_and_empty_fragment() {
        let u = parse_graceful("/foo?#").unwrap();
        assert_lazy(&u, "/foo", Some(""), Some(""));
    }

    #[test]
    fn origin_only_first_question_mark_ends_path() {
        // RFC 3986 §3.4: only the first `?` ends the path; subsequent `?`
        // are valid query bytes.
        let u = parse_graceful("/foo?a=b?c=d").unwrap();
        assert_lazy(&u, "/foo", Some("a=b?c=d"), None);
    }

    #[test]
    fn origin_fragment_containing_question_mark() {
        // `?` is a valid fragment byte.
        let u = parse_graceful("/foo#frag?x").unwrap();
        assert_lazy(&u, "/foo", None, Some("frag?x"));
    }

    #[test]
    fn origin_hash_inside_query_starts_fragment() {
        let u = parse_graceful("/p?q#f").unwrap();
        assert_lazy(&u, "/p", Some("q"), Some("f"));
    }

    // ----------------------------------------------------------------------
    // Unconditional rejections (both modes)
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
            Err(ParseError::ControlCharInUri { at: 4, byte: b'\r' })
        ));
    }

    #[test]
    fn rejects_control_char_lf() {
        let r = parse_graceful("/foo\n/bar");
        assert!(matches!(
            r,
            Err(ParseError::ControlCharInUri { at: 4, byte: b'\n' })
        ));
    }

    #[test]
    fn rejects_control_char_nul() {
        let r = parse_graceful("/foo\0bar");
        assert!(matches!(
            r,
            Err(ParseError::ControlCharInUri { at: 4, byte: 0 })
        ));
    }

    #[test]
    fn rejects_tab() {
        let r = parse_graceful("/foo\tbar");
        assert!(matches!(
            r,
            Err(ParseError::ControlCharInUri { at: 4, byte: b'\t' })
        ));
    }

    #[test]
    fn rejects_del() {
        let r = parse_graceful("/foo\x7Fbar");
        assert!(matches!(
            r,
            Err(ParseError::ControlCharInUri { at: 4, byte: 0x7F })
        ));
    }

    #[test]
    fn rejects_control_char_in_query() {
        let r = parse_graceful("/foo?bar\rbaz");
        assert!(matches!(
            r,
            Err(ParseError::ControlCharInUri { at: 8, byte: b'\r' })
        ));
    }

    #[test]
    fn rejects_control_char_in_fragment() {
        let r = parse_graceful("/foo#bar\nbaz");
        assert!(matches!(
            r,
            Err(ParseError::ControlCharInUri { at: 8, byte: b'\n' })
        ));
    }

    #[test]
    fn rejects_too_long() {
        let big = "/".to_owned() + &"a".repeat(MAX_URI_LEN);
        let r = parse_graceful(&big);
        assert!(matches!(r, Err(ParseError::TooLong { .. })));
    }

    // ----------------------------------------------------------------------
    // Graceful vs strict
    // ----------------------------------------------------------------------

    #[test]
    fn graceful_accepts_unreserved_extras_in_path() {
        // `{`, `}`, `|`, `^`, `<`, `>` are not in RFC 3986 pchar — graceful
        // accepts (matching browsers and curl); strict rejects.
        for s in ["/path{x}", "/p|q", "/p^q", "/p<x>"] {
            let u = parse_graceful(s).unwrap();
            assert_lazy(&u, s, None, None);
            assert!(
                matches!(parse_strict(s), Err(ParseError::StrictViolation)),
                "strict should reject {s}"
            );
        }
    }

    #[test]
    fn strict_accepts_pchar_path() {
        let u = parse_strict("/a-b.c_d~e").unwrap();
        assert_lazy(&u, "/a-b.c_d~e", None, None);

        let u = parse_strict("/foo/bar/baz").unwrap();
        assert_lazy(&u, "/foo/bar/baz", None, None);

        let u = parse_strict("/a%20b").unwrap();
        assert_lazy(&u, "/a%20b", None, None);

        let u = parse_strict("/p?key=val").unwrap();
        assert_lazy(&u, "/p", Some("key=val"), None);
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

    #[test]
    fn strict_rejects_bad_pct_in_query_and_fragment() {
        assert!(matches!(
            parse_strict("/p?bad%"),
            Err(ParseError::InvalidPercentEncoding { .. })
        ));
        assert!(matches!(
            parse_strict("/p#bad%"),
            Err(ParseError::InvalidPercentEncoding { .. })
        ));
    }
}
