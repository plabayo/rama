//! Graceful-vs-strict policy difference coverage.
//!
//! `Uri::parse_strict` enforces RFC 3986 grammar; `Uri::parse` accepts the
//! looser real-wire envelope. These tests exercise the gap between them
//! and confirm strict produces the typed error variants we expect.

use super::{assert_origin_form, parse_graceful, parse_strict};
use crate::uri::ParseError;

// ----------------------------------------------------------------------
// Graceful accepts where strict rejects (per-component byte set)
// ----------------------------------------------------------------------

#[test]
fn graceful_accepts_unreserved_extras_in_path() {
    // `{`, `}`, `|`, `^`, `<`, `>` are not in RFC 3986 pchar.
    for s in ["/path{x}", "/p|q", "/p^q", "/p<x>"] {
        let u = parse_graceful(s).unwrap();
        assert_origin_form(&u, s, None, None);
        assert!(
            matches!(parse_strict(s), Err(ParseError::StrictViolation)),
            "strict should reject {s:?}"
        );
    }
}

#[test]
fn graceful_accepts_extras_in_query_and_fragment() {
    for s in ["/p?key={val}", "/p?ab|cd", "/p#frag^x", "/p#tag<x>"] {
        assert!(parse_graceful(s).is_ok(), "graceful should accept {s:?}");
        assert!(
            matches!(parse_strict(s), Err(ParseError::StrictViolation)),
            "strict should reject {s:?}"
        );
    }
}

#[test]
fn graceful_accepts_high_byte_in_path() {
    // Raw non-ASCII byte in path. Graceful accepts (matches browser /
    // curl behaviour on the wire), strict rejects (outside pchar).
    let s = b"/p\xc3\xa9foo"; // UTF-8 "/péfoo"
    let buf = rama_core::bytes::Bytes::copy_from_slice(s);
    crate::uri::Uri::parse_bytes(buf.clone()).unwrap();
    assert!(matches!(
        crate::uri::Uri::parse_bytes_strict(buf),
        Err(ParseError::StrictViolation)
    ));
}

// ----------------------------------------------------------------------
// Strict accepts canonical pchar
// ----------------------------------------------------------------------

#[test]
fn strict_accepts_pchar_path() {
    for s in [
        "/foo",
        "/a/b/c",
        "/a-b.c_d~e",
        "/a%20b",
        "/p:q@r",
        "/p?key=val",
    ] {
        assert!(parse_strict(s).is_ok(), "strict should accept {s:?}");
    }
}

#[test]
fn strict_accepts_well_formed_absolute() {
    for s in [
        "http://example.com/",
        "https://api.example.com:443/v1/users",
        "ftp://ftp.example.org/pub/file.txt",
        "ws://chat.example.com/socket",
        "urn:isbn:0451450523",
        "mailto:user@example.com",
    ] {
        assert!(
            parse_strict(s).is_ok(),
            "strict should accept {s:?}, got {:?}",
            parse_strict(s)
        );
    }
}

// ----------------------------------------------------------------------
// Strict-only rejections
// ----------------------------------------------------------------------

#[test]
fn strict_rejects_non_pchar_in_absolute_path() {
    for s in [
        "http://example.com/p{x}",
        "http://example.com/p|q",
        "http://example.com/p^q",
        "http://example.com/p<q>",
    ] {
        assert!(
            matches!(parse_strict(s), Err(ParseError::StrictViolation)),
            "strict must reject {s:?}"
        );
    }
}

#[test]
fn strict_rejects_non_pchar_in_query_and_fragment() {
    for s in ["http://example.com/?p{x}", "http://example.com/#frag|x"] {
        assert!(matches!(parse_strict(s), Err(ParseError::StrictViolation)));
    }
}

#[test]
fn strict_rejects_bad_percent_encoding_in_path() {
    for s in ["/foo%", "/foo%a", "/foo%zz", "/foo%g0"] {
        assert!(
            matches!(
                parse_strict(s),
                Err(ParseError::InvalidPercentEncoding { .. })
            ),
            "got {:?} for {s:?}",
            parse_strict(s)
        );
    }
}

#[test]
fn strict_rejects_bad_percent_encoding_in_query_and_fragment() {
    assert!(matches!(
        parse_strict("/p?bad%"),
        Err(ParseError::InvalidPercentEncoding { .. })
    ));
    assert!(matches!(
        parse_strict("/p#bad%"),
        Err(ParseError::InvalidPercentEncoding { .. })
    ));
}

// ----------------------------------------------------------------------
// Percent-encoded specials (the RFC 3986 §6.2.2.2 "encoded reserved
// characters preserved as-is" rule)
// ----------------------------------------------------------------------

#[test]
fn percent_encoded_specials_preserved_in_path() {
    // `%23` (#), `%3F` (?), `%2F` (/) inside path bytes must NOT be
    // decoded as delimiters. Each parses as part of the path.
    for (s, expected_path) in [
        ("/abc%23def", "/abc%23def"),
        ("/abc%3Fdef", "/abc%3Fdef"),
        ("/abc%2Fdef", "/abc%2Fdef"),
    ] {
        let u = parse_graceful(s).unwrap();
        assert_origin_form(&u, expected_path, None, None);
    }
}

#[test]
fn percent_encoded_specials_preserved_in_query() {
    // `%23` (#) in a query is a literal byte, not a fragment-start.
    let u = parse_graceful("/p?q=%23anchor").unwrap();
    assert_origin_form(&u, "/p", Some("q=%23anchor"), None);
}

// ----------------------------------------------------------------------
// Strict-mode userinfo grammar (RFC 3986 §3.2.1)
//
// userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
//
// `@` is NOT in the set — it's the userinfo terminator. A raw `@` inside
// the userinfo bytes (which only happens via the lenient last-`@` split
// on inputs with multiple `@`s) is a strict violation. Per RFC, it MUST
// be percent-encoded as `%40`.
// ----------------------------------------------------------------------

#[test]
fn strict_accepts_valid_userinfo_chars() {
    // Unreserved + sub-delims + `:` are all permitted.
    for s in [
        "http://user@example.com/",
        "http://user:pass@example.com/",
        "http://a-b.c_d~e@example.com/",
        "http://us!er$tag@example.com/",
        "http://u(s)e+r,1;2=3@example.com/",
        "http://user%40info@example.com/", // %40 = encoded `@`
    ] {
        assert!(parse_strict(s).is_ok(), "strict should accept {s:?}");
    }
}

#[test]
fn strict_rejects_at_in_userinfo() {
    // `user@info@host` — last-`@` split puts `user@info` in userinfo, but
    // `@` is not in the userinfo grammar. Graceful accepts (real-world
    // parity); strict rejects with StrictViolation.
    let graceful = parse_graceful("http://user@info@example.com/").unwrap();
    assert!(!graceful.is_asterisk()); // smoke: parses
    assert!(matches!(
        parse_strict("http://user@info@example.com/"),
        Err(ParseError::StrictViolation)
    ));
}

#[test]
fn strict_rejects_non_userinfo_byte_classes() {
    // `{`, `}`, `|`, `<`, `>`, `[`, `]` aren't in the userinfo grammar.
    // Graceful accepts; strict rejects.
    for s in [
        "http://us{er}@example.com/",
        "http://us|er@example.com/",
        "http://us<er>@example.com/",
    ] {
        assert!(parse_graceful(s).is_ok(), "graceful should accept {s:?}");
        assert!(
            matches!(parse_strict(s), Err(ParseError::StrictViolation)),
            "strict should reject {s:?}"
        );
    }
}

#[test]
fn strict_rejects_bad_pct_in_userinfo() {
    // `%` not followed by two hex digits inside the userinfo run.
    for s in [
        "http://user%@example.com/",
        "http://user%z@example.com/",
        "http://user%zz@example.com/",
    ] {
        assert!(
            matches!(
                parse_strict(s),
                Err(ParseError::InvalidPercentEncoding { .. })
            ),
            "got {:?} for {s:?}",
            parse_strict(s)
        );
    }
}
