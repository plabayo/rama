//! Origin-form `/path?query#fragment` — HTTP request-target with no scheme
//! / authority. Also covers the asterisk-form `*` since it's adjacent.

use super::{assert_origin_form, parse_graceful, parse_strict};
use crate::uri::{Component, ParseError, UriInner};

// ----------------------------------------------------------------------
// Asterisk-form (HTTP-only, RFC 9112 §3.2.4)
// ----------------------------------------------------------------------

#[test]
fn asterisk_only_graceful() {
    let u = parse_graceful("*").unwrap();
    assert!(matches!(u.inner, UriInner::Asterisk));
}

#[test]
fn asterisk_only_strict() {
    let u = parse_strict("*").unwrap();
    assert!(matches!(u.inner, UriInner::Asterisk));
}

#[test]
fn asterisk_only_matches_exactly() {
    // `*foo` is NOT asterisk-form — should NOT match.
    let r = parse_graceful("*foo");
    assert!(matches!(
        r,
        Err(ParseError::InvalidComponent(Component::Scheme))
    ));
}

// ----------------------------------------------------------------------
// Origin-form: exact-content assertions
// ----------------------------------------------------------------------

#[test]
fn path_only() {
    let u = parse_graceful("/foo").unwrap();
    assert_origin_form(&u, "/foo", None, None);
}

#[test]
fn root_only() {
    let u = parse_graceful("/").unwrap();
    assert_origin_form(&u, "/", None, None);
}

#[test]
fn multi_segment_path() {
    let u = parse_graceful("/a/b/c").unwrap();
    assert_origin_form(&u, "/a/b/c", None, None);
}

#[test]
fn path_with_query() {
    let u = parse_graceful("/foo?bar=baz").unwrap();
    assert_origin_form(&u, "/foo", Some("bar=baz"), None);
}

#[test]
fn path_with_fragment() {
    let u = parse_graceful("/foo#section").unwrap();
    assert_origin_form(&u, "/foo", None, Some("section"));
}

#[test]
fn path_with_query_and_fragment() {
    let u = parse_graceful("/foo?bar=baz#frag").unwrap();
    assert_origin_form(&u, "/foo", Some("bar=baz"), Some("frag"));
}

#[test]
fn empty_query_distinct_from_none() {
    // `/foo?` is distinct from `/foo` — Some("") vs None.
    let with = parse_graceful("/foo?").unwrap();
    assert_origin_form(&with, "/foo", Some(""), None);

    let without = parse_graceful("/foo").unwrap();
    assert_origin_form(&without, "/foo", None, None);
}

#[test]
fn empty_fragment_distinct_from_none() {
    let with = parse_graceful("/foo#").unwrap();
    assert_origin_form(&with, "/foo", None, Some(""));

    let without = parse_graceful("/foo").unwrap();
    assert_origin_form(&without, "/foo", None, None);
}

#[test]
fn empty_query_and_empty_fragment() {
    let u = parse_graceful("/foo?#").unwrap();
    assert_origin_form(&u, "/foo", Some(""), Some(""));
}

#[test]
fn only_first_question_mark_ends_path() {
    // RFC 3986 §3.4: only the first `?` ends the path; subsequent `?` are
    // valid query bytes.
    let u = parse_graceful("/foo?a=b?c=d").unwrap();
    assert_origin_form(&u, "/foo", Some("a=b?c=d"), None);
}

#[test]
fn fragment_containing_question_mark() {
    // `?` is a valid fragment byte.
    let u = parse_graceful("/foo#frag?x").unwrap();
    assert_origin_form(&u, "/foo", None, Some("frag?x"));
}

#[test]
fn hash_inside_query_starts_fragment() {
    let u = parse_graceful("/p?q#f").unwrap();
    assert_origin_form(&u, "/p", Some("q"), Some("f"));
}

// ----------------------------------------------------------------------
// Path content preserved literally (no normalization)
// ----------------------------------------------------------------------

#[test]
fn dot_segments_preserved_literally() {
    // `/.`, `/..`, `/a/./b`, `/a/../b` etc. are *bytes*, not directives.
    // Normalization is a separate opt-in op (lands M5/M6); the parser
    // must preserve the wire bytes verbatim.
    for s in ["/.", "/..", "/a/./b", "/a/../b", "/./", "/../"] {
        let u = parse_graceful(s).unwrap();
        assert_origin_form(&u, s, None, None);
    }
}

#[test]
fn empty_segments_preserved() {
    // `/foo//bar` — empty segment between `foo` and `bar`. RFC 3986 path
    // grammar allows empty segments. Parser must not collapse them.
    let u = parse_graceful("/foo//bar").unwrap();
    assert_origin_form(&u, "/foo//bar", None, None);
}

#[test]
fn trailing_slash_preserved() {
    let u = parse_graceful("/foo/").unwrap();
    assert_origin_form(&u, "/foo/", None, None);
}
