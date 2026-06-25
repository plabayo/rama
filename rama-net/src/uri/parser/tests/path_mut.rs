//! `Uri::path_mut()` — RAII guard for incremental path mutation.

use super::parse_graceful;
use crate::uri::{PathMatchOptions, Uri};

// ----------------------------------------------------------------------
// push_segment — basic shapes
// ----------------------------------------------------------------------

#[test]
fn push_segment_shapes() {
    for (start, segment, want) in [
        ("/", "x", "/x"),
        ("/foo", "bar", "/foo/bar"),
        ("/foo/", "bar", "/foo/bar"), // no double slash
        ("/a/b", "c", "/a/b/c"),
        ("https://example.com", "v1", "https://example.com/v1"),
        ("https://example.com/", "v1", "https://example.com/v1"),
    ] {
        let mut uri: Uri = parse_graceful(start).unwrap();
        uri.path_mut().push_segment(segment);
        assert_eq!(uri.to_string(), want, "start={start:?} seg={segment:?}");
    }
}

#[test]
fn push_segment_empty_path() {
    let mut uri: Uri = parse_graceful("https://example.com/x").unwrap();
    uri.set_path("");
    assert_eq!(uri.to_string(), "https://example.com");
    uri.path_mut().push_segment("v1");
    assert_eq!(uri.to_string(), "https://example.com/v1");
}

#[test]
fn push_segment_chained() {
    let mut uri: Uri = parse_graceful("/").unwrap();
    {
        let mut g = uri.path_mut();
        g.push_segment("api")
            .push_segment("v2")
            .push_segment("users");
    }
    assert_eq!(uri.to_string(), "/api/v2/users");
}

#[test]
fn push_segment_integer_and_bool() {
    let mut uri: Uri = parse_graceful("https://example.com/users").unwrap();
    uri.path_mut()
        .push_segment(42_u32)
        .push_segment(-7_i64)
        .push_segment(true);
    assert_eq!(uri.to_string(), "https://example.com/users/42/-7/true");
}

// ----------------------------------------------------------------------
// push_segment — auto-encoding (RFC 3986 pchar enforcement)
// ----------------------------------------------------------------------

#[test]
fn push_segment_encodes_structural_bytes() {
    // `/`, `?`, `#` — would change URI structure if unescaped.
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.path_mut()
        .push_segment("a/b")
        .push_segment("a?b")
        .push_segment("a#b");
    assert_eq!(uri.to_string(), "/p/a%2Fb/a%3Fb/a%23b");
}

#[test]
fn push_segment_encodes_control_bytes() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.path_mut().push_segment("a\nb").push_segment("a\0b");
    assert_eq!(uri.to_string(), "/p/a%0Ab/a%00b");
}

#[test]
fn push_segment_encodes_space_and_unreserved_punctuation() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    // Space and the printable-ASCII non-pchar bytes.
    uri.path_mut()
        .push_segment("hello world")
        .push_segment("a\"b")
        .push_segment("a<b>c")
        .push_segment("a[b]")
        .push_segment("a^b")
        .push_segment("a|b")
        .push_segment("a`b")
        .push_segment("a{b}")
        .push_segment("a\\b");
    assert_eq!(
        uri.to_string(),
        "/p/hello%20world/a%22b/a%3Cb%3Ec/a%5Bb%5D/a%5Eb/a%7Cb/a%60b/a%7Bb%7D/a%5Cb",
    );
}

#[test]
fn push_segment_encodes_non_ascii_utf8() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.path_mut().push_segment("café");
    assert_eq!(uri.to_string(), "/p/caf%C3%A9");
}

#[test]
fn push_segment_encodes_percent_literal() {
    // `%` itself is encoded to `%25` — pass decoded values, not
    // pre-encoded ones. `%2F` in the input becomes `%252F` on the wire.
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.path_mut().push_segment("a%2Fb");
    assert_eq!(uri.to_string(), "/p/a%252Fb");
}

#[test]
fn push_segment_passes_pchar_through() {
    // ALPHA, DIGIT, `-._~`, sub-delims `!$&'()*+,;=`, `:`, `@`
    // are all legal in pchar position — must NOT be encoded.
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.path_mut()
        .push_segment("AZaz09-._~")
        .push_segment("!$&'()*+,;=")
        .push_segment(":@");
    assert_eq!(uri.to_string(), "/p/AZaz09-._~/!$&'()*+,;=/:@");
}

// ----------------------------------------------------------------------
// pop_segment
// ----------------------------------------------------------------------

#[test]
fn pop_segment_shapes() {
    for (start, want_popped, want_remaining) in [
        ("/foo/bar", Some("bar"), "/foo"),
        ("/foo/", Some(""), "/foo"),
        ("/foo", Some("foo"), ""),
        ("/", Some(""), ""),
        ("/a/b/c", Some("c"), "/a/b"),
    ] {
        let mut uri: Uri = parse_graceful(start).unwrap();
        let popped = uri.path_mut().pop_segment();
        assert_eq!(
            popped.as_deref(),
            want_popped.map(str::as_bytes),
            "start={start:?}",
        );
        assert_eq!(uri.path().unwrap().as_encoded_str(), want_remaining);
    }
}

#[test]
fn pop_segment_empty_path_returns_none() {
    let mut uri: Uri = parse_graceful("https://example.com/x").unwrap();
    uri.set_path("");
    assert!(uri.path_mut().pop_segment().is_none());
}

#[test]
fn pop_segment_opaque_path_removes_all() {
    let mut uri: Uri = parse_graceful("data:text/plain").unwrap();
    let popped = uri.path_mut().pop_segment();
    assert_eq!(popped.as_deref(), Some(b"plain".as_ref()));
    assert_eq!(uri.path().unwrap().as_encoded_str(), "text");

    let popped = uri.path_mut().pop_segment();
    assert_eq!(popped.as_deref(), Some(b"text".as_ref()));
    assert_eq!(uri.path().unwrap().as_encoded_str(), "");
}

// ----------------------------------------------------------------------
// clear
// ----------------------------------------------------------------------

#[test]
fn clear_path() {
    let mut uri: Uri = parse_graceful("/a/b/c").unwrap();
    uri.path_mut().clear();
    assert_eq!(uri.to_string(), "");
    assert!(uri.path_mut().pop_segment().is_none());
}

#[test]
fn trim_trailing_slash_normalizes_to_single_rooted_path() {
    for (start, changed, want) in [
        ("/foo", false, "/foo"),
        ("/foo/", true, "/foo"),
        ("/foo////", true, "/foo"),
        ("//foo///", true, "/foo"),
        ("/", true, "/"),
        (
            "https://example.com/foo////?a=1",
            true,
            "https://example.com/foo?a=1",
        ),
    ] {
        let mut uri: Uri = parse_graceful(start).unwrap();
        assert_eq!(
            uri.path_mut().trim_trailing_slash(),
            changed,
            "start={start:?}"
        );
        assert_eq!(uri.to_string(), want, "start={start:?}");
    }
}

#[test]
fn append_trailing_slash_normalizes_to_single_trailing_slash() {
    for (start, changed, want) in [
        ("/foo", true, "/foo/"),
        ("/foo/", false, "/foo/"),
        ("/foo////", true, "/foo/"),
        ("//foo///", true, "/foo/"),
        ("/", false, "/"),
        (
            "https://example.com/foo////?a=1",
            true,
            "https://example.com/foo/?a=1",
        ),
    ] {
        let mut uri: Uri = parse_graceful(start).unwrap();
        assert_eq!(
            uri.path_mut().append_trailing_slash(),
            changed,
            "start={start:?}",
        );
        assert_eq!(uri.to_string(), want, "start={start:?}");
    }
}

#[test]
fn debug_impl_shows_current_path() {
    let mut uri: Uri = parse_graceful("/api/v1").unwrap();
    let g = uri.path_mut();
    let dbg = format!("{g:?}");
    assert!(dbg.contains("/api/v1"), "got {dbg:?}");
}

// ----------------------------------------------------------------------
// Push-then-pop round-trip — pop yields the raw encoded segment.
// ----------------------------------------------------------------------

#[test]
fn push_then_pop_yields_encoded_form() {
    let mut uri: Uri = parse_graceful("/api").unwrap();
    {
        let mut g = uri.path_mut();
        g.push_segment("a/b"); // becomes a%2Fb on the wire
    }
    assert_eq!(uri.to_string(), "/api/a%2Fb");
    let popped = uri.path_mut().pop_segment();
    assert_eq!(popped.as_deref(), Some(b"a%2Fb".as_ref()));
    assert_eq!(uri.to_string(), "/api");
}

// ----------------------------------------------------------------------
// push_segments — multi-segment append
// ----------------------------------------------------------------------

#[test]
fn push_segments_shapes() {
    for (start, segs, want) in [
        ("/api", "v2/users", "/api/v2/users"),
        ("/", "a/b/c", "/a/b/c"),
        ("https://example.com", "v1/x", "https://example.com/v1/x"),
        ("/api", "/v2/users", "/api/v2/users"), // leading slash absorbed
        ("/api", "v2//users", "/api/v2/users"), // internal `//` collapses
        ("/api", "v2/users/", "/api/v2/users/"), // trailing slash kept
    ] {
        let mut uri: Uri = parse_graceful(start).unwrap();
        uri.path_mut().push_segments(segs);
        assert_eq!(uri.to_string(), want, "start={start:?} segs={segs:?}");
    }
}

#[test]
fn push_segments_encodes_each_piece() {
    // `/` splits into separate segments; other non-pchar bytes are
    // percent-encoded within each piece.
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.path_mut().push_segments("a b/c?d");
    assert_eq!(uri.to_string(), "/p/a%20b/c%3Fd");
}

// ----------------------------------------------------------------------
// pop_segments — multi-segment removal
// ----------------------------------------------------------------------

#[test]
fn pop_segments_counts() {
    let mut uri: Uri = parse_graceful("/a/b/c/d").unwrap();
    assert_eq!(uri.path_mut().pop_segments(2), 2);
    assert_eq!(uri.path().unwrap().as_encoded_str(), "/a/b");
}

#[test]
fn pop_segments_stops_at_empty() {
    let mut uri: Uri = parse_graceful("/a/b").unwrap();
    assert_eq!(uri.path_mut().pop_segments(5), 2);
    assert_eq!(uri.path().unwrap().as_encoded_str(), "");
}

#[test]
fn pop_segments_zero_is_noop() {
    let mut uri: Uri = parse_graceful("/a/b").unwrap();
    assert_eq!(uri.path_mut().pop_segments(0), 0);
    assert_eq!(uri.path().unwrap().as_encoded_str(), "/a/b");
}

// ----------------------------------------------------------------------
// strip_prefix — leading path-prefix removal (case-sensitive)
// ----------------------------------------------------------------------

#[test]
fn strip_prefix_shapes() {
    for (start, prefix, want_stripped, want_path) in [
        ("/foo/bar", "foo", true, "/bar"),
        ("/foo/bar", "/foo/", true, "/bar"), // slashes on prefix ignored
        ("/foo/bar", "foo/b", false, "/foo/bar"), // mid-segment rejected (boundary)
        ("/foo/bar", "foo/bar", true, "/"),
        ("/foo", "foo", true, "/"),
        ("/foo/bar", "bar", false, "/foo/bar"), // no match: unchanged
        ("/foo/bar", "", true, "/foo/bar"),     // empty prefix: re-root only
    ] {
        let mut uri: Uri = parse_graceful(start).unwrap();
        let stripped = uri.path_mut().strip_prefix(prefix);
        assert_eq!(stripped, want_stripped, "start={start:?} prefix={prefix:?}");
        assert_eq!(
            uri.path().unwrap().as_encoded_str(),
            want_path,
            "start={start:?} prefix={prefix:?}",
        );
    }
}

#[test]
fn strip_prefix_preserves_query_and_authority() {
    let mut uri: Uri = parse_graceful("https://example.com/api/v1/users?q=1").unwrap();
    assert!(uri.path_mut().strip_prefix("api/v1"));
    assert_eq!(uri.to_string(), "https://example.com/users?q=1");
}

#[test]
fn strip_prefix_is_case_sensitive() {
    let mut uri: Uri = parse_graceful("/FOO/bar").unwrap();
    assert!(!uri.path_mut().strip_prefix("foo"));
    assert_eq!(uri.path().unwrap().as_encoded_str(), "/FOO/bar");
}

#[test]
fn strip_prefix_ignore_ascii_case_matches_mixed_case() {
    for (start, prefix, want_stripped, want_path) in [
        ("/FOO/bar", "foo", true, "/bar"),
        ("/foo/BAR", "FOO/bar", true, "/"),
        ("/Api/V1/users", "api/v1", true, "/users"),
        ("/foo/bar", "baz", false, "/foo/bar"),
    ] {
        let mut uri: Uri = parse_graceful(start).unwrap();
        let opts = PathMatchOptions {
            ignore_ascii_case: true,
            ..Default::default()
        };
        let stripped = uri.path_mut().strip_prefix_with_opts(prefix, opts);
        assert_eq!(stripped, want_stripped, "start={start:?} prefix={prefix:?}");
        assert_eq!(
            uri.path().unwrap().as_encoded_str(),
            want_path,
            "start={start:?} prefix={prefix:?}",
        );
    }
}
