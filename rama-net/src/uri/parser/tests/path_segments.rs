//! `PathRef::segments()` — iteration over URI path segments.

use super::parse_graceful;

/// Collect segments as raw `&str` (no percent-decoding) for assertion.
fn raw_segments(uri_str: &str) -> Vec<String> {
    let u = parse_graceful(uri_str).unwrap();
    u.path()
        .unwrap()
        .segments()
        .map(|s| s.as_raw_str().to_owned())
        .collect()
}

/// Collect segments as percent-decoded `String` for assertion.
fn decoded_segments(uri_str: &str) -> Vec<String> {
    let u = parse_graceful(uri_str).unwrap();
    u.path()
        .unwrap()
        .segments()
        .map(|s| s.as_decoded_str().into_owned())
        .collect()
}

// ----------------------------------------------------------------------
// Basic origin-form segmentation
// ----------------------------------------------------------------------

#[test]
fn root_yields_one_empty_segment() {
    // url::Url::path_segments parity: "/" -> [""].
    assert_eq!(raw_segments("/"), vec![""]);
}

#[test]
fn single_segment() {
    assert_eq!(raw_segments("/foo"), vec!["foo"]);
}

#[test]
fn multi_segment() {
    assert_eq!(raw_segments("/foo/bar/baz"), vec!["foo", "bar", "baz"]);
}

#[test]
fn trailing_slash_yields_empty_segment() {
    // `/foo/` is distinct from `/foo` — trailing empty preserves that.
    assert_eq!(raw_segments("/foo/"), vec!["foo", ""]);
}

#[test]
fn double_slash_preserves_empty_segment() {
    assert_eq!(raw_segments("/a//b"), vec!["a", "", "b"]);
}

#[test]
fn deep_path() {
    assert_eq!(raw_segments("/a/b/c/d/e"), vec!["a", "b", "c", "d", "e"]);
}

// ----------------------------------------------------------------------
// Empty path / leading slash absence
// ----------------------------------------------------------------------

#[test]
fn absolute_form_empty_path_yields_nothing() {
    // `http://example.com` — path is empty (path-abempty).
    let u = parse_graceful("http://example.com").unwrap();
    let segs: Vec<_> = u.path().unwrap().segments().collect();
    assert!(segs.is_empty());
}

#[test]
fn opaque_path_splits_from_start() {
    // urn:isbn:0451450523 — path is `isbn:0451450523`, no leading `/`.
    let u = parse_graceful("urn:isbn:0451450523").unwrap();
    let segs: Vec<_> = u
        .path()
        .unwrap()
        .segments()
        .map(|s| s.as_raw_str().to_owned())
        .collect();
    // One segment because there's no `/` in `isbn:0451450523`.
    assert_eq!(segs, vec!["isbn:0451450523"]);
}

#[test]
fn opaque_path_without_slashes() {
    // mailto's path = "user@example.com" — no `/`, one segment.
    let u = parse_graceful("mailto:user@example.com").unwrap();
    let segs: Vec<_> = u
        .path()
        .unwrap()
        .segments()
        .map(|s| s.as_raw_str().to_owned())
        .collect();
    assert_eq!(segs, vec!["user@example.com"]);
}

#[test]
fn opaque_path_with_slashes_splits_from_start() {
    // data:text/plain — opaque path "text/plain" with internal `/`.
    // No leading `/` to strip; split happens from the first byte.
    let u = parse_graceful("data:text/plain").unwrap();
    let segs: Vec<_> = u
        .path()
        .unwrap()
        .segments()
        .map(|s| s.as_raw_str().to_owned())
        .collect();
    assert_eq!(segs, vec!["text", "plain"]);
}

#[test]
fn asterisk_has_no_path_so_no_segments() {
    let u = parse_graceful("*").unwrap();
    assert!(u.path().is_none());
}

// ----------------------------------------------------------------------
// Absolute-form
// ----------------------------------------------------------------------

#[test]
fn absolute_form_segments() {
    assert_eq!(
        raw_segments("https://api.example.com/v1/users/42"),
        vec!["v1", "users", "42"]
    );
}

#[test]
fn absolute_form_with_trailing_slash() {
    assert_eq!(
        raw_segments("https://api.example.com/v1/users/"),
        vec!["v1", "users", ""]
    );
}

// ----------------------------------------------------------------------
// Percent-decoding
// ----------------------------------------------------------------------

#[test]
fn decoded_simple_space() {
    // `%20` → ` ` (space).
    assert_eq!(decoded_segments("/hello%20world"), vec!["hello world"]);
}

#[test]
fn decoded_slash_in_segment() {
    // `%2F` is a literal `/` byte inside a segment. The segment
    // iterator must NOT decode `%2F` into `/` AT THE BOUNDARY level
    // (it's a path-traversal vector if used for routing).
    //
    // Raw segments split on actual `/` bytes only:
    assert_eq!(
        raw_segments("/admin/%2F../secret"),
        vec!["admin", "%2F..", "secret"]
    );
    // But `decoded()` does decode `%2F` to `/` inside the segment value
    // — that's the per-segment view; caller must not concatenate
    // decoded values and re-split.
    assert_eq!(
        decoded_segments("/admin/%2F../secret"),
        vec!["admin", "/..", "secret"]
    );
}

#[test]
fn decoded_utf8_segment() {
    // `%C3%A9` is `é` in UTF-8.
    assert_eq!(decoded_segments("/caf%C3%A9"), vec!["café"]);
}

#[test]
fn decoded_no_percent_borrows() {
    // Sanity: when there's no `%`, decoded() returns Cow::Borrowed
    // (no allocation). Verify by checking the variant.
    let u = parse_graceful("/foo/bar").unwrap();
    let segs: Vec<_> = u.path().unwrap().segments().collect();
    assert!(matches!(
        segs[0].as_decoded_str(),
        std::borrow::Cow::Borrowed(_)
    ));
    assert!(matches!(
        segs[1].as_decoded_str(),
        std::borrow::Cow::Borrowed(_)
    ));
}

#[test]
fn decoded_with_percent_owns() {
    // When `%XX` is present, decoded() must own (the result differs
    // from the input bytes).
    let u = parse_graceful("/hello%20world").unwrap();
    let seg = u.path().unwrap().segments().next().unwrap();
    assert!(matches!(seg.as_decoded_str(), std::borrow::Cow::Owned(_)));
}

#[test]
fn decoded_invalid_utf8_uses_replacement_char() {
    // `%FF` is not valid UTF-8 standalone. Lossy decode emits U+FFFD.
    let u = parse_graceful("/%FF").unwrap();
    let seg = u.path().unwrap().segments().next().unwrap();
    let decoded = seg.as_decoded_str();
    // Should contain replacement char `\u{FFFD}`.
    assert!(decoded.contains('\u{FFFD}'), "got {decoded:?}");
}

// ----------------------------------------------------------------------
// PathSegment::is_empty
// ----------------------------------------------------------------------

#[test]
fn empty_segment_is_empty() {
    let u = parse_graceful("/foo/").unwrap();
    let segs: Vec<_> = u.path().unwrap().segments().collect();
    assert!(!segs[0].is_empty()); // "foo"
    assert!(segs[1].is_empty()); // trailing ""
}

// ----------------------------------------------------------------------
// Iterator behaviour
// ----------------------------------------------------------------------

#[test]
fn iterator_fused_after_exhaustion() {
    let u = parse_graceful("/foo").unwrap();
    let mut it = u.path().unwrap().segments();
    assert_eq!(it.next().unwrap().as_raw_str(), "foo");
    assert!(it.next().is_none());
    // Fused — subsequent calls keep returning None.
    assert!(it.next().is_none());
    assert!(it.next().is_none());
}

#[test]
fn iterator_count_matches() {
    for (path, expected_count) in [
        ("/foo", 1),
        ("/foo/bar", 2),
        ("/foo/bar/baz", 3),
        ("/", 1),
        ("/foo/", 2),
        ("/a//b", 3),
    ] {
        let u = parse_graceful(path).unwrap();
        assert_eq!(
            u.path().unwrap().segments().count(),
            expected_count,
            "count mismatch for {path:?}"
        );
    }
}

#[test]
fn exact_size_len_and_size_hint() {
    for (path, n) in [
        ("/foo", 1usize),
        ("/foo/bar", 2),
        ("/foo/bar/baz", 3),
        ("/", 1),
        ("/foo/", 2),
        ("/a//b", 3),
    ] {
        let u = parse_graceful(path).unwrap();
        let it = u.path().unwrap().segments();
        assert_eq!(it.len(), n, "len for {path:?}");
        assert_eq!(it.size_hint(), (n, Some(n)), "size_hint for {path:?}");
    }
    // Empty path -> zero-length iterator.
    let u = parse_graceful("http://example.com").unwrap();
    assert_eq!(u.path().unwrap().segments().len(), 0);
}

#[test]
fn len_tracks_remaining_as_it_advances() {
    let u = parse_graceful("/a/b/c").unwrap();
    let mut it = u.path().unwrap().segments();
    assert_eq!(it.len(), 3);
    it.next();
    assert_eq!(it.len(), 2);
    it.next();
    assert_eq!(it.len(), 1);
    it.next();
    assert_eq!(it.len(), 0);
    assert!(it.next().is_none());
    assert_eq!(it.len(), 0);
}

// ----------------------------------------------------------------------
// Positional accessors: nth/first/last_segment, segment_count
// ----------------------------------------------------------------------

#[test]
fn positional_accessors() {
    let u = parse_graceful("/v1/users/42").unwrap();
    let p = u.path().unwrap();
    assert_eq!(p.first_segment().unwrap().as_raw_str(), "v1");
    assert_eq!(p.nth_segment(1).unwrap().as_raw_str(), "users");
    assert_eq!(p.last_segment().unwrap().as_raw_str(), "42");
    assert_eq!(p.nth_segment(3), None);
    assert_eq!(p.segment_count(), 3);
}

#[test]
fn last_segment_of_trailing_slash_is_empty() {
    let u = parse_graceful("/foo/").unwrap();
    let p = u.path().unwrap();
    assert!(p.last_segment().unwrap().is_empty());
    assert_eq!(p.segment_count(), 2);
}

#[test]
fn accessors_on_empty_path() {
    let u = parse_graceful("http://example.com").unwrap();
    let p = u.path().unwrap();
    assert_eq!(p.first_segment(), None);
    assert_eq!(p.last_segment(), None);
    assert_eq!(p.nth_segment(0), None);
    assert_eq!(p.segment_count(), 0);
}
