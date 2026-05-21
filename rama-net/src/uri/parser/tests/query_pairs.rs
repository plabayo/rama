//! `QueryRef::pairs()` — iteration over URI query `name[=value]` pairs.

use std::borrow::Cow;

use super::parse_graceful;
use crate::uri::Uri;

/// Collect raw (no-decode) `(name, value)` tuples from `uri_str`'s query.
fn raw_pairs(uri_str: &str) -> Vec<(String, Option<String>)> {
    parse_graceful(uri_str)
        .unwrap()
        .query()
        .unwrap()
        .pairs()
        .map(|p| (p.name_raw().to_owned(), p.value_raw().map(str::to_owned)))
        .collect()
}

/// Collect form-decoded `(name, value)` tuples from `uri_str`'s query.
fn decoded_pairs(uri_str: &str) -> Vec<(String, Option<String>)> {
    parse_graceful(uri_str)
        .unwrap()
        .query()
        .unwrap()
        .pairs()
        .map(|p| {
            (
                p.name_decoded().into_owned(),
                p.value_decoded().map(Cow::into_owned),
            )
        })
        .collect()
}

/// Build the expected shape: `[("a", None), ("b", Some(""))]`-style literals
/// expand to the heap-owned form `raw_pairs` returns.
fn expected(pairs: &[(&str, Option<&str>)]) -> Vec<(String, Option<String>)> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), v.map(str::to_owned)))
        .collect()
}

// ----------------------------------------------------------------------
// Splitting shapes (raw view) — covers basic shapes, bare-vs-empty,
// empty-fragment drop, first-`=` only.
// ----------------------------------------------------------------------

#[test]
fn raw_pair_shapes() {
    for (input, want) in [
        // single pair shapes
        ("/p?foo", &[("foo", None)][..]),
        ("/p?foo=", &[("foo", Some(""))]),
        ("/p?foo=bar", &[("foo", Some("bar"))]),
        // multiple pairs
        (
            "/p?foo=bar&baz=qux",
            &[("foo", Some("bar")), ("baz", Some("qux"))],
        ),
        ("/p?a&b&c", &[("a", None), ("b", None), ("c", None)]),
        ("/p?a&b=2&c", &[("a", None), ("b", Some("2")), ("c", None)]),
        // empty-fragment dropping (leading/trailing/internal `&`)
        ("/p?&foo=bar", &[("foo", Some("bar"))]),
        ("/p?foo=bar&", &[("foo", Some("bar"))]),
        (
            "/p?foo=bar&&baz=qux",
            &[("foo", Some("bar")), ("baz", Some("qux"))],
        ),
        ("/p?&a=1&&b=2&", &[("a", Some("1")), ("b", Some("2"))]),
        // first `=` only splitting
        ("/p?a=b=c", &[("a", Some("b=c"))]),
        ("/p?=value", &[("", Some("value"))]),
        ("/p?=", &[("", Some(""))]),
        // absolute-form sanity
        (
            "https://api.example.com/search?q=rust&page=2",
            &[("q", Some("rust")), ("page", Some("2"))],
        ),
    ] {
        assert_eq!(raw_pairs(input), expected(want), "input: {input:?}");
    }
}

#[test]
fn empty_or_all_separator_queries_yield_nothing() {
    for input in ["/p?", "/p?&", "/p?&&", "/p?&&&"] {
        let u: Uri = parse_graceful(input).unwrap();
        assert_eq!(
            u.query().unwrap().pairs().count(),
            0,
            "expected no pairs for {input:?}",
        );
    }
}

#[test]
fn iterator_count_matches() {
    for (input, want) in [
        ("/p?foo", 1usize),
        ("/p?foo=bar", 1),
        ("/p?a&b&c", 3),
        ("/p?a=1&b=2&c=3", 3),
        ("/p?&&", 0),
        ("/p?", 0),
        ("/p?a&&b&", 2),
    ] {
        let u: Uri = parse_graceful(input).unwrap();
        assert_eq!(u.query().unwrap().pairs().count(), want, "input: {input:?}",);
    }
}

// ----------------------------------------------------------------------
// Bare-vs-empty-value distinction
// ----------------------------------------------------------------------

#[test]
fn has_value_reflects_equals_presence() {
    let u: Uri = parse_graceful("/p?bare&empty=&v=1").unwrap();
    let pairs: Vec<_> = u.query().unwrap().pairs().collect();
    assert_eq!(pairs.len(), 3);
    assert!(!pairs[0].has_value(), "?bare → no value");
    assert!(pairs[1].has_value(), "?empty= → Some(\"\")");
    assert!(pairs[2].has_value(), "?v=1 → Some(\"1\")");
    assert_eq!(pairs[0].value_bytes(), None);
    assert_eq!(pairs[1].value_bytes(), Some(b"".as_ref()));
    assert_eq!(pairs[2].value_bytes(), Some(b"1".as_ref()));
}

// ----------------------------------------------------------------------
// Form-decoding (`+` → space, `%XX` → byte) — covers basic decode,
// utf-8, malformed pct passthrough, mixed-case hex, raw-doesn't-decode.
// ----------------------------------------------------------------------

#[test]
fn form_decoding_shapes() {
    for (input, want) in [
        ("/p?msg=hello%20world", &[("msg", Some("hello world"))][..]),
        ("/p?msg=hello+world", &[("msg", Some("hello world"))]),
        (
            "/p?msg=hello+wide%20world",
            &[("msg", Some("hello wide world"))],
        ),
        ("/p?with+space=v", &[("with space", Some("v"))]),
        ("/p?city=caf%C3%A9", &[("city", Some("café"))]),
        // mixed-case hex
        ("/p?x=caf%C3%a9", &[("x", Some("café"))]),
        // malformed / trailing `%` → literal passthrough
        ("/p?x=a%ZZb", &[("x", Some("a%ZZb"))]),
        ("/p?x=trail%", &[("x", Some("trail%"))]),
        ("/p?x=trail%A", &[("x", Some("trail%A"))]),
    ] {
        assert_eq!(decoded_pairs(input), expected(want), "input: {input:?}");
    }
}

#[test]
fn raw_view_keeps_plus_and_percent_literal() {
    for (input, want) in [
        ("/p?a=b+c", &[("a", Some("b+c"))][..]),
        ("/p?a=b%20c", &[("a", Some("b%20c"))]),
    ] {
        assert_eq!(raw_pairs(input), expected(want), "input: {input:?}");
    }
}

#[test]
fn decoded_invalid_utf8_uses_replacement_char() {
    // `%FF` standalone is not valid UTF-8; lossy decode emits U+FFFD.
    let u: Uri = parse_graceful("/p?x=%FF").unwrap();
    let pair = u.query().unwrap().pairs().next().unwrap();
    let decoded = pair.value_decoded().unwrap();
    assert!(decoded.contains('\u{FFFD}'), "got {decoded:?}");
}

// ----------------------------------------------------------------------
// Cow::Borrowed vs Owned — verifies the documented zero-copy behaviour.
// ----------------------------------------------------------------------

#[test]
fn decoded_borrows_when_no_escapes_else_owns() {
    let u: Uri = parse_graceful("/p?foo=bar").unwrap();
    let pair = u.query().unwrap().pairs().next().unwrap();
    assert!(matches!(pair.name_decoded(), Cow::Borrowed(_)));
    assert!(matches!(pair.value_decoded(), Some(Cow::Borrowed(_))));

    for input in ["/p?foo=hello%20world", "/p?foo=a+b"] {
        let u: Uri = parse_graceful(input).unwrap();
        let pair = u.query().unwrap().pairs().next().unwrap();
        assert!(
            matches!(pair.value_decoded(), Some(Cow::Owned(_))),
            "expected Cow::Owned for {input:?}",
        );
    }
}

// ----------------------------------------------------------------------
// Iterator behaviour & owned/borrowed parity
// ----------------------------------------------------------------------

#[test]
fn iterator_fused_after_exhaustion() {
    let u: Uri = parse_graceful("/p?foo=bar").unwrap();
    let mut it = u.query().unwrap().pairs();
    assert!(it.next().is_some());
    assert!(it.next().is_none());
    assert!(it.next().is_none());
    assert!(it.next().is_none());
}

#[test]
fn owned_query_pairs_matches_ref() {
    let u: Uri = parse_graceful("/p?a=1&b=2").unwrap();
    let q_ref = u.query().unwrap();
    let from_ref: Vec<_> = q_ref
        .pairs()
        .map(|p| (p.name_raw().to_owned(), p.value_raw().map(str::to_owned)))
        .collect();
    let from_owned: Vec<_> = q_ref
        .to_owned()
        .pairs()
        .map(|p| (p.name_raw().to_owned(), p.value_raw().map(str::to_owned)))
        .collect();
    assert_eq!(from_ref, from_owned);
}

// ----------------------------------------------------------------------
// `eq_at` offset width — the cached `=` position inside a pair.
//
// The parser caps inputs at `MAX_URI_LEN` (u16-bounded), but the
// mutation API has no such cap — `query_mut().push_pair(big_key, ...)`
// can build a single pair larger than 65535 bytes. The eq offset must
// span that range; `u16` truncated silently and reported the wrong
// slice. The cache is now `u32`.
// ----------------------------------------------------------------------

#[test]
fn eq_offset_handles_70k_byte_key() {
    let key = "k".repeat(70_000);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair(key.as_str(), "v");
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_bytes().len(), 70_000);
    assert_eq!(pair.value_bytes().map(<[u8]>::len), Some(1));
}

#[test]
fn eq_offset_handles_100k_byte_value() {
    let value = "v".repeat(100_000);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair("k", value.as_str());
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_bytes(), b"k");
    assert_eq!(pair.value_bytes().map(<[u8]>::len), Some(100_000));
}

#[test]
fn eq_offset_at_exact_u16_boundary() {
    // 65535 bytes of key → `=` sits at offset 65535 = u16::MAX. `u16`
    // wraps to 0; `u32` stores it cleanly.
    let key = "k".repeat(65_535);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair(key.as_str(), "v");
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_bytes().len(), 65_535);
    assert_eq!(pair.value_bytes(), Some(&b"v"[..]));

    // 65536 — one past the u16 cap.
    let key = "k".repeat(65_536);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair(key.as_str(), "v");
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_bytes().len(), 65_536);
    assert_eq!(pair.value_bytes(), Some(&b"v"[..]));
}

#[test]
fn bare_key_with_huge_size_has_no_value() {
    // The `u16` → `u32` widening must not change semantics for bare
    // keys (`eq_at = None` stays `None`).
    let key = "k".repeat(70_000);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_key(key.as_str());
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_bytes().len(), 70_000);
    assert_eq!(pair.value_bytes(), None);
    assert!(!pair.has_value());
}

#[test]
fn huge_pair_via_pair_ref_iterator() {
    // Borrowed `QueryPairRef` has its own `eq_at: u32` — exercise it.
    let key = "k".repeat(70_000);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair(key.as_str(), "vvvv");
    let q = uri.query().unwrap();
    let pair_ref = q.pairs().next().unwrap();
    assert_eq!(pair_ref.name_bytes().len(), 70_000);
    assert_eq!(pair_ref.value_bytes(), Some(&b"vvvv"[..]));
    assert!(pair_ref.has_value());
}
