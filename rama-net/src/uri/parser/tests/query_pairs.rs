//! `QueryRef::pairs()` — iteration over URI query `name[=value]` pairs.

use crate::std::borrow::Cow;

use super::parse_graceful;
use crate::uri::Uri;

/// Collect encoded `(name, value)` tuples from `uri_str`'s query.
fn encoded_pairs(uri_str: &str) -> Vec<(String, Option<String>)> {
    parse_graceful(uri_str)
        .unwrap()
        .query()
        .unwrap()
        .pairs()
        .map(|p| {
            (
                p.name_encoded().into_owned(),
                p.value_encoded().map(|v| v.into_owned()),
            )
        })
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
/// expand to the heap-owned form `encoded_pairs` returns.
fn expected(pairs: &[(&str, Option<&str>)]) -> Vec<(String, Option<String>)> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), v.map(str::to_owned)))
        .collect()
}

// ----------------------------------------------------------------------
// Splitting shapes (encoded view) — covers basic shapes, bare-vs-empty,
// empty-fragment drop, first-`=` only.
// ----------------------------------------------------------------------

#[test]
fn encoded_pair_shapes() {
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
        ("/p?a=b=c", &[("a", Some("b%3Dc"))]),
        ("/p?=value", &[("", Some("value"))]),
        ("/p?=", &[("", Some(""))]),
        // absolute-form sanity
        (
            "https://api.example.com/search?q=rust&page=2",
            &[("q", Some("rust")), ("page", Some("2"))],
        ),
    ] {
        assert_eq!(encoded_pairs(input), expected(want), "input: {input:?}");
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
    assert_eq!(pairs[0].value_encoded(), None);
    assert_eq!(pairs[1].value_encoded().as_deref(), Some(""));
    assert_eq!(pairs[2].value_encoded().as_deref(), Some("1"));
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
fn encoded_view_escapes_form_plus_and_preserves_pct_triplets() {
    for (input, want) in [
        ("/p?a=b+c", &[("a", Some("b%2Bc"))][..]),
        ("/p?a=b%20c", &[("a", Some("b%20c"))]),
    ] {
        assert_eq!(encoded_pairs(input), expected(want), "input: {input:?}");
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
        .map(|p| {
            (
                p.name_encoded().into_owned(),
                p.value_encoded().map(|v| v.into_owned()),
            )
        })
        .collect();
    let from_owned: Vec<_> = q_ref
        .into_owned()
        .pairs()
        .map(|p| {
            (
                p.name_encoded().into_owned(),
                p.value_encoded().map(|v| v.into_owned()),
            )
        })
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
    assert_eq!(pair.name_encoded().len(), 70_000);
    assert_eq!(pair.value_encoded().as_deref().map(str::len), Some(1));
}

#[test]
fn eq_offset_handles_100k_byte_value() {
    let value = "v".repeat(100_000);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair("k", value.as_str());
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_encoded(), "k");
    assert_eq!(pair.value_encoded().as_deref().map(str::len), Some(100_000));
}

#[test]
fn eq_offset_at_exact_u16_boundary() {
    // 65535 bytes of key → `=` sits at offset 65535 = u16::MAX. `u16`
    // wraps to 0; `u32` stores it cleanly.
    let key = "k".repeat(65_535);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair(key.as_str(), "v");
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_encoded().len(), 65_535);
    assert_eq!(pair.value_encoded().as_deref(), Some("v"));

    // 65536 — one past the u16 cap.
    let key = "k".repeat(65_536);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair(key.as_str(), "v");
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_encoded().len(), 65_536);
    assert_eq!(pair.value_encoded().as_deref(), Some("v"));
}

#[test]
fn bare_key_with_huge_size_has_no_value() {
    // The `u16` → `u32` widening must not change semantics for bare
    // keys (`eq_at = None` stays `None`).
    let key = "k".repeat(70_000);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_key(key.as_str());
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_encoded().len(), 70_000);
    assert_eq!(pair.value_encoded(), None);
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
    assert_eq!(pair_ref.name_encoded().len(), 70_000);
    assert_eq!(pair_ref.value_encoded().as_deref(), Some("vvvv"));
    assert!(pair_ref.has_value());
}

// ----------------------------------------------------------------------
// first_value / values / contains_name — by-name lookup
// ----------------------------------------------------------------------

#[test]
fn first_value_returns_first_match_form_decoded() {
    let uri = parse_graceful("/p?tag=a+b&tag=c%20d&x=1").unwrap();
    let q = uri.query().unwrap();
    assert_eq!(q.first_value("tag").as_deref(), Some("a b"));
    assert_eq!(q.first_value("x").as_deref(), Some("1"));
    assert_eq!(q.first_value("zz"), None);
}

#[test]
fn first_value_matches_names_form_decoded() {
    // `a+b` and `a%20b` both decode to the name "a b".
    let uri = parse_graceful("/p?a+b=1").unwrap();
    assert_eq!(
        uri.query().unwrap().first_value("a b").as_deref(),
        Some("1")
    );
    let uri = parse_graceful("/p?a%20b=2").unwrap();
    assert_eq!(
        uri.query().unwrap().first_value("a b").as_deref(),
        Some("2")
    );
}

#[test]
fn first_value_bare_key_yields_empty() {
    // WHATWG convention (same as `deserialize`): `?foo` reads as `foo=""`.
    let uri = parse_graceful("/p?foo&bar=1").unwrap();
    assert_eq!(uri.query().unwrap().first_value("foo").as_deref(), Some(""));
}

#[test]
fn values_yields_every_match_in_order() {
    let uri = parse_graceful("/p?tag=a&x=0&tag&tag=c").unwrap();
    let q = uri.query().unwrap();
    let values: Vec<_> = q.values("tag").collect();
    assert_eq!(values, ["a", "", "c"]);
    assert_eq!(q.values("zz").count(), 0);
}

#[test]
fn contains_name_matches_pairs_and_bare_keys() {
    let uri = parse_graceful("/p?foo&a=1").unwrap();
    let q = uri.query().unwrap();
    assert!(q.contains_name("foo"));
    assert!(q.contains_name("a"));
    assert!(!q.contains_name("bar"));
    assert!(!q.contains_name("1")); // values are not names
}

#[test]
fn owned_query_lookup_delegates_to_view() {
    let owned = parse_graceful("/p?a=1&a=2")
        .unwrap()
        .query()
        .unwrap()
        .into_owned();
    assert_eq!(owned.first_value("a").as_deref(), Some("1"));
    assert_eq!(owned.values("a").count(), 2);
    assert!(owned.contains_name("a"));
    assert!(!owned.contains_name("b"));
    assert!(!owned.is_empty());
}

#[test]
fn query_is_empty_distinguishes_empty_from_content() {
    let uri = parse_graceful("/p?").unwrap();
    assert!(uri.query().unwrap().is_empty());
    assert!(uri.query().unwrap().into_owned().is_empty());
    let uri = parse_graceful("/p?a").unwrap();
    assert!(!uri.query().unwrap().is_empty());
    assert!(!uri.query().unwrap().into_owned().is_empty());
}

// ----------------------------------------------------------------------
// Uri-level shortcuts — query_pairs / first_query_value / query_values /
// contains_query_name
// ----------------------------------------------------------------------

#[test]
fn uri_query_lookup_shortcuts() {
    let uri = parse_graceful("/p?tag=a&x=1&tag=b&bare").unwrap();
    assert_eq!(uri.first_query_value("tag").as_deref(), Some("a"));
    assert_eq!(uri.first_query_value("bare").as_deref(), Some(""));
    assert_eq!(uri.first_query_value("zz"), None);
    let tags: Vec<_> = uri.query_values("tag").collect();
    assert_eq!(tags, ["a", "b"]);
    assert!(uri.contains_query_name("x"));
    assert!(!uri.contains_query_name("y"));
    assert_eq!(uri.query_pairs().count(), 4);
}

#[test]
fn uri_query_lookup_without_query_is_empty() {
    let uri = parse_graceful("/p").unwrap();
    assert_eq!(uri.first_query_value("a"), None);
    assert_eq!(uri.query_values("a").count(), 0);
    assert!(!uri.contains_query_name("a"));
    assert_eq!(uri.query_pairs().count(), 0);

    // asterisk-form behaves the same
    let uri = parse_graceful("*").unwrap();
    assert_eq!(uri.first_query_value("a"), None);
    assert_eq!(uri.query_values("a").count(), 0);
    assert!(!uri.contains_query_name("a"));
    assert_eq!(uri.query_pairs().count(), 0);
}

#[test]
fn name_lookup_normalizes_component_patterns() {
    // Names compare form-decoded on BOTH sides — `a b`, `a+b`, and
    // `a%20b` all address the same name, mirroring how the path
    // matchers normalize their patterns.
    let uri = parse_graceful("/p?a+b=1&n=2").unwrap();
    let q = uri.query().unwrap();
    assert_eq!(q.first_value("a b").as_deref(), Some("1"));
    assert_eq!(q.first_value("a+b").as_deref(), Some("1"));
    assert_eq!(q.first_value("a%20b").as_deref(), Some("1"));
    assert!(q.contains_name("a+b"));
    assert_eq!(q.values("a%20b").count(), 1);
}

#[test]
fn name_lookup_accepts_scalar_component_inputs() {
    // Same input flexibility as the other IntoUriComponent takers.
    let uri = parse_graceful("/p?42=x&flag=1").unwrap();
    let q = uri.query().unwrap();
    assert_eq!(q.first_value(42).as_deref(), Some("x"));
    assert!(q.contains_name(42_u16));
    assert!(uri.contains_query_name(42));
    assert_eq!(uri.first_query_value(42).as_deref(), Some("x"));
}
