//! `QueryRef::pairs()` — iteration over URI query `name[=value]` pairs.
//!
//! Splitting follows WHATWG URLSearchParams / `application/x-www-form-urlencoded`
//! parse rules. See `QueryRef::pairs` rustdoc for the contract.

use std::borrow::Cow;

use super::parse_graceful;
use crate::uri::Uri;

/// Helper: parse `uri_str` and return its query pairs as `(name, value)`
/// tuples using raw `&str` form (no decoding).
fn raw_pairs(uri_str: &str) -> Vec<(String, Option<String>)> {
    let u: Uri = parse_graceful(uri_str).unwrap();
    u.query()
        .unwrap()
        .pairs()
        .map(|p| (p.name_raw().to_owned(), p.value_raw().map(str::to_owned)))
        .collect()
}

/// Helper: parse `uri_str` and return its query pairs as form-decoded
/// `(name, value)` tuples.
fn decoded_pairs(uri_str: &str) -> Vec<(String, Option<String>)> {
    let u: Uri = parse_graceful(uri_str).unwrap();
    u.query()
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

// ----------------------------------------------------------------------
// Basic shapes
// ----------------------------------------------------------------------

#[test]
fn single_bare_key() {
    // `?foo` — value None.
    assert_eq!(raw_pairs("/p?foo"), vec![("foo".into(), None)]);
}

#[test]
fn single_key_empty_value() {
    // `?foo=` — value Some("").
    assert_eq!(raw_pairs("/p?foo="), vec![("foo".into(), Some("".into()))]);
}

#[test]
fn single_key_value() {
    assert_eq!(
        raw_pairs("/p?foo=bar"),
        vec![("foo".into(), Some("bar".into()))]
    );
}

#[test]
fn two_pairs() {
    assert_eq!(
        raw_pairs("/p?foo=bar&baz=qux"),
        vec![
            ("foo".into(), Some("bar".into())),
            ("baz".into(), Some("qux".into())),
        ]
    );
}

#[test]
fn many_bare_keys() {
    assert_eq!(
        raw_pairs("/p?a&b&c"),
        vec![("a".into(), None), ("b".into(), None), ("c".into(), None),]
    );
}

#[test]
fn mixed_bare_and_valued() {
    assert_eq!(
        raw_pairs("/p?a&b=2&c"),
        vec![
            ("a".into(), None),
            ("b".into(), Some("2".into())),
            ("c".into(), None),
        ]
    );
}

// ----------------------------------------------------------------------
// Bare-key vs empty-value distinction
// ----------------------------------------------------------------------

#[test]
fn bare_vs_empty_value_distinct() {
    let bare = raw_pairs("/p?foo");
    let empty = raw_pairs("/p?foo=");
    assert_ne!(bare, empty);
    assert_eq!(bare[0].1, None);
    assert_eq!(empty[0].1, Some(String::new()));
}

#[test]
fn has_value_reflects_equals_presence() {
    let u: Uri = parse_graceful("/p?bare&empty=&v=1").unwrap();
    let pairs: Vec<_> = u.query().unwrap().pairs().collect();
    assert_eq!(pairs.len(), 3);
    assert!(!pairs[0].has_value()); // bare
    assert!(pairs[1].has_value()); // empty=
    assert!(pairs[2].has_value()); // v=1
}

// ----------------------------------------------------------------------
// Empty-fragment dropping
// ----------------------------------------------------------------------

#[test]
fn leading_ampersand_dropped() {
    // `?&foo=bar` — leading empty fragment dropped.
    assert_eq!(
        raw_pairs("/p?&foo=bar"),
        vec![("foo".into(), Some("bar".into()))]
    );
}

#[test]
fn trailing_ampersand_dropped() {
    // `?foo=bar&` — trailing empty fragment dropped.
    assert_eq!(
        raw_pairs("/p?foo=bar&"),
        vec![("foo".into(), Some("bar".into()))]
    );
}

#[test]
fn double_ampersand_dropped() {
    // `?foo=bar&&baz=qux` — internal empty fragment dropped.
    assert_eq!(
        raw_pairs("/p?foo=bar&&baz=qux"),
        vec![
            ("foo".into(), Some("bar".into())),
            ("baz".into(), Some("qux".into())),
        ]
    );
}

#[test]
fn only_ampersands_yields_nothing() {
    // `?&&&` — all empty.
    let u: Uri = parse_graceful("/p?&&&").unwrap();
    let pairs: Vec<_> = u.query().unwrap().pairs().collect();
    assert!(pairs.is_empty());
}

#[test]
fn empty_query_yields_nothing() {
    // `?` — empty query, no pairs.
    let u: Uri = parse_graceful("/p?").unwrap();
    // The query bytes are empty; iterator returns nothing.
    let pairs: Vec<_> = u.query().unwrap().pairs().collect();
    assert!(pairs.is_empty());
}

// ----------------------------------------------------------------------
// First-`=` only splitting
// ----------------------------------------------------------------------

#[test]
fn split_on_first_equals_only() {
    // `a=b=c` → name="a", value="b=c".
    assert_eq!(
        raw_pairs("/p?a=b=c"),
        vec![("a".into(), Some("b=c".into()))]
    );
}

#[test]
fn empty_name_with_value() {
    // `?=value` → name="", value=Some("value"). Unusual but legal.
    assert_eq!(
        raw_pairs("/p?=value"),
        vec![("".into(), Some("value".into()))]
    );
}

#[test]
fn empty_name_empty_value() {
    // `?=` → name="", value=Some("").
    assert_eq!(raw_pairs("/p?="), vec![("".into(), Some("".into()))]);
}

// ----------------------------------------------------------------------
// Percent + form decoding
// ----------------------------------------------------------------------

#[test]
fn decoded_percent_in_value() {
    assert_eq!(
        decoded_pairs("/p?msg=hello%20world"),
        vec![("msg".into(), Some("hello world".into()))]
    );
}

#[test]
fn decoded_plus_is_space() {
    // Form convention: `+` → space.
    assert_eq!(
        decoded_pairs("/p?msg=hello+world"),
        vec![("msg".into(), Some("hello world".into()))]
    );
}

#[test]
fn decoded_plus_and_percent_mixed() {
    // `hello+wide%20world` → "hello wide world".
    assert_eq!(
        decoded_pairs("/p?msg=hello+wide%20world"),
        vec![("msg".into(), Some("hello wide world".into()))]
    );
}

#[test]
fn decoded_plus_in_name() {
    // `+` works in names too.
    assert_eq!(
        decoded_pairs("/p?with+space=v"),
        vec![("with space".into(), Some("v".into()))]
    );
}

#[test]
fn decoded_utf8_value() {
    // `%C3%A9` → `é`.
    assert_eq!(
        decoded_pairs("/p?city=caf%C3%A9"),
        vec![("city".into(), Some("café".into()))]
    );
}

#[test]
fn decoded_invalid_utf8_uses_replacement_char() {
    // `%FF` is not valid UTF-8 standalone — lossy decode → U+FFFD.
    let u: Uri = parse_graceful("/p?x=%FF").unwrap();
    let pair = u.query().unwrap().pairs().next().unwrap();
    let decoded = pair.value_decoded().unwrap();
    assert!(decoded.contains('\u{FFFD}'), "got {decoded:?}");
}

#[test]
fn decoded_malformed_percent_passes_through() {
    // `%ZZ` is not valid hex — the form-decoder emits the literal `%` and
    // continues, matching the `percent_encoding` crate's behaviour. `Z`s
    // pass through unchanged.
    assert_eq!(
        decoded_pairs("/p?x=a%ZZb"),
        vec![("x".into(), Some("a%ZZb".into()))]
    );
}

#[test]
fn decoded_trailing_percent_passes_through() {
    // Trailing `%` with no following chars — literal `%`.
    assert_eq!(
        decoded_pairs("/p?x=trail%"),
        vec![("x".into(), Some("trail%".into()))]
    );
}

#[test]
fn decoded_percent_with_one_char_passes_through() {
    // `%A` with only one char left — literal `%A`.
    assert_eq!(
        decoded_pairs("/p?x=trail%A"),
        vec![("x".into(), Some("trail%A".into()))]
    );
}

#[test]
fn decoded_mixed_case_hex() {
    // Both `%ab` and `%AB` work; `%C3%a9` (mixed) decodes to `é`.
    assert_eq!(
        decoded_pairs("/p?x=caf%C3%a9"),
        vec![("x".into(), Some("café".into()))]
    );
}

#[test]
fn raw_does_not_decode_plus() {
    // `_raw` view keeps `+` as `+`.
    assert_eq!(
        raw_pairs("/p?a=b+c"),
        vec![("a".into(), Some("b+c".into()))]
    );
}

#[test]
fn raw_does_not_decode_percent() {
    // `_raw` view keeps `%20` literal.
    assert_eq!(
        raw_pairs("/p?a=b%20c"),
        vec![("a".into(), Some("b%20c".into()))]
    );
}

// ----------------------------------------------------------------------
// Cow::Borrowed vs Owned
// ----------------------------------------------------------------------

#[test]
fn decoded_no_escape_borrows() {
    // No `%` and no `+` → Cow::Borrowed for both name and value.
    let u: Uri = parse_graceful("/p?foo=bar").unwrap();
    let pair = u.query().unwrap().pairs().next().unwrap();
    assert!(matches!(pair.name_decoded(), Cow::Borrowed(_)));
    assert!(matches!(pair.value_decoded(), Some(Cow::Borrowed(_))));
}

#[test]
fn decoded_with_percent_owns() {
    let u: Uri = parse_graceful("/p?foo=hello%20world").unwrap();
    let pair = u.query().unwrap().pairs().next().unwrap();
    assert!(matches!(pair.value_decoded(), Some(Cow::Owned(_))));
}

#[test]
fn decoded_with_plus_owns() {
    // `+` triggers form-decoding allocation.
    let u: Uri = parse_graceful("/p?foo=a+b").unwrap();
    let pair = u.query().unwrap().pairs().next().unwrap();
    assert!(matches!(pair.value_decoded(), Some(Cow::Owned(_))));
}

// ----------------------------------------------------------------------
// Byte / Option accessors
// ----------------------------------------------------------------------

#[test]
fn name_bytes_and_value_bytes() {
    let u: Uri = parse_graceful("/p?foo=bar&baz").unwrap();
    let pairs: Vec<_> = u.query().unwrap().pairs().collect();
    assert_eq!(pairs[0].name_bytes(), b"foo");
    assert_eq!(pairs[0].value_bytes(), Some(b"bar".as_ref()));
    assert_eq!(pairs[1].name_bytes(), b"baz");
    assert_eq!(pairs[1].value_bytes(), None);
}

// ----------------------------------------------------------------------
// Iterator behaviour
// ----------------------------------------------------------------------

#[test]
fn iterator_fused_after_exhaustion() {
    let u: Uri = parse_graceful("/p?foo=bar").unwrap();
    let mut it = u.query().unwrap().pairs();
    assert!(it.next().is_some());
    assert!(it.next().is_none());
    // Fused — subsequent calls keep returning None.
    assert!(it.next().is_none());
    assert!(it.next().is_none());
}

#[test]
fn iterator_count_matches() {
    for (uri, expected_count) in [
        ("/p?foo", 1usize),
        ("/p?foo=bar", 1),
        ("/p?a&b&c", 3),
        ("/p?a=1&b=2&c=3", 3),
        ("/p?&&", 0),
        ("/p?", 0),
        ("/p?a&&b&", 2),
    ] {
        let u: Uri = parse_graceful(uri).unwrap();
        assert_eq!(
            u.query().unwrap().pairs().count(),
            expected_count,
            "count mismatch for {uri:?}"
        );
    }
}

// ----------------------------------------------------------------------
// Absolute-form URIs
// ----------------------------------------------------------------------

#[test]
fn absolute_form_pairs() {
    assert_eq!(
        raw_pairs("https://api.example.com/search?q=rust&page=2"),
        vec![
            ("q".into(), Some("rust".into())),
            ("page".into(), Some("2".into())),
        ]
    );
}

// ----------------------------------------------------------------------
// Owned Query::pairs() pass-through
// ----------------------------------------------------------------------

#[test]
fn owned_query_pairs_matches_ref() {
    let u: Uri = parse_graceful("/p?a=1&b=2").unwrap();
    let q_ref = u.query().unwrap();
    let q_owned = q_ref.to_owned();
    let from_ref: Vec<_> = q_ref
        .pairs()
        .map(|p| (p.name_raw().to_owned(), p.value_raw().map(str::to_owned)))
        .collect();
    let from_owned: Vec<_> = q_owned
        .pairs()
        .map(|p| (p.name_raw().to_owned(), p.value_raw().map(str::to_owned)))
        .collect();
    assert_eq!(from_ref, from_owned);
}
