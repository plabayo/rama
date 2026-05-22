//! `Uri::query_mut()` — RAII guard for incremental query mutation.

use super::parse_graceful;
use crate::uri::Uri;

// ----------------------------------------------------------------------
// push_pair / push_key
// ----------------------------------------------------------------------

#[test]
fn push_pair_into_empty_query() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.query_mut().push_pair("a", "1");
    assert_eq!(uri.to_string(), "/p?a=1");
}

#[test]
fn push_pair_appends_with_ampersand() {
    let mut uri: Uri = parse_graceful("/p?a=1").unwrap();
    uri.query_mut().push_pair("b", "2").push_pair("c", "3");
    assert_eq!(uri.to_string(), "/p?a=1&b=2&c=3");
}

#[test]
fn push_key_bare() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.query_mut().push_key("foo");
    assert_eq!(uri.to_string(), "/p?foo");
    uri.query_mut().push_key("bar").push_pair("x", "1");
    assert_eq!(uri.to_string(), "/p?foo&bar&x=1");
}

#[test]
fn push_pair_auto_encodes_structural_bytes() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.query_mut()
        .push_pair("a&b", "c=d")
        .push_pair("plus", "a+b");
    // & and = encoded in both name and value; + encoded so round-trip works
    assert_eq!(uri.to_string(), "/p?a%26b=c%3Dd&plus=a%2Bb");
}

#[test]
fn push_pair_auto_encodes_space_and_non_ascii() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.query_mut()
        .push_pair("hello world", "caf\u{e9}")
        .push_pair("ctrl", "\n");
    assert_eq!(uri.to_string(), "/p?hello%20world=caf%C3%A9&ctrl=%0A");
}

#[test]
fn push_pair_pchar_passes_through() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.query_mut()
        .push_pair("Aa0-._~!$'()*,;:@/?", "Aa0-._~!$'()*,;:@/?");
    assert_eq!(
        uri.to_string(),
        // /, ?, :, @, -, ., _, ~, !, $, ', (, ), *, ,, ;, ALPHA, DIGIT all pass through
        "/p?Aa0-._~!$'()*,;:@/?=Aa0-._~!$'()*,;:@/?",
    );
}

// ----------------------------------------------------------------------
// pop
// ----------------------------------------------------------------------

#[test]
fn pop_returns_last_pair() {
    let mut uri: Uri = parse_graceful("/p?a=1&b=2&c=3").unwrap();
    let pair = uri.query_mut().pop().unwrap();
    assert_eq!(pair.name_raw(), "c");
    assert_eq!(pair.value_raw(), Some("3"));
    assert_eq!(uri.to_string(), "/p?a=1&b=2");
}

#[test]
fn pop_bare_key() {
    let mut uri: Uri = parse_graceful("/p?a=1&bare").unwrap();
    let pair = uri.query_mut().pop().unwrap();
    assert_eq!(pair.name_raw(), "bare");
    assert!(pair.value_raw().is_none());
    assert!(!pair.has_value());
    assert_eq!(uri.to_string(), "/p?a=1");
}

#[test]
fn pop_decodes_through_helpers() {
    let mut uri: Uri = parse_graceful("/p?msg=hello%20world").unwrap();
    let pair = uri.query_mut().pop().unwrap();
    assert_eq!(pair.value_decoded().unwrap(), "hello world");
}

#[test]
fn pop_until_empty() {
    let mut uri: Uri = parse_graceful("/p?a=1&b=2").unwrap();
    {
        let mut g = uri.query_mut();
        assert_eq!(g.pop().unwrap().name_raw(), "b");
        assert_eq!(g.pop().unwrap().name_raw(), "a");
        assert!(g.pop().is_none());
    }
    // After draining pairs, the `?` stays because Query is Some(empty).
    assert_eq!(uri.to_string(), "/p?");
}

#[test]
fn pop_skips_trailing_empty_fragment() {
    // Query ends with `&` (empty trailing fragment) — pop skips it.
    let mut uri: Uri = parse_graceful("/p?a=1&").unwrap();
    let pair = uri.query_mut().pop().unwrap();
    assert_eq!(pair.name_raw(), "a");
}

#[test]
fn pop_returns_none_when_no_query() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    assert!(uri.query_mut().pop().is_none());
    assert_eq!(uri.to_string(), "/p");
}

// ----------------------------------------------------------------------
// drain
// ----------------------------------------------------------------------

#[test]
fn drain_yields_all_pairs_in_order() {
    let mut uri: Uri = parse_graceful("/p?a=1&b=2&c=3").unwrap();
    let pairs: Vec<_> = uri
        .query_mut()
        .drain()
        .map(|p| (p.name_raw().to_owned(), p.value_raw().map(str::to_owned)))
        .collect();
    assert_eq!(
        pairs,
        vec![
            ("a".to_owned(), Some("1".to_owned())),
            ("b".to_owned(), Some("2".to_owned())),
            ("c".to_owned(), Some("3".to_owned())),
        ],
    );
    // Query content cleared, `?` remains.
    assert_eq!(uri.to_string(), "/p?");
}

#[test]
fn drain_dropped_unread_still_clears() {
    let mut uri: Uri = parse_graceful("/p?a=1&b=2").unwrap();
    {
        let _ = uri.query_mut().drain(); // dropped without consuming
    }
    assert_eq!(uri.to_string(), "/p?");
}

#[test]
fn drain_skips_empty_fragments() {
    let mut uri: Uri = parse_graceful("/p?&a=1&&b=2&").unwrap();
    let names: Vec<_> = uri
        .query_mut()
        .drain()
        .map(|p| p.name_raw().to_owned())
        .collect();
    assert_eq!(names, vec!["a", "b"]);
}

#[test]
fn drain_on_no_query_yields_nothing() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    let pairs: Vec<_> = uri.query_mut().drain().collect();
    assert!(pairs.is_empty());
    // No-query stays no-query (no `?` materialized).
    assert_eq!(uri.to_string(), "/p");
}

// ----------------------------------------------------------------------
// Round-trip: push then pop
// ----------------------------------------------------------------------

#[test]
fn push_then_pop_yields_encoded_form() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    {
        let mut g = uri.query_mut();
        g.push_pair("a", "hello world").push_pair("b", "x&y");
    }
    assert_eq!(uri.to_string(), "/p?a=hello%20world&b=x%26y");

    let pair = uri.query_mut().pop().unwrap();
    // Raw view shows encoded form; decoded view recovers the original.
    assert_eq!(pair.name_raw(), "b");
    assert_eq!(pair.value_raw(), Some("x%26y"));
    assert_eq!(pair.value_decoded().unwrap(), "x&y");
}

// ----------------------------------------------------------------------
// Type rename sanity: QueryRef::pairs() yields QueryPairRef
// ----------------------------------------------------------------------

#[test]
fn iterator_yields_query_pair_ref() {
    use crate::uri::QueryPairRef;
    let uri: Uri = parse_graceful("/p?a=1").unwrap();
    let pair: QueryPairRef<'_> = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_raw(), "a");
}

// ----------------------------------------------------------------------
// QueryPair (owned) — `to_owned` from a borrowed pair
// ----------------------------------------------------------------------

#[test]
fn query_pair_ref_to_owned_round_trip() {
    let uri: Uri = parse_graceful("/p?key=value").unwrap();
    let ref_pair = uri.query().unwrap().pairs().next().unwrap();
    let owned = ref_pair.into_owned();
    assert_eq!(owned.name_raw(), "key");
    assert_eq!(owned.value_raw(), Some("value"));
    // Owned -> Ref round-trip
    let back = owned.view();
    assert_eq!(back.name_bytes(), b"key");
    assert_eq!(back.value_bytes(), Some(b"value".as_ref()));
}
