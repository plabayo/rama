//! `Query: FromIterator<QueryPair>` / `FromIterator<QueryPairRef<'_>>`
//! and the bypass-encoding setter `Uri::set_query`.

use super::parse_graceful;
use crate::test_hash::hash;
use crate::uri::{Query, QueryRef, Uri};

// ----------------------------------------------------------------------
// FromIterator
// ----------------------------------------------------------------------

#[test]
fn collect_owned_pairs_into_query() {
    let mut uri: Uri = parse_graceful("/p?a=1&b=2&c=3").unwrap();
    // Drain yields owned pairs; collect rebuilds a Query.
    let q: Query = uri.query_mut().drain().collect();
    assert_eq!(q.as_encoded_str(), "a=1&b=2&c=3");
}

#[test]
fn collect_borrowed_pairs_into_query() {
    let uri: Uri = parse_graceful("/p?a=1&b=2&c=3").unwrap();
    let q: Query = uri.query().unwrap().pairs().collect();
    assert_eq!(q.as_encoded_str(), "a=1&b=2&c=3");
}

#[test]
fn collect_empty_iterator_yields_empty_query() {
    let pairs: Vec<crate::uri::QueryPair> = Vec::new();
    let q: Query = pairs.into_iter().collect();
    assert_eq!(q.as_encoded_str(), "");
}

#[test]
fn collect_preserves_bare_keys_and_empty_values() {
    let uri: Uri = parse_graceful("/p?bare&empty=&v=1").unwrap();
    let q: Query = uri.query().unwrap().pairs().collect();
    assert_eq!(q.as_encoded_str(), "bare&empty=&v=1");
}

#[test]
fn collect_preserves_already_encoded_bytes_no_double_encoding() {
    // Source query has `%20` and `%26` already; collect must NOT
    // re-encode (i.e. must not produce `%2520` / `%2526`).
    let uri: Uri = parse_graceful("/p?msg=hello%20world&sep=a%26b").unwrap();
    let q: Query = uri.query().unwrap().pairs().collect();
    assert_eq!(q.as_encoded_str(), "msg=hello%20world&sep=a%26b");
}

#[test]
fn collect_filtered_pairs_into_query() {
    let uri: Uri = parse_graceful("/p?keep=1&drop=2&keep=3").unwrap();
    let q: Query = uri
        .query()
        .unwrap()
        .pairs()
        .filter(|p| p.name_encoded() == "keep")
        .collect();
    assert_eq!(q.as_encoded_str(), "keep=1&keep=3");
}

#[test]
fn ref_equality_hash_and_order_use_encoded_view() {
    let raw = QueryRef::from_raw_str("msg=hello world");
    let encoded = QueryRef::from_raw_str("msg=hello%20world");

    assert_eq!(raw.as_encoded_str(), "msg=hello%20world");
    assert_eq!(raw, encoded);
    assert_eq!(raw.cmp(&encoded), core::cmp::Ordering::Equal);

    assert_eq!(hash(&raw), hash(&encoded));
}

#[test]
fn ref_into_owned_exports_only_explicit_encoded_or_decoded_views() {
    let query = QueryRef::from_raw_str("msg=hello world&bad=%zz&tail=%").into_owned();

    assert_eq!(
        query.as_encoded_str(),
        "msg=hello%20world&bad=%25zz&tail=%25",
    );
    assert_eq!(query.as_decoded_str(), "msg=hello world&bad=%zz&tail=%");
}

#[test]
fn encoded_query_ref_preserves_valid_pct_and_escapes_invalid_bytes() {
    let query = QueryRef::from_raw_str("msg=hello world&good=%2F&bad=%zz&tail=%");

    assert_eq!(
        query.as_encoded_str(),
        "msg=hello%20world&good=%2F&bad=%25zz&tail=%25",
    );
    assert_eq!(
        query.as_decoded_str(),
        "msg=hello world&good=/&bad=%zz&tail=%",
    );
}

#[test]
fn pair_encoded_view_escapes_query_structure_per_component() {
    let query = QueryRef::from_raw_str("a=b=c&plus=a+b&good=%2F&bad=%zz");
    let pairs: Vec<_> = query
        .pairs()
        .map(|pair| {
            (
                pair.name_encoded().into_owned(),
                pair.value_encoded().map(|value| value.into_owned()),
            )
        })
        .collect();

    assert_eq!(
        pairs,
        vec![
            ("a".to_owned(), Some("b%3Dc".to_owned())),
            ("plus".to_owned(), Some("a%2Bb".to_owned())),
            ("good".to_owned(), Some("%2F".to_owned())),
            ("bad".to_owned(), Some("%25zz".to_owned())),
        ],
    );
}

// ----------------------------------------------------------------------
// set_query / with_query (bypass encoding)
// ----------------------------------------------------------------------

#[test]
fn set_query_assigns_query_back() {
    let mut uri: Uri = parse_graceful("/p?a=1&b=2&c=3").unwrap();
    let q: Query = uri
        .query()
        .unwrap()
        .pairs()
        .filter(|p| p.name_encoded() != "b")
        .collect();
    uri.set_query(q);
    assert_eq!(uri.to_string(), "/p?a=1&c=3");
}

#[test]
fn with_query_consuming_form() {
    let q: Query = parse_graceful("/p?a=1&b=2")
        .unwrap()
        .query()
        .unwrap()
        .pairs()
        .collect();
    let uri = parse_graceful("/x").unwrap().with_query(q);
    assert_eq!(uri.to_string(), "/x?a=1&b=2");
}

#[test]
fn set_query_no_double_encoding_of_existing_percents() {
    // Round-trip through collect + set_query must preserve bytes.
    let mut uri: Uri = parse_graceful("/p?msg=hello%20world").unwrap();
    let q: Query = uri.query().unwrap().pairs().collect();
    uri.set_query(q);
    assert_eq!(uri.to_string(), "/p?msg=hello%20world");
}

#[test]
fn full_round_trip_drain_filter_collect_assign() {
    // The "remove a pair" use case: drain → filter → collect → assign.
    let mut uri: Uri = parse_graceful("/p?keep=1&drop=2&keep=3").unwrap();
    let kept: Query = uri
        .query_mut()
        .drain()
        .filter(|p| p.name_encoded() == "keep")
        .collect();
    uri.set_query(kept);
    assert_eq!(uri.to_string(), "/p?keep=1&keep=3");
}
