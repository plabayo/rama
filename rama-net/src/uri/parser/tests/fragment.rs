//! `FragmentRef` / `Fragment` — borrowed/owned views of a URI fragment.

use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash as _, Hasher as _};

use super::parse_graceful;
use crate::uri::{FragmentRef, Uri};

#[test]
fn raw_view_keeps_bytes_verbatim() {
    for (input, want) in [
        ("/p#foo", "foo"),
        ("/p#hello%20world", "hello%20world"),
        ("/p#with+plus", "with+plus"),
        ("https://example.com/path#section", "section"),
        ("/p#", ""),
    ] {
        let uri: Uri = parse_graceful(input).unwrap();
        let f = uri.fragment().unwrap();
        assert_eq!(f.as_encoded_str(), want, "input: {input:?}");
        assert_eq!(
            f.as_encoded_str().as_bytes(),
            want.as_bytes(),
            "input: {input:?}"
        );
    }
}

#[test]
fn decoded_view_percent_decodes_but_not_plus() {
    // Fragment decoding follows RFC 3986 pct-decoding only — `+` is
    // *not* a space here (unlike the query's form-decode path).
    for (input, want) in [
        ("/p#hello%20world", "hello world"),
        ("/p#caf%C3%A9", "café"),
        ("/p#with+plus", "with+plus"), // `+` stays literal
    ] {
        let uri: Uri = parse_graceful(input).unwrap();
        assert_eq!(
            uri.fragment().unwrap().as_decoded_str(),
            want,
            "input: {input:?}",
        );
    }
}

#[test]
fn decoded_borrows_when_no_percent_else_owns() {
    let uri: Uri = parse_graceful("/p#plain").unwrap();
    assert!(matches!(
        uri.fragment().unwrap().as_decoded_str(),
        Cow::Borrowed(_),
    ));

    let uri: Uri = parse_graceful("/p#has%20space").unwrap();
    assert!(matches!(
        uri.fragment().unwrap().as_decoded_str(),
        Cow::Owned(_),
    ));
}

#[test]
fn invalid_utf8_in_decoded_uses_replacement_char() {
    // `%FF` standalone is not valid UTF-8 — lossy decode emits U+FFFD.
    let uri: Uri = parse_graceful("/p#%FF").unwrap();
    let decoded = uri.fragment().unwrap().as_decoded_str();
    assert!(decoded.contains('\u{FFFD}'), "got {decoded:?}");
}

#[test]
fn no_fragment_yields_none() {
    let uri: Uri = parse_graceful("/p?q=1").unwrap();
    assert!(uri.fragment().is_none());
}

#[test]
fn owned_round_trip_preserves_bytes() {
    let uri: Uri = parse_graceful("/p#section%201").unwrap();
    let f_ref = uri.fragment().unwrap();
    let owned = f_ref.into_owned();
    assert_eq!(owned.as_encoded_str(), f_ref.as_encoded_str());
    assert_eq!(owned.as_decoded_str(), f_ref.as_decoded_str());
    // Borrowed view from the owned form matches the original.
    assert_eq!(owned.view().as_encoded_str(), f_ref.as_encoded_str());
}

#[test]
fn ref_equality_hash_and_order_use_encoded_view() {
    let raw = FragmentRef::from_raw_str("hello world");
    let encoded = FragmentRef::from_raw_str("hello%20world");

    assert_eq!(raw.as_encoded_str(), "hello%20world");
    assert_eq!(raw, encoded);
    assert_eq!(raw.cmp(&encoded), std::cmp::Ordering::Equal);

    let mut raw_hash = DefaultHasher::new();
    raw.hash(&mut raw_hash);
    let mut encoded_hash = DefaultHasher::new();
    encoded.hash(&mut encoded_hash);
    assert_eq!(raw_hash.finish(), encoded_hash.finish());
}

#[test]
fn ref_into_owned_exports_only_explicit_encoded_or_decoded_views() {
    let fragment = FragmentRef::from_raw_str("hello world/%2F/%zz/%").into_owned();

    assert_eq!(fragment.as_encoded_str(), "hello%20world/%2F/%25zz/%25");
    assert_eq!(fragment.as_decoded_str(), "hello world///%zz/%");
}

#[test]
fn encoded_fragment_ref_preserves_valid_pct_and_escapes_invalid_bytes() {
    let fragment = FragmentRef::from_raw_str("hello world/%2F/%zz/%");

    assert_eq!(fragment.as_encoded_str(), "hello%20world/%2F/%25zz/%25");
    assert_eq!(fragment.as_decoded_str(), "hello world///%zz/%");
}
