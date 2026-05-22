//! `Uri` equality, hashing, ordering — all project through the Display
//! wire form (audit C3 follow-up). Plus the [`TryFrom`] impls for every
//! supported input shape (audit M10).
//!
//! Wire-form projection means two URIs that render identically compare
//! equal regardless of Lazy/Owned representation, source-buffer identity,
//! or component decomposition. **Not** semantic equality —
//! `https://example.com/a%62c` and `https://example.com/abc` Display
//! differently and so compare non-equal. Use [`Uri::canonicalize`] when
//! that distinction needs to be bridged.

use ahash::{HashMap, HashMapExt as _, HashSet, HashSetExt as _};
use rama_core::bytes::{Bytes, BytesMut};

use crate::uri::Uri;

// ---- PartialEq / Eq -------------------------------------------------------

#[test]
fn eq_same_input_parsed_twice_lazy_lazy() {
    let a = Uri::parse("https://example.com/path?q=1#f").unwrap();
    let b = Uri::parse("https://example.com/path?q=1#f").unwrap();
    assert_eq!(a, b);
}

#[test]
fn eq_clone_is_equal_and_hits_arc_ptr_eq_path() {
    // Clone shares the Arc — the ptr_eq fast path returns immediately.
    let a = Uri::parse("https://example.com/p").unwrap();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn eq_asterisk_form() {
    // Asterisk is its own variant — equality is the variant tag.
    let a = Uri::parse("*").unwrap();
    let b = Uri::parse("*").unwrap();
    assert_eq!(a, b);
}

#[test]
fn eq_lazy_owned_after_mutation() {
    // Mutation upgrades Lazy → Owned. The resulting URI must still
    // compare equal to a freshly-parsed identical input regardless of
    // internal representation.
    let mut a = Uri::parse("https://example.com/p").unwrap();
    a.set_path("/p"); // no-op semantically but triggers Owned upgrade
    let b = Uri::parse("https://example.com/p").unwrap();
    assert_eq!(a, b);
}

#[test]
fn eq_distinguishes_path_difference() {
    let a = Uri::parse("https://example.com/a").unwrap();
    let b = Uri::parse("https://example.com/b").unwrap();
    assert_ne!(a, b);
}

#[test]
fn eq_distinguishes_query_presence() {
    // `?` with empty query vs no `?` are distinct wire forms.
    let with_q = Uri::parse("https://example.com/p?").unwrap();
    let no_q = Uri::parse("https://example.com/p").unwrap();
    assert_ne!(with_q, no_q);
}

#[test]
fn eq_distinguishes_pct_encoded_vs_decoded_path() {
    // Wire-form equality, not semantic. canonicalize bridges these.
    let a = Uri::parse("https://example.com/a%62c").unwrap();
    let b = Uri::parse("https://example.com/abc").unwrap();
    assert_ne!(a, b);
    // ... but after canonicalize on both sides they DO equal.
    assert_eq!(a.canonicalize(), b.canonicalize());
}

#[test]
fn eq_ignores_host_case_via_domain_semantics() {
    // RFC 3986 §6.2.2.1: hosts are case-insensitive. Match what
    // `Domain` already does so `Uri` works as a routing-table key
    // regardless of the input casing.
    let a = Uri::parse("https://EXAMPLE.com/p").unwrap();
    let b = Uri::parse("https://example.com/p").unwrap();
    assert_eq!(a, b);
}

#[test]
fn eq_treats_pct_decoded_host_equivalent() {
    // Through `UninterpretedHostRef`'s §6.2.2.2 logical-byte eq —
    // sub-delim reg-names with pct-encoded vs raw byte forms hash and
    // compare equal at the Uri level.
    let a = Uri::parse("http://exa%2Cmple/p").unwrap();
    let b = Uri::parse("http://exa,mple/p").unwrap();
    assert_eq!(a, b);
}

#[test]
fn eq_distinguishes_default_port_explicit_vs_implicit() {
    let with_port = Uri::parse("https://example.com:443/").unwrap();
    let without = Uri::parse("https://example.com/").unwrap();
    // Wire forms differ → not equal at this layer.
    assert_ne!(with_port, without);
    // canonicalize drops default port → equal post-canonicalize.
    assert_eq!(with_port.canonicalize(), without.canonicalize());
}

// ---- Hash -----------------------------------------------------------------

#[test]
fn hashmap_lookup_works_with_uri_key() {
    let mut m: HashMap<Uri, &'static str> = HashMap::new();
    m.insert(Uri::parse("https://example.com/p").unwrap(), "value");
    // Lookup with a separately-parsed identical URI finds the entry.
    assert_eq!(
        m.get(&Uri::parse("https://example.com/p").unwrap()),
        Some(&"value")
    );
    // Path difference → no collision.
    assert!(!m.contains_key(&Uri::parse("https://example.com/q").unwrap()));
}

#[test]
fn hashmap_lookup_works_across_lazy_owned_boundary() {
    // Insert Lazy, look up via Owned (or vice versa). Hash projects on
    // wire form so the representation gap doesn't matter.
    let mut m: HashMap<Uri, ()> = HashMap::new();
    let lazy = Uri::parse("https://example.com/p").unwrap();
    m.insert(lazy, ());

    let mut owned = Uri::parse("https://example.com/p").unwrap();
    owned.set_path("/p"); // forces Owned form
    assert!(m.contains_key(&owned));
}

#[test]
fn hashset_dedup() {
    let mut s: HashSet<Uri> = HashSet::new();
    s.insert(Uri::parse("http://a.example/").unwrap());
    s.insert(Uri::parse("http://a.example/").unwrap());
    s.insert(Uri::parse("http://b.example/").unwrap());
    assert_eq!(s.len(), 2);
}

// ---- Ord / PartialOrd -----------------------------------------------------

#[test]
fn ord_lex_compare_on_wire_form() {
    let a = Uri::parse("https://example.com/a").unwrap();
    let b = Uri::parse("https://example.com/b").unwrap();
    assert!(a < b);
}

#[test]
fn ord_sort_stable_for_routing_table_keys() {
    let mut v: Vec<Uri> = [
        "https://c.example/",
        "https://a.example/",
        "https://b.example/p",
        "https://b.example/",
    ]
    .into_iter()
    .map(|s| Uri::parse(s).unwrap())
    .collect();
    v.sort();
    let rendered: Vec<String> = v.iter().map(Uri::to_string).collect();
    assert_eq!(
        rendered,
        vec![
            "https://a.example/".to_owned(),
            "https://b.example/".to_owned(),
            "https://b.example/p".to_owned(),
            "https://c.example/".to_owned(),
        ]
    );
}

// ---- TryFrom impls --------------------------------------------------------

const URI_STR: &str = "https://example.com/path?q=1";

#[test]
fn try_from_str() {
    let u = Uri::try_from(URI_STR).unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
}

#[test]
fn try_from_string() {
    let u = Uri::try_from(URI_STR.to_owned()).unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
}

#[test]
fn try_from_byte_slice() {
    let u = Uri::try_from(URI_STR.as_bytes()).unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
}

#[test]
fn try_from_vec_u8() {
    let u = Uri::try_from(URI_STR.as_bytes().to_vec()).unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
}

#[test]
fn try_from_bytes() {
    let u = Uri::try_from(Bytes::from_static(URI_STR.as_bytes())).unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
}

#[test]
fn try_from_bytes_mut() {
    let u = Uri::try_from(BytesMut::from(URI_STR.as_bytes())).unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
}

#[test]
fn try_from_propagates_parse_error() {
    // Empty input → ParseError::Empty surfaces through TryFrom.
    let err = Uri::try_from("").unwrap_err();
    assert!(matches!(err, crate::uri::ParseError::Empty));
}

#[test]
fn try_from_works_at_generic_bound() {
    // Pin that a `T: TryInto<Uri>` bound resolves for the standard
    // input shapes — the very thing this audit item exists to enable.
    fn accept<T: TryInto<Uri, Error = crate::uri::ParseError>>(input: T) -> Uri {
        input.try_into().unwrap()
    }
    accept(URI_STR);
    accept(URI_STR.to_owned());
    accept(URI_STR.as_bytes());
    accept(URI_STR.as_bytes().to_vec());
    accept(Bytes::from_static(URI_STR.as_bytes()));
    accept(BytesMut::from(URI_STR.as_bytes()));
}
