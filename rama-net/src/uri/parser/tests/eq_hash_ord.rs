//! `Uri` equality, hashing, ordering — component-wise + RFC 3986 §6.2.2
//! semantic. Plus the [`TryFrom`] impls for every supported input shape.
//!
//! All four `Uri` impls compare via the public component accessors
//! (`scheme`, `authority`, `path`, `query`, `fragment`); each sub-type's
//! own `Eq`/`Hash`/`Ord` carries the right semantics. So two URIs that
//! render differently can still compare equal when their components are
//! §6.2.2 equivalent:
//!
//! - Host (§6.2.2.1 + §6.2.2.2): ASCII case-insensitive, pct-encoded
//!   octets equivalent to their decoded form (`exa%2Cmple` ≡ `exa,mple`,
//!   `EXAMPLE.com` ≡ `example.com`).
//! - Scheme (§6.2.2.1): ASCII case-insensitive via the `Protocol` enum.
//! - Path / query / fragment: **byte-exact** (case-sensitive,
//!   pct-encoding preserved). Per §6.2.2.2 only the host normalises
//!   pct-encoded equivalences; paths and queries stay strict.
//!
//! `Uri::canonicalize` is the operation that bridges those last three —
//! e.g. it pct-decodes unreserved bytes inside the path. So
//! `https://example.com/a%62c` ≢ `https://example.com/abc` at the `Uri`
//! level, but `uri.canonicalize() == other.canonicalize()` does hold.

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

#[test]
fn ord_asterisk_sorts_before_all_other_uris() {
    // `*` is its own variant; `Uri::cmp` places it strictly less than
    // anything with a scheme/authority/path so sort output is stable
    // when an asterisk request-target mingles with other URIs.
    let mut v: Vec<Uri> = ["https://example.com/", "/origin-form", "*", "urn:isbn:0"]
        .into_iter()
        .map(|s| Uri::parse(s).unwrap())
        .collect();
    v.sort();
    assert_eq!(v[0].to_string(), "*", "asterisk must sort first, got {v:?}");
}

#[test]
fn hash_asterisk_distinct_from_other_uris() {
    // The discriminant byte for `Asterisk` in `Uri::hash` is dedicated
    // — must not collide with any other URI's hash key. Insert one of
    // each into a HashSet and assert no dedup.
    let mut s: ahash::HashSet<Uri> = ahash::HashSet::default();
    s.insert(Uri::parse("*").unwrap());
    s.insert(Uri::parse("/").unwrap()); // origin-form, no scheme/authority
    s.insert(Uri::parse("https://example.com/").unwrap());
    assert_eq!(
        s.len(),
        3,
        "asterisk must hash distinctly from origin/absolute"
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
    // Pin that a `T: TryInto<Uri>` bound resolves for the standard inptu shapes.
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

// ---- Uri::from_static ------------------------------------------

#[test]
fn from_static_parses_canonical_input() {
    let u = Uri::from_static("https://example.com/p?q=1#f");
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.path().unwrap().as_raw_str(), "/p");
    assert_eq!(u.query().unwrap().as_raw_str(), "q=1");
    assert_eq!(u.fragment().unwrap().as_raw_str(), "f");
}

#[test]
fn from_static_round_trips_through_display() {
    let raw = "http://example.com/";
    let u = Uri::from_static(raw);
    assert_eq!(u.to_string(), raw);
}

#[test]
#[should_panic(expected = "invalid URI")]
fn from_static_panics_on_invalid_with_typed_message() {
    // Control byte → parser rejection → panic message identifies the
    // invariant for callers debugging a compile-time-constant URI.
    //
    // Two competing clippy lints meet here (`unused_must_use` vs
    // `let_underscore_must_use`); bind the result to a real name so
    // neither fires, then drop it.
    let _u = Uri::from_static("http://example.com/\x00path");
}

// ---- Uri::is_absolute coverage --------------------------------

#[test]
fn is_absolute_for_absolute_form() {
    assert!(Uri::parse("https://example.com/p").unwrap().is_absolute());
    assert!(Uri::parse("urn:isbn:0451450523").unwrap().is_absolute());
    assert!(Uri::parse("mailto:user@example.com").unwrap().is_absolute());
}

#[test]
fn is_absolute_for_origin_form() {
    // Origin-form has no scheme.
    assert!(!Uri::parse("/path").unwrap().is_absolute());
    assert!(!Uri::parse("/p?q#f").unwrap().is_absolute());
}

#[test]
fn is_absolute_for_asterisk() {
    assert!(!Uri::parse("*").unwrap().is_absolute());
}

#[test]
fn is_absolute_for_relative_reference() {
    // `parse_reference` lets us reach the relative-ref grammar.
    assert!(!Uri::parse_reference("../foo").unwrap().is_absolute());
    assert!(!Uri::parse_reference("?q").unwrap().is_absolute());
    assert!(!Uri::parse_reference("#frag").unwrap().is_absolute());
}
