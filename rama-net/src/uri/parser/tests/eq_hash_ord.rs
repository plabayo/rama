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
use rama_core::bytes::Bytes;

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

#[test]
fn hash_consistent_with_eq_for_pct_encoded_host() {
    // §6.2.2.2-equivalent hosts must hash equal (std Hash/Eq contract).
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash as _, Hasher};

    let a = Uri::parse("http://exa%2Cmple/p").unwrap();
    let b = Uri::parse("http://exa,mple/p").unwrap();
    assert_eq!(a, b);

    let mut ha = DefaultHasher::new();
    a.hash(&mut ha);
    let mut hb = DefaultHasher::new();
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());

    // Practical: HashMap lookup crosses the pct-encoding boundary.
    let mut m: HashMap<Uri, &'static str> = HashMap::new();
    m.insert(a, "value");
    assert_eq!(m.get(&b), Some(&"value"));
}

#[test]
fn hash_consistent_with_eq_for_host_case() {
    // §6.2.2.1: host comparison is ASCII case-insensitive — hash follows.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash as _, Hasher};

    let a = Uri::parse("https://EXAMPLE.com/p").unwrap();
    let b = Uri::parse("https://example.com/p").unwrap();
    assert_eq!(a, b);

    let mut ha = DefaultHasher::new();
    a.hash(&mut ha);
    let mut hb = DefaultHasher::new();
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());
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

// ---- Query / Fragment derives + Display + FromStr-------------

#[test]
fn query_display_and_from_str_round_trip() {
    use crate::uri::Query;
    use std::str::FromStr as _;
    let q = Query::from_str("a=1&b=2").unwrap();
    assert_eq!(q.to_string(), "a=1&b=2");
    // Already-legal pchar passes through; bytes outside the set encode.
    let q = Query::from_str("hello world").unwrap();
    assert_eq!(q.to_string(), "hello%20world");
}

#[test]
fn query_default_is_empty_and_distinct_from_dummy() {
    use crate::uri::Query;
    let d = Query::default();
    assert_eq!(d.as_bytes(), b"");
    assert_eq!(d.to_string(), "");
}

#[test]
fn fragment_display_and_from_str_round_trip() {
    use crate::uri::Fragment;
    use std::str::FromStr as _;
    let f = Fragment::from_str("section-1.2").unwrap();
    assert_eq!(f.to_string(), "section-1.2");
}

// ---- UriRef + Uri::view()-------------------------------------

#[test]
fn uri_view_caches_all_components() {
    let u = Uri::parse("https://alice:secret@example.com:8443/p?q=1#f").unwrap();
    let v = u.view();
    // Every accessor returns the same value as the source Uri's
    // accessor — the snapshot is a faithful borrow, just cached.
    assert_eq!(v.scheme(), u.scheme());
    assert_eq!(v.path().map(|p| p.as_raw_str()), Some("/p"));
    assert_eq!(v.query().map(|q| q.as_raw_str()), Some("q=1"));
    assert_eq!(v.fragment().map(|f| f.as_raw_str()), Some("f"));
    assert_eq!(v.port(), Some(8443));
    assert!(v.host().is_some());
    assert!(v.userinfo().is_some());
    assert!(!v.is_asterisk());
    assert!(v.is_absolute());
}

#[test]
fn uri_view_display_matches_source() {
    let u = Uri::parse("https://example.com/p?q=1").unwrap();
    assert_eq!(u.view().to_string(), u.to_string());
}

#[test]
fn uri_view_asterisk_form_all_components_none() {
    let u = Uri::parse("*").unwrap();
    let v = u.view();
    assert!(v.is_asterisk());
    assert!(!v.is_absolute());
    assert!(v.scheme().is_none());
    assert!(v.authority().is_none());
    assert!(v.path().is_none());
    assert!(v.query().is_none());
    assert!(v.fragment().is_none());
    assert!(v.host().is_none());
    assert!(v.port().is_none());
    assert!(v.userinfo().is_none());
}

#[test]
fn uri_view_origin_form_no_authority() {
    let u = Uri::parse("/p?q=1#f").unwrap();
    let v = u.view();
    assert!(v.scheme().is_none());
    assert!(v.authority().is_none());
    assert!(v.host().is_none());
    assert!(v.port().is_none());
    assert!(v.userinfo().is_none());
    assert_eq!(v.path().map(|p| p.as_raw_str()), Some("/p"));
    assert_eq!(v.query().map(|q| q.as_raw_str()), Some("q=1"));
    assert_eq!(v.fragment().map(|f| f.as_raw_str()), Some("f"));
}

#[test]
fn query_hash_works_as_btreemap_key() {
    // Hash / Ord derives let `Query` flow into ordered/unordered maps.
    use crate::uri::Query;
    use std::collections::BTreeMap;
    use std::str::FromStr as _;
    let mut m: BTreeMap<Query, &'static str> = BTreeMap::new();
    m.insert(Query::from_str("a=1").unwrap(), "first");
    m.insert(Query::from_str("a=2").unwrap(), "second");
    assert_eq!(m.get(&Query::from_str("a=1").unwrap()), Some(&"first"));
    assert_eq!(m.len(), 2);
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
fn try_from_propagates_parse_error() {
    // Empty input → ParseError::Empty surfaces through TryFrom.
    let err = Uri::try_from("").unwrap_err();
    assert!(matches!(err, crate::uri::ParseError::Empty));
}

#[test]
fn from_str_direct_via_parse_trait() {
    // `str::parse::<Uri>()` routes through `FromStr` (graceful mode).
    let u: Uri = "https://example.com/p".parse().unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.path().unwrap().as_raw_str(), "/p");

    let r: Result<Uri, _> = "".parse();
    assert!(matches!(r, Err(crate::uri::ParseError::Empty)));
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
