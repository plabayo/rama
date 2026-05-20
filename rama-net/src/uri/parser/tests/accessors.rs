use super::parse_graceful;
use crate::Protocol;

// ----------------------------------------------------------------------
// scheme()
// ----------------------------------------------------------------------

#[test]
fn scheme_origin_form_is_none() {
    assert!(parse_graceful("/foo").unwrap().scheme().is_none());
    assert!(parse_graceful("/foo?bar#baz").unwrap().scheme().is_none());
}

#[test]
fn scheme_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().scheme().is_none());
}

#[test]
fn scheme_http() {
    let u = parse_graceful("http://example.com/").unwrap();
    assert_eq!(u.scheme(), Some(&Protocol::HTTP));
}

#[test]
fn scheme_https() {
    let u = parse_graceful("https://example.com/").unwrap();
    assert_eq!(u.scheme(), Some(&Protocol::HTTPS));
}

#[test]
fn scheme_custom() {
    for (input, expected) in [
        ("urn:isbn:0", "urn"),
        ("mailto:a@b", "mailto"),
        ("ftp://h/p", "ftp"),
        ("git+ssh://h/r", "git+ssh"),
        ("ws://h/", "ws"),
        ("wss://h/", "wss"),
    ] {
        let u = parse_graceful(input).unwrap();
        assert_eq!(
            u.scheme().map(|p| p.as_str()),
            Some(expected),
            "scheme for {input:?}"
        );
    }
}

// ----------------------------------------------------------------------
// path()
// ----------------------------------------------------------------------

#[test]
fn path_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().path().is_none());
}

#[test]
fn path_origin_form() {
    let u = parse_graceful("/foo/bar").unwrap();
    let p = u.path().unwrap();
    assert_eq!(p.as_bytes(), b"/foo/bar");
    assert_eq!(p.as_str(), "/foo/bar");
}

#[test]
fn path_root() {
    let u = parse_graceful("/").unwrap();
    assert_eq!(u.path().unwrap().as_str(), "/");
}

#[test]
fn path_strips_at_query_delimiter() {
    let u = parse_graceful("/foo?q").unwrap();
    assert_eq!(u.path().unwrap().as_str(), "/foo");
}

#[test]
fn path_strips_at_fragment_delimiter() {
    let u = parse_graceful("/foo#f").unwrap();
    assert_eq!(u.path().unwrap().as_str(), "/foo");
}

#[test]
fn path_absolute_form() {
    let u = parse_graceful("http://example.com/v1/users").unwrap();
    assert_eq!(u.path().unwrap().as_str(), "/v1/users");
}

#[test]
fn path_absolute_empty() {
    // `http://example.com` — path-abempty is empty.
    let u = parse_graceful("http://example.com").unwrap();
    let p = u.path().unwrap();
    assert_eq!(p.as_str(), "");
    assert!(p.as_bytes().is_empty());
}

#[test]
fn path_opaque_in_urn() {
    let u = parse_graceful("urn:isbn:0451450523").unwrap();
    assert_eq!(u.path().unwrap().as_str(), "isbn:0451450523");
}

// ----------------------------------------------------------------------
// query()
// ----------------------------------------------------------------------

#[test]
fn query_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().query().is_none());
}

#[test]
fn query_absent_is_none() {
    assert!(parse_graceful("/foo").unwrap().query().is_none());
    assert!(parse_graceful("http://x/").unwrap().query().is_none());
}

#[test]
fn query_present() {
    let u = parse_graceful("/p?key=val&x=y").unwrap();
    assert_eq!(u.query().unwrap().as_str(), "key=val&x=y");
}

#[test]
fn query_empty_distinct_from_none() {
    // `/foo?` — Some("") vs None for `/foo`.
    let with = parse_graceful("/foo?").unwrap();
    let q = with.query().unwrap();
    assert_eq!(q.as_str(), "");
    assert!(q.as_bytes().is_empty());

    let without = parse_graceful("/foo").unwrap();
    assert!(without.query().is_none());
}

#[test]
fn query_stops_at_fragment() {
    let u = parse_graceful("/p?q1=a#frag").unwrap();
    assert_eq!(u.query().unwrap().as_str(), "q1=a");
}

#[test]
fn query_in_absolute_form() {
    let u = parse_graceful("https://api.example.com/v1?id=42").unwrap();
    assert_eq!(u.query().unwrap().as_str(), "id=42");
}

// ----------------------------------------------------------------------
// fragment()
// ----------------------------------------------------------------------

#[test]
fn fragment_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().fragment().is_none());
}

#[test]
fn fragment_absent_is_none() {
    assert!(parse_graceful("/foo").unwrap().fragment().is_none());
    assert!(parse_graceful("/foo?q").unwrap().fragment().is_none());
}

#[test]
fn fragment_present() {
    let u = parse_graceful("/foo#section").unwrap();
    assert_eq!(u.fragment().unwrap().as_str(), "section");
}

#[test]
fn fragment_empty_distinct_from_none() {
    let with = parse_graceful("/foo#").unwrap();
    let f = with.fragment().unwrap();
    assert_eq!(f.as_str(), "");
    assert!(f.as_bytes().is_empty());

    let without = parse_graceful("/foo").unwrap();
    assert!(without.fragment().is_none());
}

#[test]
fn fragment_with_question_mark_byte() {
    // `?` is a legal fragment byte (RFC 3986 §3.5).
    let u = parse_graceful("/p#frag?q").unwrap();
    assert_eq!(u.fragment().unwrap().as_str(), "frag?q");
}

#[test]
fn fragment_in_absolute_form() {
    let u = parse_graceful("https://x/v#bio").unwrap();
    assert_eq!(u.fragment().unwrap().as_str(), "bio");
}

// ----------------------------------------------------------------------
// All four accessors together — single-URI roundtrip
// ----------------------------------------------------------------------

#[test]
fn full_uri_all_accessors() {
    let u = parse_graceful("https://api.example.com/v1/users?id=42&filter=x#bio").unwrap();
    assert_eq!(u.scheme(), Some(&Protocol::HTTPS));
    assert_eq!(u.path().unwrap().as_str(), "/v1/users");
    assert_eq!(u.query().unwrap().as_str(), "id=42&filter=x");
    assert_eq!(u.fragment().unwrap().as_str(), "bio");
}

#[test]
fn origin_form_all_accessors() {
    let u = parse_graceful("/p?a=b#frag").unwrap();
    assert!(u.scheme().is_none());
    assert_eq!(u.path().unwrap().as_str(), "/p");
    assert_eq!(u.query().unwrap().as_str(), "a=b");
    assert_eq!(u.fragment().unwrap().as_str(), "frag");
}

#[test]
fn asterisk_all_accessors_none() {
    let u = parse_graceful("*").unwrap();
    assert!(u.is_asterisk());
    assert!(u.scheme().is_none());
    assert!(u.path().is_none());
    assert!(u.query().is_none());
    assert!(u.fragment().is_none());
}
