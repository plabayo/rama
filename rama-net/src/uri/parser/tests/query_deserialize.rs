//! `QueryRef::deserialize` / `Query::deserialize` — serde-into-struct
//! coverage via `serde_html_form`.

use std::borrow::Cow;

use ahash::HashMap;
use serde::Deserialize;

use super::parse_graceful;
use crate::uri::Uri;

// ----------------------------------------------------------------------
// Basic shapes
// ----------------------------------------------------------------------

#[test]
fn into_simple_struct() {
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct Params {
        foo: String,
        bar: u32,
    }
    let uri: Uri = parse_graceful("/p?foo=hello&bar=42").unwrap();
    let got: Params = uri.query().unwrap().deserialize().unwrap();
    assert_eq!(
        got,
        Params {
            foo: "hello".into(),
            bar: 42,
        }
    );
}

#[test]
fn into_optional_fields_some_and_none() {
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct Params {
        foo: Option<String>,
        baz: Option<u32>,
    }
    let uri: Uri = parse_graceful("/p?foo=bar").unwrap();
    let got: Params = uri.query().unwrap().deserialize().unwrap();
    assert_eq!(
        got,
        Params {
            foo: Some("bar".into()),
            baz: None,
        }
    );
}

#[test]
fn into_vec_repeated_key() {
    // Repeated keys aggregate into a Vec — form-data convention.
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct Params {
        x: Vec<u32>,
    }
    let uri: Uri = parse_graceful("/p?x=1&x=2&x=3").unwrap();
    let got: Params = uri.query().unwrap().deserialize().unwrap();
    assert_eq!(got, Params { x: vec![1, 2, 3] });
}

#[test]
fn into_hashmap() {
    let uri: Uri = parse_graceful("/p?a=1&b=2&c=3").unwrap();
    let map: HashMap<String, String> = uri.query().unwrap().deserialize().unwrap();
    assert_eq!(map.len(), 3);
    assert_eq!(map["a"], "1");
    assert_eq!(map["b"], "2");
    assert_eq!(map["c"], "3");
}

// ----------------------------------------------------------------------
// Form-urlencoded decoding (`+` → space, `%XX` → byte, UTF-8)
// ----------------------------------------------------------------------

#[test]
fn form_decoding_through_serde() {
    #[derive(Deserialize)]
    struct Params {
        msg: String,
    }
    for (input, want) in [
        ("/p?msg=hello%20world", "hello world"),
        ("/p?msg=hello+world", "hello world"),
        ("/p?msg=hello+wide%20world", "hello wide world"),
        ("/p?msg=caf%C3%A9", "café"),
    ] {
        let uri: Uri = parse_graceful(input).unwrap();
        let got: Params = uri.query().unwrap().deserialize().unwrap();
        assert_eq!(got.msg, want, "input: {input:?}");
    }
}

// ----------------------------------------------------------------------
// Borrowed deserialization edge — `&'a str` only when escape-free,
// `Cow<'a, str>` always succeeds.
// ----------------------------------------------------------------------

#[test]
fn borrowed_str_field_zero_copy_when_no_escapes() {
    #[derive(Deserialize, Debug)]
    struct Params<'a> {
        foo: &'a str,
    }
    let uri: Uri = parse_graceful("/p?foo=bar").unwrap();
    let query = uri.query().unwrap();
    let got: Params<'_> = query.deserialize().unwrap();
    assert_eq!(got.foo, "bar");
    // Pointer is inside the original query slice — verifies zero-copy.
    let query_encoded = query.as_encoded_str();
    let query_bytes = query_encoded.as_bytes();
    let offset = unsafe { got.foo.as_ptr().offset_from(query_bytes.as_ptr()) };
    assert!((0..query_bytes.len() as isize).contains(&offset));
}

#[test]
fn borrowed_str_field_fails_when_escapes_present() {
    #[derive(Deserialize, Debug)]
    #[expect(
        dead_code,
        reason = "field captured for the failed-deserialize assertion"
    )]
    struct Params<'a> {
        foo: &'a str,
    }
    for input in ["/p?foo=hello%20world", "/p?foo=hello+world"] {
        let uri: Uri = parse_graceful(input).unwrap();
        let result: Result<Params<'_>, _> = uri.query().unwrap().deserialize();
        assert!(result.is_err(), "expected failure for {input:?}");
    }
}

#[test]
fn cow_field_borrows_or_owns_per_encoding() {
    #[derive(Deserialize, Debug)]
    struct Params<'a> {
        #[serde(borrow)]
        foo: Cow<'a, str>,
    }
    // No escapes → Borrowed.
    let uri: Uri = parse_graceful("/p?foo=bar").unwrap();
    let got: Params<'_> = uri.query().unwrap().deserialize().unwrap();
    assert_eq!(got.foo, "bar");
    assert!(matches!(got.foo, Cow::Borrowed(_)));

    // `%XX` or `+` → Owned.
    for input in ["/p?foo=hello%20world", "/p?foo=hello+world"] {
        let uri: Uri = parse_graceful(input).unwrap();
        let got: Params<'_> = uri.query().unwrap().deserialize().unwrap();
        assert_eq!(got.foo, "hello world");
        assert!(
            matches!(got.foo, Cow::Owned(_)),
            "expected Cow::Owned for {input:?}",
        );
    }
}

// ----------------------------------------------------------------------
// Bare-key semantics — `serde_html_form` treats `?foo` as `foo=""`.
// Documented divergence from `QueryPair { value: None }`.
// ----------------------------------------------------------------------

#[test]
fn bare_key_treated_as_empty_string() {
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct Params {
        foo: String,
    }
    let uri: Uri = parse_graceful("/p?foo").unwrap();
    let got: Params = uri.query().unwrap().deserialize().unwrap();
    assert_eq!(got.foo, "");
}

// ----------------------------------------------------------------------
// Error surfaces
// ----------------------------------------------------------------------

#[test]
fn deserialize_errors_chain_via_source() {
    #[derive(Deserialize, Debug)]
    #[expect(
        dead_code,
        reason = "field captured for the failed-deserialize assertion"
    )]
    struct Params {
        n: u32,
        required: String,
    }
    for input in [
        "/p?n=not_a_number&required=x", // type mismatch
        "/p?n=1",                       // missing required field
    ] {
        let uri: Uri = parse_graceful(input).unwrap();
        let err = uri
            .query()
            .unwrap()
            .deserialize::<Params>()
            .expect_err(&format!("expected error for {input:?}"));
        assert!(
            std::error::Error::source(&err).is_some(),
            "expected error.source() for {input:?}",
        );
        assert!(
            format!("{err}").contains("deserialize"),
            "Display should mention deserialize for {input:?}",
        );
    }
}

// ----------------------------------------------------------------------
// Empty query & owned-vs-borrowed parity
// ----------------------------------------------------------------------

#[test]
fn empty_query_with_all_optional_fields() {
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct Params {
        foo: Option<String>,
        bar: Option<u32>,
    }
    let uri: Uri = parse_graceful("/p?").unwrap();
    let got: Params = uri.query().unwrap().deserialize().unwrap();
    assert_eq!(
        got,
        Params {
            foo: None,
            bar: None,
        }
    );
}

#[test]
fn owned_query_deserialize_parity() {
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct Params {
        a: String,
        b: u32,
    }
    let uri: Uri = parse_graceful("/p?a=hi&b=7").unwrap();
    let from_ref: Params = uri.query().unwrap().deserialize().unwrap();
    let from_owned: Params = uri.query().unwrap().into_owned().deserialize().unwrap();
    assert_eq!(from_ref, from_owned);
}

// ----------------------------------------------------------------------
// End-to-end: absolute-form URI with a representative filter shape.
// ----------------------------------------------------------------------

#[test]
fn absolute_form_realistic_filter() {
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct Filter {
        q: String,
        page: Option<u32>,
        tag: Vec<String>,
    }
    let uri: Uri =
        parse_graceful("https://api.example.com/search?q=rust&page=2&tag=async&tag=web").unwrap();
    let got: Filter = uri.query().unwrap().deserialize().unwrap();
    assert_eq!(
        got,
        Filter {
            q: "rust".into(),
            page: Some(2),
            tag: vec!["async".into(), "web".into()],
        }
    );
}
