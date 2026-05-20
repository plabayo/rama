//! `QueryRef::deserialize` / `Query::deserialize` — serde-into-struct
//! coverage via `serde_html_form`.
//!
//! Behavioural pins for the M4 (f) API: form-decoding semantics, bare-key
//! handling, repeated keys → `Vec<T>`, borrowed vs owned deserialization,
//! and error surfaces.

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
fn into_optional_fields() {
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
// Form-urlencoded decoding
// ----------------------------------------------------------------------

#[test]
fn percent_decoding_via_serde() {
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct Params {
        msg: String,
    }
    let uri: Uri = parse_graceful("/p?msg=hello%20world").unwrap();
    let got: Params = uri.query().unwrap().deserialize().unwrap();
    assert_eq!(got.msg, "hello world");
}

#[test]
fn plus_decoding_via_serde() {
    // Form convention: `+` → space.
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct Params {
        msg: String,
    }
    let uri: Uri = parse_graceful("/p?msg=hello+world").unwrap();
    let got: Params = uri.query().unwrap().deserialize().unwrap();
    assert_eq!(got.msg, "hello world");
}

#[test]
fn utf8_via_serde() {
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct Params {
        city: String,
    }
    let uri: Uri = parse_graceful("/p?city=caf%C3%A9").unwrap();
    let got: Params = uri.query().unwrap().deserialize().unwrap();
    assert_eq!(got.city, "café");
}

// ----------------------------------------------------------------------
// Borrowed deserialization — the documented edge from the rustdoc
// ----------------------------------------------------------------------

#[test]
fn borrowed_str_field_zero_copy_when_no_escapes() {
    // No `%` and no `+` in `foo=bar` — `&str` deserializes by borrowing
    // straight from the query bytes.
    #[derive(Deserialize, Debug)]
    struct Params<'a> {
        foo: &'a str,
    }
    let uri: Uri = parse_graceful("/p?foo=bar").unwrap();
    let query = uri.query().unwrap();
    let got: Params<'_> = query.deserialize().unwrap();
    assert_eq!(got.foo, "bar");
    // Verify it really borrowed: pointer falls inside the query bytes.
    let query_bytes = query.as_bytes();
    let foo_ptr = got.foo.as_ptr();
    let q_start = query_bytes.as_ptr();
    // Safety: just a pointer-arithmetic check, not dereferencing.
    let offset = unsafe { foo_ptr.offset_from(q_start) };
    assert!(
        (0..query_bytes.len() as isize).contains(&offset),
        "expected got.foo to borrow from the query slice (offset {offset})",
    );
}

#[test]
fn borrowed_str_field_fails_when_escapes_present() {
    // `%20` requires decoding → can't borrow → `&str` deserialize fails.
    #[derive(Deserialize, Debug)]
    #[expect(
        dead_code,
        reason = "field captured for the failed-deserialize assertion"
    )]
    struct Params<'a> {
        foo: &'a str,
    }
    let uri: Uri = parse_graceful("/p?foo=hello%20world").unwrap();
    let result: Result<Params<'_>, _> = uri.query().unwrap().deserialize();
    assert!(
        result.is_err(),
        "expected failure deserializing escaped value into &str"
    );
}

#[test]
fn borrowed_cow_field_owns_on_escape() {
    // `Cow<str>` succeeds in both cases: borrows when no escapes,
    // owns when decoding was required.
    #[derive(Deserialize, Debug)]
    struct Params<'a> {
        #[serde(borrow)]
        foo: Cow<'a, str>,
    }

    // No escapes → Borrowed.
    let uri1: Uri = parse_graceful("/p?foo=bar").unwrap();
    let g1: Params<'_> = uri1.query().unwrap().deserialize().unwrap();
    assert_eq!(g1.foo, "bar");
    assert!(matches!(g1.foo, Cow::Borrowed(_)));

    // Escaped → Owned.
    let uri2: Uri = parse_graceful("/p?foo=hello%20world").unwrap();
    let g2: Params<'_> = uri2.query().unwrap().deserialize().unwrap();
    assert_eq!(g2.foo, "hello world");
    assert!(matches!(g2.foo, Cow::Owned(_)));

    // Plus → Owned (form convention).
    let uri3: Uri = parse_graceful("/p?foo=hello+world").unwrap();
    let g3: Params<'_> = uri3.query().unwrap().deserialize().unwrap();
    assert_eq!(g3.foo, "hello world");
    assert!(matches!(g3.foo, Cow::Owned(_)));
}

// ----------------------------------------------------------------------
// Bare-key semantics — serde_html_form treats `?foo` as `foo=""`
// ----------------------------------------------------------------------

#[test]
fn bare_key_treated_as_empty_string() {
    // Documented divergence from QueryPair { value: None }.
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
fn type_mismatch_errors() {
    #[derive(Deserialize, Debug)]
    #[expect(
        dead_code,
        reason = "field captured for the failed-deserialize assertion"
    )]
    struct Params {
        n: u32,
    }
    let uri: Uri = parse_graceful("/p?n=not_a_number").unwrap();
    let result: Result<Params, _> = uri.query().unwrap().deserialize();
    let err = result.expect_err("expected type-mismatch error");
    // source() chains to the underlying serde_html_form error.
    let source = std::error::Error::source(&err);
    assert!(source.is_some(), "expected error.source() to expose inner");
    // Display should mention "deserialize" so users can spot it in logs.
    let display = format!("{err}");
    assert!(
        display.contains("deserialize"),
        "Display should mention deserialize: {display:?}",
    );
}

#[test]
fn missing_required_field_errors() {
    #[derive(Deserialize, Debug)]
    #[expect(
        dead_code,
        reason = "field captured for the failed-deserialize assertion"
    )]
    struct Params {
        required: String,
    }
    let uri: Uri = parse_graceful("/p?other=x").unwrap();
    let result: Result<Params, _> = uri.query().unwrap().deserialize();
    assert!(result.is_err(), "expected missing-field error");
}

// ----------------------------------------------------------------------
// Empty / minimal queries
// ----------------------------------------------------------------------

#[test]
fn empty_query_with_all_optional_fields() {
    // Empty query (`?` with nothing) → all-optional struct deserializes
    // to all-None.
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

// ----------------------------------------------------------------------
// Owned vs borrowed parity
// ----------------------------------------------------------------------

#[test]
fn owned_query_deserialize_parity() {
    // Query::deserialize and QueryRef::deserialize must produce the
    // same value for the same input.
    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct Params {
        a: String,
        b: u32,
    }
    let uri: Uri = parse_graceful("/p?a=hi&b=7").unwrap();
    let from_ref: Params = uri.query().unwrap().deserialize().unwrap();
    let owned = uri.query().unwrap().to_owned();
    let from_owned: Params = owned.deserialize().unwrap();
    assert_eq!(from_ref, from_owned);
}

// ----------------------------------------------------------------------
// Absolute-form URI (sanity that the call chain works end-to-end)
// ----------------------------------------------------------------------

#[test]
fn absolute_form_deserialize() {
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
