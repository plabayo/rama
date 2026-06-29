//! Fuzz target for the RFC 9535 JSONPath parser and streaming matcher.
//!
//! Invariants:
//! - successful parses display to a canonical form that reparses identically;
//! - matching arbitrary concrete value paths never panics.
//!
//! Run with:
//!     cargo +nightly fuzz run json_path
#![no_main]

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use rama::json::path::{JsonPath, PathElement};

#[derive(Debug)]
struct Input<'a> {
    selector: &'a str,
    path: Vec<PathPart<'a>>,
}

#[derive(Arbitrary, Debug)]
enum PathPart<'a> {
    Member(&'a str),
    Index(usize),
}

impl<'a> Arbitrary<'a> for Input<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let selector = <&str>::arbitrary(u)?;
        let mut path = Vec::new();
        for _ in 0..u.int_in_range(0..=12)? {
            path.push(PathPart::arbitrary(u)?);
        }
        Ok(Self { selector, path })
    }
}

fuzz_target!(|input: Input<'_>| {
    let Ok(path) = input.selector.parse::<JsonPath>() else {
        return;
    };

    let rendered = path.to_string();
    let reparsed = rendered.parse::<JsonPath>();
    assert!(
        reparsed.is_ok(),
        "displayed JSONPath did not parse: {rendered:?}"
    );
    let Ok(reparsed) = reparsed else {
        return;
    };
    assert_eq!(path, reparsed);

    let concrete = input
        .path
        .into_iter()
        .map(|part| match part {
            PathPart::Member(name) => PathElement::Member(name.into()),
            PathPart::Index(index) => PathElement::Index(index),
        })
        .collect::<Vec<_>>();
    std::hint::black_box(path.matches_path(&concrete));
});
