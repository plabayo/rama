//! Fuzz target for the [`rama_http::protocols::html::selector`] engine.
//!
//! Goals: never panic on any input; the parser returns a typed error for
//! invalid/unsupported selectors. For every selector that *does* parse, two
//! properties are checked:
//!
//!   1. Round-trip: serializing it and re-parsing yields an equal AST.
//!   2. Matching it against a small tree never panics.
//!
//! Run with:
//!     cargo +nightly fuzz run selector_parse
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::http::protocols::html::selector::{Dom, Selector};

fuzz_target!(|data: &str| {
    let Ok(selector) = data.parse::<Selector>() else {
        return;
    };

    // Serialization must round-trip back to an equal selector.
    let serialized = selector.to_string();
    assert_eq!(
        serialized.parse::<Selector>().ok().as_ref(),
        Some(&selector),
        "round-trip failed for {data:?} -> {serialized:?}",
    );

    // Matching against a tiny tree must terminate without panicking.
    let mut dom = Dom::new();
    let root = dom.create("div");
    let child = dom.append(root, "span");
    dom.set_attr(child, "class", "alpha beta");
    dom.set_attr(child, "id", "node");
    dom.set_attr(child, "data-x", "y-z");
    let _ = selector.matches(&dom.element(child));
    let _ = selector.matches(&dom.element(root));
});
