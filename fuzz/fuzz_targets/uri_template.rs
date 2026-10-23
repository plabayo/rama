//! Fuzz target for [`rama_net::uri::UriTemplate`] and [`rama_net::uri::UriTemplateMatcher`].
//!
//! Goals: parsing, expansion and matching never panic, and a matchable template's own
//! expansion of non-empty values matches back to those values.
//!
//! Run with:
//!     cargo +nightly fuzz run uri_template
#![no_main]

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary},
    fuzz_target,
};
use rama::net::uri::{UriTemplate, UriTemplateMatcher};

#[derive(Arbitrary, Debug)]
struct Input {
    template: String,
    values: Vec<String>,
    path: String,
    query: Option<String>,
}

fuzz_target!(|input: Input| {
    let Ok(template) = UriTemplate::try_new(&input.template) else {
        return;
    };
    let variables: Vec<_> = template.variables().collect();
    let value = |variable| {
        variables
            .iter()
            .position(|v| *v == variable)
            .and_then(|index| input.values.get(index))
            .map(String::as_str)
    };
    let expanded = template.expand(value);
    let Ok(matcher) = UriTemplateMatcher::try_new(&template) else {
        return;
    };
    _ = matcher.captures(&input.path, input.query.as_deref());

    let all_defined = variables
        .iter()
        .all(|v| value(*v).is_some_and(|s| !s.is_empty()));
    if !all_defined {
        return;
    }
    let (path, query) = match expanded.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (expanded.as_str(), None),
    };
    let captures = matcher.captures(path, query);
    assert!(
        captures.is_some(),
        "{template:?} did not match its own expansion {expanded:?}"
    );
    let Some(captures) = captures else {
        return;
    };
    for variable in &variables {
        assert_eq!(
            captures.get(*variable),
            value(*variable),
            "{template:?}: {expanded:?}"
        );
    }
});
