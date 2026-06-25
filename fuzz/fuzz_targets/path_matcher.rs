//! Fuzz target for [`rama_net::uri::PathPattern`].
//!
//! Goals: compilation and matching never panic on any pattern/path bytes
//! (the matcher is infallible by contract), and the two match entry points
//! stay consistent — `is_match` must agree with `captures().is_some()` for
//! every input, since `is_match` takes an allocation-free fast path for
//! capture-free patterns that must not diverge from the capturing path.
//!
//! Run with:
//!     cargo +nightly fuzz run path_matcher
#![no_main]

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary},
    fuzz_target,
};
use rama::net::uri::{PathMatchOptions, PathPattern, PathRef};

#[derive(Arbitrary, Debug)]
struct Input {
    pattern: String,
    path: String,
    ignore_ascii_case: bool,
    percent_decode: bool,
}

fuzz_target!(|input: Input| {
    let opts = PathMatchOptions {
        partial: false,
        ignore_ascii_case: input.ignore_ascii_case,
        percent_decode: input.percent_decode,
    };
    let pat = PathPattern::new_with_opts(input.pattern.as_str(), opts);
    let path = PathRef::from_raw_str(&input.path);

    let matched = pat.is_match(path);
    let caps = pat.captures(path);
    assert_eq!(
        matched,
        caps.is_some(),
        "is_match vs captures disagree: pattern={:?} path={:?}",
        input.pattern,
        input.path,
    );

    if let Some(caps) = caps {
        for (name, _value) in caps.iter() {
            // Every iterated name must be resolvable (duplicate names resolve
            // to the first binding, so don't assert value equality here).
            assert!(caps.get(name).is_some());
        }
        std::hint::black_box((caps.glob(), caps.is_empty()));
    }
});
