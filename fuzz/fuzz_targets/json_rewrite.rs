//! Fuzz target for streaming JSON rewriting.
//!
//! Invariants:
//! - rewrites are stable across arbitrary chunk boundaries;
//! - successful rewrites produce valid JSON;
//! - an empty handler set is an exact passthrough.
//!
//! Run with:
//!     cargo +nightly fuzz run json_rewrite
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::json::{
    path::JsonPath,
    rewrite::{JsonHandlers, JsonRewriter, raw_json, rewrite_bytes},
};

const HEADER_LEN: usize = 4;

const SELECTORS: &[&str] = &[
    "$",
    "$.*",
    "$[*]",
    "$.prompt",
    "$.extensions",
    "$.extensions[*]",
    "$.extensions[0]",
    "$.items",
    "$.items[*]",
    "$.items[0]",
    "$..id",
    "$..secret",
];

const REPLACEMENTS: &[&[u8]] = &[
    b"null",
    b"true",
    b"0",
    br#""redacted""#,
    br#"{}"#,
    br#"[]"#,
    br#"{"replaced":true}"#,
    br#"[{"id":9}]"#,
];

fuzz_target!(|data: &[u8]| {
    if data.len() <= HEADER_LEN {
        return;
    }

    let selector = SELECTORS[usize::from(data[0]) % SELECTORS.len()]
        .parse::<JsonPath>()
        .expect("static selector must parse");
    let operation = data[1] % 3;
    let split = usize::from(data[2]) % (data.len() - HEADER_LEN + 1);
    let replacement = REPLACEMENTS[usize::from(data[3]) % REPLACEMENTS.len()];
    let json = &data[HEADER_LEN..];

    if let Ok(identity) = rewrite_bytes(json, JsonHandlers::new()) {
        assert_eq!(identity, json);
    }

    let one_shot = rewrite(json, &selector, operation, replacement, None);
    let chunked = rewrite(json, &selector, operation, replacement, Some(split));
    assert_eq!(one_shot, chunked);

    if let Some(output) = one_shot {
        serde_json::from_slice::<serde_json::Value>(&output)
            .expect("successful rewrite output must be valid JSON");
    }
});

fn rewrite(
    json: &[u8],
    selector: &JsonPath,
    operation: u8,
    replacement: &[u8],
    split: Option<usize>,
) -> Option<Vec<u8>> {
    let handlers = JsonHandlers::new().on(selector.clone(), move |value| match operation {
        0 => Ok(()),
        1 => value.replace(raw_json(replacement)),
        _ => {
            if value.path().segments().is_empty() {
                value.replace(raw_json(replacement))
            } else {
                value.remove();
                Ok(())
            }
        }
    });

    let mut rewriter = JsonRewriter::from_handlers(handlers);
    match split {
        Some(split) => {
            rewriter.write(&json[..split]).ok()?;
            rewriter.write(&json[split..]).ok()?;
        }
        None => rewriter.write(json).ok()?,
    }
    rewriter.end().ok()?;
    Some(rewriter.take_output())
}
