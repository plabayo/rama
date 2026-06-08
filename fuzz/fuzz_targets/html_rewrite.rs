//! Fuzz target for the [`rama_http::protocols::html::rewrite`] rewriter.
//!
//! Three properties are checked on arbitrary input:
//!
//!   1. **Passthrough identity** — with no handlers registered, the rewriter
//!      reproduces the input byte-for-byte (or errors on a strict-mode
//!      parsing ambiguity, consistently).
//!   2. **Chunk-split stability** — rewriting the input in one `write` vs.
//!      split into two `write`s yields identical output (and the same
//!      success/error outcome). This exercises the suppression / deferred
//!      end-action state across chunk boundaries.
//!   3. **No panic** — arbitrary selectors and element mutations never panic.
//!
//! Run with:
//!     cargo +nightly fuzz run html_rewrite
#![no_main]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use rama::http::protocols::html::rewrite::{
    AttributeName, Element, ElementContentHandlers, HtmlRewriter, rewrite_str,
};
use rama::http::protocols::html::selector::Selector;

#[derive(Arbitrary, Debug)]
struct Input {
    html: String,
    selector: u8,
    op: u8,
    split: usize,
}

/// A spread of selectors covering the supported feature surface.
const SELECTORS: &[&str] = &[
    "*",
    "div",
    "a",
    "span",
    "p",
    "div > span",
    "a.link",
    "#main",
    "p:nth-child(2)",
    ":not(a)",
    "body",
    "ul li",
];

/// Applies one mutation, chosen by `op`, covering every `Element` edit.
fn apply_op(el: &mut Element<'_>, op: u8) {
    match op % 9 {
        0 => el.set_attribute(AttributeName::from_static("data-x"), "1"),
        1 => el.remove(),
        2 => el.replace("R"),
        3 => el.before("B"),
        4 => el.after("A"),
        5 => el.append("P"),
        6 => el.prepend("Q"),
        7 => el.set_inner_content("I"),
        _ => el.remove_and_keep_content(),
    }
}

/// Rewrites `html` (one-shot if `split` is `None`, else split into two
/// `write`s) and returns the output bytes, or `None` if the rewrite errored.
fn run(html: &str, selector: &Selector, op: u8, split: Option<usize>) -> Option<Vec<u8>> {
    let handlers = ElementContentHandlers::new().on(selector.clone(), move |el| {
        apply_op(el, op);
        Ok(())
    });
    let mut rewriter = HtmlRewriter::from_handlers(handlers);
    let bytes = html.as_bytes();

    let result = match split {
        None => rewriter.write(bytes),
        Some(at) => {
            let at = at.min(bytes.len());
            rewriter
                .write(&bytes[..at])
                .and_then(|()| rewriter.write(&bytes[at..]))
        }
    };
    if result.and_then(|()| rewriter.end()).is_err() {
        return None;
    }
    Some(rewriter.take_output())
}

fuzz_target!(|input: Input| {
    let html = input.html.as_str();

    // 1. No handlers => byte-identical passthrough (when not an ambiguity).
    if let Ok(out) = rewrite_str(html, ElementContentHandlers::new()) {
        assert_eq!(out, html, "no-handler rewrite changed the input");
    }

    let source = SELECTORS[input.selector as usize % SELECTORS.len()];
    let Ok(selector) = source.parse::<Selector>() else {
        return;
    };

    // 2 + 3. Chunk-split stability (and no panic) with a mutating handler.
    let one_shot = run(html, &selector, input.op, None);
    let split = run(html, &selector, input.op, Some(input.split));
    assert_eq!(
        one_shot, split,
        "chunk split changed the rewrite for selector {source:?}",
    );
});
