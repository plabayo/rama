//! Tests for the streaming selector matcher, driven through the tokenizer.

use super::SelectorMatcher;
use crate::protocols::html::selector::Selector;
use crate::protocols::html::tokenizer::{EndTag, StartTag, TokenSink, tokenize};

/// Drives a [`SelectorMatcher`] from token events, recording each match as
/// `(selector index, element name)` in document order.
struct Recorder {
    vm: SelectorMatcher,
    hits: Vec<(usize, String)>,
}

impl TokenSink for Recorder {
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        let Self { vm, hits } = self;
        let name = String::from_utf8_lossy(tag.name()).into_owned();
        vm.push_element(tag, |index| hits.push((index, name.clone())));
    }

    fn end_tag(&mut self, tag: &EndTag<'_>) {
        self.vm.pop_element(tag.name_hash());
    }
}

fn run(selectors: &[&str], html: &[u8]) -> Vec<(usize, String)> {
    let selectors: Vec<Selector> = selectors
        .iter()
        .map(|s| {
            s.parse()
                .unwrap_or_else(|e| panic!("`{s}` should parse: {e}"))
        })
        .collect();
    let mut recorder = Recorder {
        vm: SelectorMatcher::new(&selectors),
        hits: Vec::new(),
    };
    tokenize(html, &mut recorder).expect("no ambiguity in test inputs");
    recorder.hits
}

fn hit(index: usize, name: &str) -> (usize, String) {
    (index, name.to_owned())
}

#[test]
fn type_selector() {
    assert_eq!(
        run(&["p"], b"<p></p><div></div><p></p>"),
        [hit(0, "p"), hit(0, "p")]
    );
}

#[test]
fn class_and_id() {
    assert_eq!(
        run(&[".x"], b"<a class=\"x y\"></a><a class=\"z\"></a>"),
        [hit(0, "a")]
    );
    assert_eq!(
        run(&["#main"], b"<div id=main></div><div id=other></div>"),
        [hit(0, "div")]
    );
}

#[test]
fn descendant_vs_child() {
    // descendant: matches the deep <p>, not the top-level one.
    assert_eq!(
        run(&["div p"], b"<div><span><p></p></span></div><p></p>"),
        [hit(0, "p")]
    );
    // child: only the direct child <p>.
    assert_eq!(
        run(
            &["div > p"],
            b"<div><p></p></div><div><span><p></p></span></div>"
        ),
        [hit(0, "p")]
    );
}

#[test]
fn child_combinator_multiple_children() {
    assert_eq!(
        run(&["ul > li"], b"<ul><li></li><li></li></ul>"),
        [hit(0, "li"), hit(0, "li")]
    );
}

#[test]
fn deep_chain() {
    assert_eq!(
        run(
            &["a b > c d"],
            b"<a><x><b><c><y><d></d></y></c></b></x></a>"
        ),
        [hit(0, "d")]
    );
}

#[test]
fn attributes() {
    assert_eq!(
        run(
            &["a[href^=\"https\"]"],
            b"<a href=\"https://x\"></a><a href=\"http://y\"></a>"
        ),
        [hit(0, "a")]
    );
    assert_eq!(
        run(
            &["[data-x~=\"b\"]"],
            b"<i data-x=\"a b c\"></i><i data-x=\"ab\"></i>"
        ),
        [hit(0, "i")]
    );
}

#[test]
fn nth_child_and_of_type() {
    assert_eq!(
        run(
            &["li:nth-child(odd)"],
            b"<ul><li></li><li></li><li></li></ul>"
        ),
        [hit(0, "li"), hit(0, "li")]
    );
    // 2nd <p> by type (a <span> sits between the two <p>s).
    assert_eq!(
        run(
            &["p:nth-of-type(2)"],
            b"<div><p></p><span></span><p id=second></p></div>"
        ),
        [hit(0, "p")]
    );
}

#[test]
fn negation() {
    assert_eq!(
        run(
            &["a:not(.skip)"],
            b"<a></a><a class=skip></a><a class=keep></a>"
        ),
        [hit(0, "a"), hit(0, "a")]
    );
}

#[test]
fn void_element_is_matched_but_not_pushed() {
    // <img> is void: it matches `div > img`, and the following <p> is still
    // a child of <div> (img did not open a scope).
    assert_eq!(
        run(&["div > img", "div > p"], b"<div><img><p></p></div>"),
        [hit(0, "img"), hit(1, "p")]
    );
}

#[test]
fn multiple_selectors_and_lists() {
    assert_eq!(
        run(&["a", "b"], b"<a></a><b></b><c></c>"),
        [hit(0, "a"), hit(1, "b")]
    );
    // a comma list within one selector reports the same index for both.
    assert_eq!(
        run(&["a, b"], b"<a></a><b></b>"),
        [hit(0, "a"), hit(0, "b")]
    );
}

#[test]
fn same_name_nesting() {
    // `div div` matches the inner div (descendant of the outer), not the outer.
    assert_eq!(
        run(&["div div"], b"<div><div></div></div>"),
        [hit(0, "div")]
    );
}

#[test]
fn universal_and_star_child() {
    assert_eq!(run(&["*"], b"<a><b></b></a>"), [hit(0, "a"), hit(0, "b")]);
}
