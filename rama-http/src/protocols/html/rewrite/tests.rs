//! Tests for the streaming selector matcher, driven through the tokenizer.

use ahash::HashMap;

use super::SelectorMatcher;
use crate::protocols::html::selector::Selector;
use crate::protocols::html::tokenizer::{EndTag, LocalNameHash, StartTag, TokenSink, tokenize};

/// Drives a [`SelectorMatcher`] from token events, recording each match as
/// `(selector index, element name)` in document order.
struct Recorder {
    vm: SelectorMatcher,
    hits: Vec<(usize, String)>,
    /// Recount the open stack after every event (O(depth) each, so off for the
    /// large pathological inputs).
    check_open_counts: bool,
}

impl TokenSink for Recorder {
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        let Self {
            vm,
            hits,
            check_open_counts,
        } = self;
        let name = String::from_utf8_lossy(tag.name()).into_owned();
        vm.pop_implied_for_start(tag.name_hash());
        if *check_open_counts {
            assert_open_counts_mirror_stack(vm);
        }
        vm.push_element(tag, |index| hits.push((index, name.clone())));
        if *check_open_counts {
            assert_open_counts_mirror_stack(vm);
        }
    }

    fn end_tag(&mut self, tag: &EndTag<'_>) {
        self.vm.pop_element(tag.name_hash());
        if self.check_open_counts {
            assert_open_counts_mirror_stack(&self.vm);
        }
    }
}

/// The per-name open counts must always equal a recount of the open stack.
fn assert_open_counts_mirror_stack(vm: &SelectorMatcher) {
    let mut expected: HashMap<LocalNameHash, usize> = HashMap::default();
    for frame in vm.stack.iter().skip(1) {
        *expected.entry(frame.name).or_default() += 1;
    }
    assert_eq!(vm.open_counts, expected);
}

fn run(selectors: &[&str], html: &[u8]) -> Vec<(usize, String)> {
    run_with(selectors, html, true)
}

fn run_with(selectors: &[&str], html: &[u8], check_open_counts: bool) -> Vec<(usize, String)> {
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
        check_open_counts,
    };
    tokenize(html, &mut recorder).expect("no ambiguity in test inputs");
    recorder.vm.finish();
    assert!(
        recorder.vm.open_counts.is_empty(),
        "EOF closes every open frame"
    );
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
    assert_eq!(
        run(&["ul > li"], b"<ul><li>one<li>two</ul>"),
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
    assert_eq!(
        run(&["li:nth-child(2)"], b"<ul><li>one<li id=second>two</ul>"),
        [hit(0, "li")]
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

#[test]
fn attribute_names_match_ascii_case_insensitively() {
    assert_eq!(
        run(&["[FOO]"], b"<a foo></a><b FOO=1></b><c></c>"),
        [hit(0, "a"), hit(0, "b")]
    );
    assert_eq!(
        run(
            &[r#"[FOO="bar"]"#],
            b"<a foo='bar'></a><b FOO='bar'></b><c foo='BAR'></c><d></d>"
        ),
        [hit(0, "a"), hit(0, "b")]
    );
    assert_eq!(
        run(&[":not([FOO])"], b"<a foo></a><b FOO=1></b><c></c>"),
        [hit(0, "c")]
    );
}

#[test]
fn nth_of_type_counts_names_ascii_case_insensitively() {
    assert_eq!(
        run(
            &["my-widget:nth-of-type(2)"],
            b"<div><My-Widget></My-Widget><p></p><MY-WIDGET></MY-WIDGET></div>"
        ),
        [hit(0, "MY-WIDGET")]
    );
}

#[test]
fn nth_of_type_with_many_distinct_sibling_names() {
    // Each child costs one map lookup, however many distinct names came before.
    let siblings: String = (0..20_000).map(|i| format!("<x{i}></x{i}>")).collect();
    let html = format!("<div>{siblings}<x7></x7></div>");
    assert_eq!(run(&["x7:nth-of-type(2)"], html.as_bytes()), [hit(0, "x7")]);
}

#[test]
fn open_counts_follow_implied_and_crossed_closes() {
    // `run` recounts the open stack against the per-name counts after every event.
    for html in [
        &b"<ul><li>a<li>b<ul><li>c</ul></ul>"[..],
        b"<p>a<div>b</div><p>c<p>d",
        b"<table><tr><td>1<td>2<tr><th>3<tbody><tr><td>4</table>",
        b"<select><optgroup><option>a<option>b<optgroup><option>c</select>",
        b"<dl><dt>a<dd>b<dt>c</dl>",
        b"<ruby>a<rb>b<rt>c<rp>d<rtc>e</ruby>",
        b"<a><b><a></b></a>stray</i></a>",
        b"<x/><img><br><X></x><DIV><div></DIV></div><p>unclosed",
    ] {
        assert!(!run(&["*"], html).is_empty());
    }
}

#[test]
fn stray_end_tags_and_implied_closes_skip_the_stack_scan() {
    // Each stray `</b>` and each p-closing `<div>` meets a deep open stack; a
    // scan per tag would make this input quadratic.
    const N: usize = 50_000;
    let mut html = "<div>".repeat(N);
    html.push_str(&"<a></b>".repeat(N));
    let hits = run_with(&["div a"], html.as_bytes(), false);
    assert_eq!(hits.len(), N);
    assert!(hits.iter().all(|(index, name)| *index == 0 && name == "a"));
}
