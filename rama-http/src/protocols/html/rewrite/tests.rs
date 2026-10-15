//! Tests for the streaming selector matcher, driven through the tokenizer.

use std::time::{Duration, Instant};

use quickcheck_macros::quickcheck;

use super::{AttributeName, ElementContentHandlers, HtmlRewriter, ScopeMode, SelectorMatcher};
use crate::protocols::html::selector::{Dom, NodeId, Selector};
use crate::protocols::html::tokenizer::{Doctype, EndTag, StartTag, Text, TokenSink, tokenize};

/// Drives a [`SelectorMatcher`] from token events, recording each match as
/// `(selector index, element name)` in document order.
struct Recorder {
    vm: SelectorMatcher,
    hits: Vec<(usize, String)>,
    /// Recount the open stack after every event (O(depth) each, so off for the
    /// large pathological inputs).
    check_caches: bool,
}

impl TokenSink for Recorder {
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        let Self {
            vm,
            hits,
            check_caches,
        } = self;
        let name = String::from_utf8_lossy(tag.name()).into_owned();
        let plan = vm.prepare_start(tag);
        vm.sync();
        if *check_caches {
            assert_stack_caches(vm);
        }
        vm.push_element(tag, plan, |index| hits.push((index, name.clone())));
        if *check_caches {
            assert_stack_caches(vm);
        }
    }

    fn text(&mut self, text: &Text<'_>) {
        self.vm.text(text.raw());
        self.vm.sync();
    }

    fn doctype(&mut self, doctype: &Doctype<'_>) {
        self.vm.tree.doctype(doctype.raw());
    }

    fn end_tag(&mut self, tag: &EndTag<'_>) {
        self.vm.pop_element(tag);
        self.vm.sync();
        if self.check_caches {
            assert_stack_caches(&self.vm);
        }
    }
}

/// Cached scope boundaries and per-name links must agree with a stack scan,
/// and every frame must carry its selector state row.
fn assert_stack_caches(vm: &SelectorMatcher) {
    vm.assert_consistent();
}

fn run(selectors: &[&str], html: &[u8]) -> Vec<(usize, String)> {
    run_with(selectors, html, true)
}

fn run_with(selectors: &[&str], html: &[u8], check_caches: bool) -> Vec<(usize, String)> {
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
        check_caches,
    };
    tokenize(html, &mut recorder).expect("no ambiguity in test inputs");
    recorder.vm.finish();
    recorder.vm.sync();
    assert!(recorder.vm.tree.depth() == 1, "EOF closes every open frame");
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
fn scope_caches_follow_implied_and_crossed_closes() {
    // `run` checks stack caches against independent scans after every event.
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

fn edited(input: &str, selector: &str, action: u8, split: usize) -> Vec<u8> {
    let handlers = ElementContentHandlers::new().on(selector.parse().unwrap(), move |el| {
        match action {
            0 => el.append("!"),
            1 => el.remove(),
            _ => el.set_inner_content("X"),
        }
        Ok(())
    });
    let mut rewriter = HtmlRewriter::from_handlers(handlers);
    let bytes = input.as_bytes();
    rewriter.write(&bytes[..split]).unwrap();
    rewriter.write(&bytes[split..]).unwrap();
    rewriter.end().unwrap();
    rewriter.take_output()
}

#[test]
fn scoped_rewrites_match_browser_end_boundaries_at_every_split() {
    for (input, selector, expected) in [
        (
            "<table><tr><td>A<table><tr><td>inner</td></tr></table>B</td></tr></table>",
            "td",
            [
                "<table><tr><td>A<table><tr><td>inner!</td></tr></table>B!</td></tr></table>",
                "<table><tr></tr></table>",
                "<table><tr><td>X</td></tr></table>",
            ],
        ),
        (
            "<ul><li>a<ul><li>b</ul></ul>",
            "li",
            [
                "<ul><li>a<ul><li>b!</ul>!</ul>",
                "<ul></ul>",
                "<ul><li>X</ul>",
            ],
        ),
        (
            "<p>secret<button>y<div>still secret?</div></button>tail</p>",
            "p",
            [
                "<p>secret<button>y<div>still secret?</div></button>tail!</p>",
                "",
                "<p>X</p>",
            ],
        ),
        (
            "<div>x<table><tr><td></div>kept?</td></tr></table>tail</div>",
            "div",
            [
                "<div>x<table><tr><td></div>kept?</td></tr></table>tail!</div>",
                "",
                "<div>X</div>",
            ],
        ),
        (
            "<dl><dt>a<dl><dd>b</dl>tail</dt></dl>",
            "dt",
            [
                "<dl><dt>a<dl><dd>b</dl>tail!</dt></dl>",
                "<dl></dl>",
                "<dl><dt>X</dt></dl>",
            ],
        ),
    ] {
        for (action, expected) in expected.into_iter().enumerate() {
            for split in 0..=input.len() {
                assert_eq!(
                    edited(input, selector, action as u8, split),
                    expected.as_bytes(),
                    "{selector}, action {action}, split {split}, input {input}"
                );
            }
        }
    }
}

#[test]
fn scope_boundaries_preserve_selector_ancestry() {
    for (selector, input, expected) in [
        (
            "table td table td",
            "<table><tr><td>A<table><tr><td>B</table></table>",
            vec![hit(0, "td")],
        ),
        ("li li", "<ul><li>a<ul><li>b</ul></ul>", vec![hit(0, "li")]),
        (
            "p div",
            "<p><button><div></div></button></p>",
            vec![hit(0, "div")],
        ),
        (
            "div span",
            "<div><table><tr><td></div><span></span></table></div>",
            vec![hit(0, "span")],
        ),
    ] {
        assert_eq!(run(&[selector], input.as_bytes()), expected);
    }
}

#[test]
fn nearest_match_mode_is_explicitly_available() {
    let handlers = ElementContentHandlers::new().on("p".parse().unwrap(), |el| {
        el.remove();
        Ok(())
    });
    let mut rewriter =
        HtmlRewriter::from_handlers(handlers).with_scope_mode(ScopeMode::NearestMatch);
    rewriter
        .write(b"<p>secret<button><div>visible</div>")
        .unwrap();
    rewriter.end().unwrap();
    assert_eq!(rewriter.take_output(), b"<div>visible</div>");
}

/// Inputs that make a stack scan per token quadratic: deep stacks, then
/// tokens whose rules look for something below or across them.
fn adversarial(id: usize, n: usize) -> String {
    match id {
        0 => format!("<p><button>{}{}", "<span>".repeat(n), "<div>".repeat(n)),
        1 => format!(
            "<div><table><tr><td>{}{}",
            "<em>".repeat(n),
            "</div></span>".repeat(n)
        ),
        2 => format!("{}{}", "<ul><li>".repeat(n), "<li>".repeat(n)),
        3 => format!("{}{}", "<table><tr><td>".repeat(n), "<td>x".repeat(n)),
        4 => format!("{}{}", "<svg>".repeat(n), "</div>".repeat(n)),
        5 => format!("<svg>{}{}", "<g>".repeat(n), "</x>".repeat(n)),
        6 => format!("{}{}", "<table><caption>".repeat(n), "<tr>".repeat(n)),
        7 => format!("{}{}", "<template>".repeat(n), "<tr><td>x</tr>".repeat(n)),
        8 => format!("{}{}", "<select>".repeat(n), "<option>".repeat(n)),
        9 => format!("<ruby>{}{}", "<rtc>".repeat(n), "<rt>".repeat(n)),
        10 => format!("{}{}", "<h1>".repeat(n), "</h2>".repeat(n)),
        11 => format!(
            "<table>{}",
            "<col><colgroup><tbody><tr><td><caption>".repeat(n)
        ),
        12 => format!("{}{}", "<math><mi>".repeat(n), "</mi></math>x".repeat(n)),
        13 => format!("{}{}", "<b><p>".repeat(n), "</b>".repeat(n)),
        14 => format!("{}{}", "<form><div>".repeat(n), "</form>".repeat(n)),
        15 => format!("<table>{}", "<div><table><tr>".repeat(n)),
        16 => format!(
            "{}{}",
            "<svg><foreignObject>".repeat(n),
            "<p></svg>".repeat(n)
        ),
        17 => format!(
            "{}{}",
            "<template><table>".repeat(n),
            "</template>".repeat(n)
        ),
        18 => format!("{}{}", "<x-a>".repeat(n), "</x-b>".repeat(n)),
        19 => format!("{}{}", "<dl><dt>".repeat(n), "<dd>".repeat(n)),
        20 => format!(
            "{}{}",
            "<div>".repeat(n),
            "<body class=b><html lang=x></p></br>".repeat(n)
        ),
        21 => format!(
            "<head></head>{}",
            "<script></script><meta><style></style>".repeat(n)
        ),
        22 => format!("{}{}", "<math><svg>".repeat(n), "<style></style>".repeat(n)),
        23 => format!("{}{}", "<div><table>".repeat(n), "<span></span>".repeat(n)),
        _ => format!("{}{}", "<p>".repeat(n), "</p>".repeat(n)),
    }
}

const ADVERSARIAL: usize = 25;

/// Every frame inspection, pop and rule iteration is counted: a stack scan
/// per token would grow with the square of these inputs.
#[test]
fn scoped_end_and_implied_checks_have_linear_work() {
    for n in [100, 1_000, 20_000] {
        for id in 0..ADVERSARIAL {
            let input = adversarial(id, n);
            let mut recorder = Recorder {
                vm: SelectorMatcher::new(&["div span".parse().unwrap()]),
                hits: Vec::new(),
                check_caches: false,
            };
            tokenize(input.as_bytes(), &mut recorder).unwrap();
            recorder.vm.finish();
            recorder.vm.sync();
            let tokens = input.matches('<').count();
            let work = recorder.vm.tree.work.get();
            assert!(
                work <= 64 * tokens + 100,
                "pattern {id}: {work} steps for {tokens} tokens"
            );
        }
    }
}

/// End-to-end tripwire for anything superlinear (tokenizer, tree, matcher,
/// rewriter): 4x the input must stay well under 16x the time.
#[test]
fn rewriting_time_is_linear_in_the_input() {
    fn fastest(input: &[u8], mode: ScopeMode) -> Duration {
        (0..3)
            .map(|_| {
                let started = Instant::now();
                let handlers =
                    ElementContentHandlers::new().on("div span".parse().unwrap(), |el| {
                        el.append("!");
                        Ok(())
                    });
                let mut rewriter = HtmlRewriter::from_handlers(handlers).with_scope_mode(mode);
                rewriter.write(input).unwrap();
                rewriter.end().unwrap();
                assert!(!rewriter.take_output().is_empty());
                started.elapsed()
            })
            .min()
            .unwrap_or_default()
    }

    for mode in [ScopeMode::Browser, ScopeMode::NearestMatch] {
        for id in 0..ADVERSARIAL {
            let small = adversarial(id, 4_000);
            let large = adversarial(id, 16_000);
            // Retry once: a loaded machine can stall any single measurement.
            let mut timings = Vec::new();
            let ok = (0..2).any(|_| {
                let large_time = fastest(large.as_bytes(), mode);
                let small_time = fastest(small.as_bytes(), mode);
                timings.push((small_time, large_time));
                large_time.as_secs_f64() / small_time.as_secs_f64().max(1e-6) < 8.0
            });
            assert!(
                ok,
                "pattern {id} in {mode:?} grows superlinearly (small, large): {timings:?}"
            );
        }
    }
}

#[quickcheck]
fn nested_scope_suppression_is_complete(depth: u8, choice: u8, split: usize) -> bool {
    let depth = usize::from(depth % 32) + 1;
    let (start, attack, end, selector, expected) = match choice % 3 {
        0 => (
            "<p><button>",
            "<div>private</div>",
            "</button></p>",
            "p",
            "",
        ),
        1 => (
            "<div><table><tr><td>",
            "</div>private",
            "</td></tr></table></div>",
            "div",
            "",
        ),
        _ => (
            "<ul><li>",
            "<ul><li>private</ul>",
            "</li></ul>",
            "li",
            "<ul></ul>",
        ),
    };
    let input = format!(
        "{start}{}{attack}{}{end}",
        "<span>".repeat(depth),
        "</span>".repeat(depth)
    );
    let split = split % (input.len() + 1);
    edited(&input, selector, 1, split) == expected.as_bytes()
}

#[test]
fn document_end_anchors_preserve_edits_and_keep_suppression_active() {
    for (selector, action, input, expected) in [
        (
            "body",
            2,
            "<html><body>old</body>tail</html>",
            "<html><body>X</body></html>",
        ),
        (
            "body",
            1,
            "<html><body>old</body>tail</html>",
            "<html></html>",
        ),
        (
            "body",
            0,
            "<html><body>old</body>tail</html>",
            "<html><body>old!</body>tail</html>",
        ),
        (
            "html",
            2,
            "<html><body>old</body>tail</html>",
            "<html>X</html>",
        ),
        (
            "body",
            0,
            "<body>old</body></body>",
            "<body>old!</body></body>",
        ),
    ] {
        for split in 0..=input.len() {
            assert_eq!(edited(input, selector, action, split), expected.as_bytes());
        }
    }
}

#[test]
fn nearest_match_honors_non_void_self_closing_flag() {
    let handlers = ElementContentHandlers::new().on("x".parse().unwrap(), |el| {
        el.replace("R");
        Ok(())
    });
    let mut rewriter =
        HtmlRewriter::from_handlers(handlers).with_scope_mode(ScopeMode::NearestMatch);
    rewriter.write(b"<x/>tail").unwrap();
    rewriter.end().unwrap();
    assert_eq!(rewriter.take_output(), b"Rtail");
}

#[test]
fn misnested_formatting_starts_keep_suppression_conservative() {
    let input = "<a>private<a>also private</a>outer private</a>tail";
    for split in 0..=input.len() {
        assert_eq!(edited(input, "a", 1, split), b"tail");
        assert_eq!(edited(input, "a", 2, split), b"<a>X</a>tail");
    }
}

#[test]
fn combined_document_anchors_finish_inner_edits_before_outer_edits() {
    for input in ["<html><body>x</html>", "<html><body>x</body></html>"] {
        for split in 0..=input.len() {
            let handlers = ElementContentHandlers::new()
                .on("body".parse().unwrap(), |el| {
                    el.append("a");
                    el.after("B");
                    Ok(())
                })
                .on("html".parse().unwrap(), |el| {
                    el.append("H");
                    el.after("z");
                    Ok(())
                });
            let mut rewriter = HtmlRewriter::from_handlers(handlers);
            rewriter.write(&input.as_bytes()[..split]).unwrap();
            rewriter.write(&input.as_bytes()[split..]).unwrap();
            rewriter.end().unwrap();
            let expected = if input.contains("</body>") {
                "<html><body>xa</body>BH</html>z"
            } else {
                "<html><body>xaBH</html>z"
            };
            assert_eq!(rewriter.take_output(), expected.as_bytes());
        }
    }
}

// --- browser-faithful parsing: leak regressions, split invariance ----------

/// An edit applied to every element a selector matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edit {
    Append,
    Remove,
    Inner,
    Replace,
    SetAttribute,
}

/// Rewrites `input` fed as `chunks`.
fn rewrite_chunks<'a>(
    chunks: impl IntoIterator<Item = &'a [u8]>,
    selector: &str,
    edit: Edit,
    mode: ScopeMode,
) -> Vec<u8> {
    let handlers = ElementContentHandlers::new().on(selector.parse().unwrap(), move |el| {
        match edit {
            Edit::Append => el.append("@@"),
            Edit::Remove => el.remove(),
            Edit::Inner => el.set_inner_content("I"),
            Edit::Replace => el.replace("R"),
            Edit::SetAttribute => {
                el.set_attribute(AttributeName::from_static("data-hit"), "1");
            }
        }
        Ok(())
    });
    let mut rewriter = HtmlRewriter::from_handlers(handlers).with_scope_mode(mode);
    let mut out = Vec::new();
    for chunk in chunks {
        rewriter.write(chunk).unwrap();
        out.extend(rewriter.take_output());
    }
    rewriter.end().unwrap();
    out.extend(rewriter.take_output());
    out
}

/// Asserts the rewrite of `input` is `expected` one-shot, split in two at
/// every byte, and fed byte by byte.
fn assert_rewrite(input: &[u8], selector: &str, edit: Edit, mode: ScopeMode, expected: &[u8]) {
    let shown = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    let one_shot = rewrite_chunks([input], selector, edit, mode);
    assert_eq!(
        shown(&one_shot),
        shown(expected),
        "{selector} {edit:?} {mode:?}: {}",
        shown(input)
    );
    for split in 0..=input.len() {
        let (a, b) = input.split_at(split);
        assert_eq!(
            rewrite_chunks([a, b], selector, edit, mode),
            expected,
            "{selector} {edit:?} {mode:?} split {split}: {}",
            shown(input)
        );
    }
    assert_eq!(
        rewrite_chunks(input.chunks(1), selector, edit, mode),
        expected,
        "{selector} {edit:?} {mode:?} byte by byte: {}",
        shown(input)
    );
}

/// Content the rewriter tokenized differently than browsers (around SVG and
/// MathML, templates and decoded attributes) slipped out of a removed
/// element. Expected outputs are checked against Chromium's parse.
#[test]
fn removed_elements_never_leak_around_foreign_content() {
    for (input, removed, inner) in [
        (
            "<div class=x><svg/><textarea></div>secret</textarea></div>tail",
            "tail",
            "<div class=x>I</div>tail",
        ),
        (
            "<div class=x><math/><style></div>secret</style></div>tail",
            "tail",
            "<div class=x>I</div>tail",
        ),
        (
            "<p class=x><span><svg></span><style></p>secret</style>tail",
            "",
            "<p class=x>I",
        ),
        (
            "<svg><title><div class=x></title><style></div>secret</style>",
            "<svg><title>",
            "<svg><title><div class=x>I",
        ),
        (
            "<svg><desc><div class=x></desc><textarea></div>secret</textarea>",
            "<svg><desc>",
            "<svg><desc><div class=x>I",
        ),
        (
            "<math><mi><div class=x></mi><xmp></div>secret</xmp>",
            "<math><mi>",
            "<math><mi><div class=x>I",
        ),
        (
            "<div class=x><math><svg><b><style></div>secret</style>",
            "",
            "<div class=x>I",
        ),
        (
            "<math><svg><desc><style><p class=x>secret",
            "<math><svg><desc><style>",
            "<math><svg><desc><style><p class=x>I",
        ),
        (
            "<template><col><style></template><p class=x>secret",
            "<template><col><style></template>",
            "<template><col><style></template><p class=x>I",
        ),
        (
            "<math class=x><annotation-xml encoding=\"text&#47html\"><div>secret",
            "",
            "<math class=x>I",
        ),
        (
            "<math class=x><annotation-xml encoding=\"text&sol;html\"><div>secret",
            "",
            "<math class=x>I",
        ),
        (
            "<math class=x><annotation-xml encoding=\"application/xhtml&plus;xml\"><div>secret",
            "",
            "<math class=x>I",
        ),
        // CDATA is a bogus comment in an integration point, as in Chromium.
        (
            "<div class=x><svg><foreignObject><![CDATA[</foreignObject></svg></div>]]>secret",
            "]]>secret",
            "<div class=x>I</div>]]>secret",
        ),
        (
            "<div class=x><svg><![CDATA[</svg></div>]]>secret</svg></div>tail",
            "tail",
            "<div class=x>I</div>tail",
        ),
        (
            "<div class=x><select><style></div>secret</style></div>tail",
            "",
            "<div class=x>I",
        ),
    ] {
        assert_rewrite(
            input.as_bytes(),
            ".x",
            Edit::Remove,
            ScopeMode::Browser,
            removed.as_bytes(),
        );
        assert_rewrite(
            input.as_bytes(),
            ".x",
            Edit::Inner,
            ScopeMode::Browser,
            inner.as_bytes(),
        );
    }
}

/// Browser structure rules a removal has to follow (checked against
/// Chromium): headings, lists, select, ruby, tables, forms, quirks.
#[test]
fn removals_follow_browser_structure() {
    for (input, removed) in [
        ("<div class=&#120;>secret</div>tail", "tail"),
        // Quirks mode: class selectors ignore ASCII case.
        ("<div class=X>secret</div>tail", "tail"),
        (
            "<!DOCTYPE html><div class=X>secret</div>tail",
            "<!DOCTYPE html><div class=X>secret</div>tail",
        ),
        (
            "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Frameset//EN\" \"\"><p class=x>a<table></table>b</p>tail",
            "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Frameset//EN\" \"\">tail",
        ),
        (
            "<!DOCTYPE html><p class=x>a<table></table>b</p>tail",
            "<!DOCTYPE html><table></table>b</p>tail",
        ),
        (
            "<div><table><tr><td class=x>a<p>b</td>secret</tr></table>tail",
            "<div><table><tr>secret</tr></table>tail",
        ),
        ("<ul><li class=x>a<li>tail", "<ul><li>tail"),
        ("<h1 class=x>a<h2>tail</h2>", "<h2>tail</h2>"),
        (
            "<select><option class=x>a<option>tail</select>",
            "<select><option>tail</select>",
        ),
        ("<ruby class=x>a<rt>b</rt></ruby>tail", "tail"),
        (
            "<table><tr><td>a<td class=x>b</table>tail",
            "<table><tr><td>a</table>tail",
        ),
        // A form browsers take off the stack under open children stays
        // open here: more is removed, nothing leaks.
        ("<form class=x><div>a</form>b</div>tail", ""),
        // A head reopened for tags browsers still insert into it.
        (
            "<head class=x></head><script>evil</script><body>ok",
            "<body>ok",
        ),
        (
            "<template><tr class=x><td>secret</td></tr></template>tail",
            "<template></template>tail",
        ),
        // `search` and `dialog` do not stop the walks, as in Chromium.
        ("<ul><li class=x>a<search><li>b</ul>", "<ul><li>b</ul>"),
        ("<x-a class=x><search></x-a>b", "b"),
        ("<x-a class=x><dialog></x-a>b", "b"),
    ] {
        assert_rewrite(
            input.as_bytes(),
            ".x",
            Edit::Remove,
            ScopeMode::Browser,
            removed.as_bytes(),
        );
    }
}

/// The edits of an element closed by text land where browsers end it, after
/// leading whitespace, however the text is chunked.
#[test]
fn text_closes_head_and_column_group_at_the_first_non_whitespace_byte() {
    for (input, selector, expected) in [
        ("<head class=h>  x", "head", "<head class=h>  @@x"),
        (
            "<head class=h>\n\t\r x<p>",
            "head",
            "<head class=h>\n\t\r @@x<p>",
        ),
        (
            "<head class=h><title>t</title>  x",
            "head",
            "<head class=h><title>t</title>  @@x",
        ),
        (
            "<table><colgroup class=c> x",
            "colgroup",
            "<table><colgroup class=c> @@x",
        ),
        (
            "<table><colgroup class=c>  </table>",
            "colgroup",
            "<table><colgroup class=c>  @@</table>",
        ),
    ] {
        assert_rewrite(
            input.as_bytes(),
            selector,
            Edit::Append,
            ScopeMode::Browser,
            expected.as_bytes(),
        );
    }
}

/// Browsers strip a leading UTF-8 BOM before parsing: it must not count as
/// body text, however it is split across writes.
#[test]
fn leading_bom_is_not_document_content() {
    let doc = "\u{feff}<!DOCTYPE html><html><head></head><body class=b>x</body></html>";
    assert_rewrite(
        doc.as_bytes(),
        "body",
        Edit::Append,
        ScopeMode::Browser,
        "\u{feff}<!DOCTYPE html><html><head></head><body class=b>x@@</body></html>".as_bytes(),
    );
    assert_rewrite(
        doc.as_bytes(),
        "html, head",
        Edit::SetAttribute,
        ScopeMode::Browser,
        "\u{feff}<!DOCTYPE html><html data-hit=\"1\"><head data-hit=\"1\"></head><body class=b>x</body></html>".as_bytes(),
    );
    // The doctype after a BOM still decides no-quirks: a table closes the p.
    assert_rewrite(
        "\u{feff}<!DOCTYPE html><p class=x>a<table></table>b".as_bytes(),
        ".x",
        Edit::Remove,
        ScopeMode::Browser,
        "\u{feff}<!DOCTYPE html><table></table>b".as_bytes(),
    );
    // Only a whole BOM at the very start is stripped; anything else is text.
    for input in [
        &b"\xef\xbb"[..],
        b"\xef",
        b"\xef\xbbx<p class=x>y",
        b"\xef\xbb\xbf",
        b"x\xef\xbb\xbf<p class=x>y",
        b"",
    ] {
        assert_rewrite(input, "body", Edit::Append, ScopeMode::Browser, input);
    }
}

/// Late `<html>` / `<body>` tags (and a `<head>` for the head browsers
/// made) are matched as the element browsers merge them into, once.
#[test]
fn late_document_tags_are_matched_once() {
    for (input, selector, edit, expected) in [
        (
            "<html><head></head><noscript>n</noscript><body class=b>t</body></html>",
            "body.b",
            Edit::Append,
            "<html><head></head><noscript>n</noscript><body class=b>t@@</body></html>",
        ),
        (
            "x<body class=b>y",
            "body",
            Edit::Append,
            "x<body class=b>y@@",
        ),
        (
            "<body>x<body class=b>y",
            "body",
            Edit::Append,
            "<body>x<body class=b>y@@",
        ),
        (
            "<body>x<body class=b>y",
            "body",
            Edit::SetAttribute,
            "<body data-hit=\"1\">x<body class=b>y",
        ),
        (
            "<meta charset=utf-8><html lang=x><head><title>t</title></head>b",
            "html",
            Edit::SetAttribute,
            "<meta charset=utf-8><html lang=\"x\" data-hit=\"1\"><head><title>t</title></head>b",
        ),
        (
            "<meta><head class=h><title>t</title></head>x",
            "head",
            Edit::Append,
            "<meta><head class=h><title>t</title>@@</head>x",
        ),
        (
            "<head><head class=h>x",
            "head.h",
            Edit::Append,
            "<head><head class=h>x",
        ),
        // Content after the late tag is the merged element's: it goes.
        ("x<body class=b>y</body>z", "body", Edit::Remove, "x"),
        // Descendants see the merged attributes.
        (
            "x<body class=b><p>y</p>",
            "body.b p",
            Edit::Remove,
            "x<body class=b>",
        ),
        // Implied elements take part in ancestry and positions.
        (
            "<p>a</p><div>b</div>",
            "body > div:nth-child(2)",
            Edit::Remove,
            "<p>a</p>",
        ),
        (
            "<table><tr class=r><td>c</td></tr></table>",
            "tbody > tr.r",
            Edit::Remove,
            "<table></table>",
        ),
        (
            "<table><tr class=r><td>c</td></tr></table>",
            "table > tr",
            Edit::Remove,
            "<table><tr class=r><td>c</td></tr></table>",
        ),
        (
            "<head></head><script class=s>s</script><body>",
            "head > script.s",
            Edit::Remove,
            "<head></head><body>",
        ),
        (
            "<div><a></a><table><b class=f></b></table></div>",
            "b:nth-child(2)",
            Edit::Remove,
            "<div><a></a><table></table></div>",
        ),
        (
            "<div></p><b class=f></b></div>",
            "b:nth-child(2)",
            Edit::Remove,
            "<div></p></div>",
        ),
    ] {
        assert_rewrite(
            input.as_bytes(),
            selector,
            edit,
            ScopeMode::Browser,
            expected.as_bytes(),
        );
    }
}

/// A `</body>` / `</html>` inside removed content is swallowed with it.
#[test]
fn document_end_tags_inside_removed_content_are_swallowed() {
    for (input, selector, edit, expected) in [
        (
            "<body><div class=x>a</body>b</html>c",
            ".x",
            Edit::Remove,
            "<body>",
        ),
        (
            "<body><div class=x>a</body>b",
            ".x",
            Edit::Inner,
            "<body><div class=x>I",
        ),
        (
            "<body class=b>a</body>b",
            "body",
            Edit::Inner,
            "<body class=b>I</body>",
        ),
        (
            "<html><body><div class=x>a</body></html>",
            "body, .x",
            Edit::Append,
            // The div is still open at `</body>`: its own end is EOF.
            "<html><body><div class=x>a@@</body></html>@@",
        ),
    ] {
        assert_rewrite(
            input.as_bytes(),
            selector,
            edit,
            ScopeMode::Browser,
            expected.as_bytes(),
        );
    }
}

/// Selectors see attribute values the way browsers do: character references
/// decoded, and the values HTML compares case-insensitively folded.
#[test]
fn selectors_match_attribute_values_as_browsers_see_them() {
    for (selector, input, expected) in [
        (".ad", "<div class=&#97;d>x</div>t", "t"),
        (".ad", "<div class=\"a&#x64; b\">x</div>t", "t"),
        ("#ad", "<div id=a&#100;>x</div>t", "t"),
        (
            "a[href^=\"https:\"]",
            "<a href=\"&#104;ttps&colon;//x\">x</a>t",
            "t",
        ),
        (
            "a[href*=\"tracker.com\"]",
            "<a href=\"//tracker&period;com/\">x</a>t",
            "t",
        ),
        (
            "a[href*=\"tracker.com\"]",
            "<a href=\"//tracker&periodx;com/\">x</a>t",
            "<a href=\"//tracker&periodx;com/\">x</a>t",
        ),
        ("[data-x=\"a&b\"]", "<i data-x=\"a&amp;b\">x</i>t", "t"),
        ("[data-x=\"a&b\"]", "<i data-x=\"a&b\">x</i>t", "t"),
        (
            "script[type=\"text/javascript\"]",
            "<script type=TEXT/JavaScript>s</script>t",
            "t",
        ),
        ("a[target=_blank]", "<a target=_BLANK>x</a>t", "t"),
        (
            "a[target=_blank s]",
            "<a target=_BLANK>x</a>t",
            "<a target=_BLANK>x</a>t",
        ),
        ("[data-k=v]", "<i data-k=V>x</i>t", "<i data-k=V>x</i>t"),
    ] {
        assert_rewrite(
            input.as_bytes(),
            selector,
            Edit::Remove,
            ScopeMode::Browser,
            expected.as_bytes(),
        );
    }
}

#[test]
fn scope_mode_is_fixed_once_input_is_written() {
    let handlers = ElementContentHandlers::new().on("p".parse().unwrap(), |el| {
        el.remove();
        Ok(())
    });
    let mut rewriter = HtmlRewriter::from_handlers(handlers);
    rewriter.write(b"<p>secret<button>").unwrap();
    // Browser mode keeps the p open across the button; switching now is ignored.
    rewriter.set_scope_mode(ScopeMode::NearestMatch);
    rewriter.write(b"<div>still secret</div>").unwrap();
    rewriter.end().unwrap();
    assert_eq!(rewriter.take_output(), b"");
}

/// A text-mode element whose end tag is split across writes: the end tag
/// stays whole, so end-anchored edits land after it, as in a one-shot rewrite.
#[test]
fn text_mode_end_tags_split_across_writes_stay_whole() {
    let rewrite = |chunks: &[&[u8]], mode: ScopeMode| -> String {
        let handlers = ElementContentHandlers::new().on("div > *".parse().unwrap(), |el| {
            el.append("[A]");
            el.after("[B]");
            Ok(())
        });
        let mut rewriter = HtmlRewriter::from_handlers(handlers).with_scope_mode(mode);
        let mut out = Vec::new();
        for chunk in chunks {
            rewriter.write(chunk).unwrap();
            out.extend(rewriter.take_output());
        }
        rewriter.end().unwrap();
        out.extend(rewriter.take_output());
        String::from_utf8(out).unwrap()
    };
    for name in [
        "script", "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes", "noscript",
    ] {
        let upper = name.to_ascii_uppercase();
        for end in [
            format!("</{name} >"),
            format!("</{upper}\tx=\"a>b\">"),
            format!("</{name}/ >"),
        ] {
            let input = format!("<div><{name}>body</p>{end}tail</div>");
            let expected = format!("<div><{name}>body</p>[A]{end}[B]tail</div>");
            for mode in [ScopeMode::Browser, ScopeMode::NearestMatch] {
                assert_eq!(rewrite(&[input.as_bytes()], mode), expected, "{mode:?}");
                for split in 0..=input.len() {
                    let (a, b) = input.as_bytes().split_at(split);
                    assert_eq!(
                        rewrite(&[a, b], mode),
                        expected,
                        "{mode:?} split {split}: {input}"
                    );
                }
                let bytes: Vec<&[u8]> = input.as_bytes().chunks(1).collect();
                assert_eq!(rewrite(&bytes, mode), expected, "{mode:?} bytes: {input}");
            }
        }
    }
}

/// Per-type sibling positions where the parent is not the current node
/// (foster parenting), where the head is reopened, and past the counts a
/// frame keeps on the stack.
#[test]
fn nth_of_type_positions_follow_browser_parents() {
    for (input, selector, expected) in [
        (
            "<table><span>a</span><tr><td>x</td></tr><span>b</span></table><span>c</span>",
            "span:nth-of-type(2)",
            "<table><span>a</span><tr><td>x</td></tr><span data-hit=\"1\">b</span></table><span>c</span>",
        ),
        (
            "<table><span>a</span><tr><td>x</td></tr><span>b</span></table><span>c</span>",
            "span:nth-of-type(3)",
            "<table><span>a</span><tr><td>x</td></tr><span>b</span></table><span data-hit=\"1\">c</span>",
        ),
        (
            "<head><meta id=a><title>t</title></head><meta id=b><link><meta id=c><body>",
            "meta:nth-of-type(3)",
            "<head><meta id=a><title>t</title></head><meta id=b><link><meta id=\"c\" data-hit=\"1\"><body>",
        ),
        (
            "<div><a>1</a><b>2</b><c>3</c><d>4</d><e>5</e><f>6</f><g>7</g><h>8</h><i>9</i><j>10</j><i>11</i><a>12</a></div>",
            "i:nth-of-type(2), a:nth-of-type(2)",
            "<div><a>1</a><b>2</b><c>3</c><d>4</d><e>5</e><f>6</f><g>7</g><h>8</h><i>9</i><j>10</j><i data-hit=\"1\">11</i><a data-hit=\"1\">12</a></div>",
        ),
    ] {
        assert_rewrite(
            input.as_bytes(),
            selector,
            Edit::SetAttribute,
            ScopeMode::Browser,
            expected.as_bytes(),
        );
    }
}

/// The streaming matcher agrees with matching on the built element tree, for
/// every tree of up to five custom elements labelled `x-a` / `x-b`, under
/// combinator chains, sibling positions, classes and negations.
#[test]
fn streaming_matches_agree_with_the_element_tree() {
    let mut selectors: Vec<String> = vec!["x-a".into(), "x-b".into()];
    let mut frontier = selectors.clone();
    for _ in 2..=3 {
        frontier = frontier
            .iter()
            .flat_map(|prefix| {
                [" ", " > "].into_iter().flat_map(move |combinator| {
                    ["x-a", "x-b"].map(|name| format!("{prefix}{combinator}{name}"))
                })
            })
            .collect();
        selectors.extend_from_slice(&frontier);
    }
    selectors.extend(
        [
            ".c",
            ".c > x-b",
            "x-a .c",
            ".c x-a > .c",
            "x-a:nth-child(2)",
            "x-b:nth-child(odd)",
            "x-a:nth-of-type(2)",
            "x-b:nth-of-type(1) > x-a",
            "x-a > x-b:nth-of-type(2)",
            "x-a x-b:nth-last-child(1)",
            ":nth-child(3)",
            ":not(x-a)",
            "x-a :not(.c)",
            "x-a > *:nth-of-type(odd) x-b",
        ]
        .into_iter()
        .filter(|s| s.parse::<Selector>().is_ok())
        .map(String::from),
    );
    assert!(selectors.len() > 50);
    // Every tree on five nodes whose parents precede their children.
    let mut trees: Vec<Vec<usize>> = vec![vec![0]];
    for i in 1..5 {
        trees = trees
            .into_iter()
            .flat_map(|tree| {
                (0..i).map(move |parent| {
                    let mut tree = tree.clone();
                    tree.push(parent);
                    tree
                })
            })
            .collect();
    }
    for parents in &trees {
        for labels in 0u32..(1 << parents.len()) {
            let name = |i: usize| if labels & (1 << i) == 0 { "x-a" } else { "x-b" };
            let mut dom = Dom::new();
            let mut ids: Vec<NodeId> = Vec::new();
            for (i, &parent) in parents.iter().enumerate() {
                let id = if i == 0 {
                    dom.create(name(i))
                } else {
                    dom.append(ids[parent], name(i))
                };
                if i.is_multiple_of(2) {
                    dom.set_attr(id, "class", "c");
                }
                ids.push(id);
            }
            fn write(
                node: usize,
                parents: &[usize],
                name: &dyn Fn(usize) -> &'static str,
                out: &mut String,
            ) {
                let class = if node.is_multiple_of(2) {
                    " class=c"
                } else {
                    ""
                };
                out.push_str(&format!("<{} id={node}{class}>", name(node)));
                for child in (1..parents.len()).filter(|&c| parents[c] == node) {
                    write(child, parents, name, out);
                }
                out.push_str(&format!("</{}>", name(node)));
            }
            let mut html = String::new();
            write(0, parents, &name, &mut html);
            for selector in &selectors {
                let parsed: Selector = selector.parse().unwrap();
                let expected: Vec<usize> = (0..parents.len())
                    .filter(|&i| parsed.matches(&dom.element(ids[i])))
                    .collect();
                for mode in [ScopeMode::Browser, ScopeMode::NearestMatch] {
                    let out = rewrite_chunks([html.as_bytes()], selector, Edit::SetAttribute, mode);
                    let out = String::from_utf8(out).unwrap();
                    let got: Vec<usize> = (0..parents.len())
                        .filter(|i| out.contains(&format!("id=\"{i}\"")))
                        .collect();
                    assert_eq!(got, expected, "`{selector}` {mode:?} in {html}");
                }
            }
        }
    }
}

// --- property tests ---------------------------------------------------------

/// A structured token soup: scope transitions, foreign content, text modes,
/// table and template modes, late document tags and doctypes.
fn token_soup(tokens: Vec<u8>) -> String {
    const TOKENS: &[&str] = &[
        "<p>",
        "<p class=x>",
        "</p>",
        "<div>",
        "<div class=x>",
        "</div>",
        "<span>",
        "</span>",
        "<button>",
        "</button>",
        "<ul>",
        "<li class=x>",
        "</li>",
        "<li>",
        "<dl>",
        "<dt>",
        "<dd>",
        "<table>",
        "<table class=x>",
        "</table>",
        "<tr>",
        "<tr class=x>",
        "</tr>",
        "<td>",
        "<td class=x>",
        "</td>",
        "<col>",
        "<colgroup>",
        "<caption>",
        "<template>",
        "</template>",
        "<svg>",
        "<svg/>",
        "</svg>",
        "<math>",
        "<math/>",
        "</math>",
        "<foreignObject>",
        "<desc>",
        "<title>",
        "</title>",
        "<mi>",
        "<annotation-xml encoding=text/html>",
        "<style>",
        "</style>",
        "<style class=x>",
        "</style x='>'>",
        "<textarea>",
        "</textarea>",
        "<xmp>",
        "<script>",
        "</script>",
        "<script class=x>",
        "</script >",
        "<title class=x>",
        "</TITLE\t/>",
        "<select>",
        "<option class=x>",
        "</select>",
        "<h1 class=x>",
        "<h2>",
        "<ruby class=x>",
        "<rt>",
        "<form class=x>",
        "</form>",
        "<head class=x>",
        "</head>",
        "<body class=x>",
        "</body>",
        "<html class=x>",
        "</html>",
        "<!DOCTYPE html>",
        "<![CDATA[x]]>",
        "<!--c-->",
        "<b>",
        "</b>",
        "<br>",
        "</br>",
        "<input type=hidden>",
        "  ",
        "~",
        "text",
    ];
    tokens
        .into_iter()
        .take(256)
        .map(|byte| TOKENS[usize::from(byte) % TOKENS.len()])
        .collect()
}

fn kept_text(out: &[u8]) -> usize {
    out.iter().filter(|&&b| b == b'~').count()
}

/// Remove, inner content and replace suppress the same content; every split
/// rewrites the same; the tree's caches stay consistent (and its text-mode
/// prediction matches tree construction, asserted on every start tag).
#[quickcheck]
fn rewrites_are_consistent_and_split_invariant(
    tokens: Vec<u8>,
    split: usize,
    nearest: bool,
) -> bool {
    let input = token_soup(tokens);
    let bytes = input.as_bytes();
    let mode = if nearest {
        ScopeMode::NearestMatch
    } else {
        ScopeMode::Browser
    };
    let split = split % (bytes.len() + 1);
    let (a, b) = bytes.split_at(split);
    for edit in [Edit::Remove, Edit::Inner, Edit::Append, Edit::Replace] {
        let one = rewrite_chunks([bytes], ".x", edit, mode);
        assert_eq!(
            one,
            rewrite_chunks([a, b], ".x", edit, mode),
            "{edit:?} split {split}: {input}"
        );
    }
    let removed = kept_text(&rewrite_chunks([bytes], ".x", Edit::Remove, mode));
    assert_eq!(
        removed,
        kept_text(&rewrite_chunks([bytes], ".x", Edit::Inner, mode)),
        "{input}"
    );
    assert_eq!(
        removed,
        kept_text(&rewrite_chunks([bytes], ".x", Edit::Replace, mode)),
        "{input}"
    );
    assert_eq!(rewrite_chunks([bytes], "x-none", Edit::Remove, mode), bytes);
    if !nearest {
        run_with(&["div > p", ".x td"], bytes, true);
    }
    true
}

/// Per-type counts agree with a plain map per frame (asserted on every
/// count), with the stack caches checked after every token.
#[quickcheck]
fn nth_of_type_counts_agree_with_a_reference_model(tokens: Vec<u8>, nearest: bool) -> bool {
    let input = token_soup(tokens);
    let bytes = input.as_bytes();
    run(
        &[
            "span:nth-of-type(2)",
            "td:nth-of-type(odd) p",
            "li:nth-of-type(3) > *",
        ],
        bytes,
    );
    let mode = if nearest {
        ScopeMode::NearestMatch
    } else {
        ScopeMode::Browser
    };
    rewrite_chunks(
        [bytes],
        "b:nth-of-type(2), .x:nth-of-type(3)",
        Edit::Remove,
        mode,
    );
    true
}

/// Brackets each matched element: `\x01` before it, `\x03` after it, and
/// the edit in between (`\x02` stands for inserted content).
fn bracketed(input: &[u8], selector: &str, edit: Edit, mode: ScopeMode, split: usize) -> Vec<u8> {
    let handlers = ElementContentHandlers::new().on(selector.parse().unwrap(), move |el| {
        el.before("\u{1}");
        match edit {
            Edit::Remove => el.remove(),
            Edit::Replace => el.replace("\u{2}"),
            Edit::Inner => el.set_inner_content("\u{2}"),
            Edit::Append | Edit::SetAttribute => el.append("\u{2}"),
        }
        el.after("\u{3}");
        Ok(())
    });
    let mut rewriter = HtmlRewriter::from_handlers(handlers).with_scope_mode(mode);
    let (a, b) = input.split_at(split % (input.len() + 1));
    rewriter.write(a).unwrap();
    rewriter.write(b).unwrap();
    rewriter.end().unwrap();
    rewriter.take_output()
}

/// Drops everything inside the outermost `\x01`…`\x03` brackets.
fn collapse_brackets(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    for &b in bytes {
        match b {
            1 => {
                if depth == 0 {
                    out.push(1);
                }
                depth += 1;
            }
            3 => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    out.push(3);
                }
            }
            _ if depth == 0 => out.push(b),
            _ => {}
        }
    }
    out
}

/// `remove` swallows exactly the extent the end-anchored edits see: the
/// element's start tag, everything up to its end, and its end tag.
/// (`html`, `head` and `body` keep content after their end anchors, so they
/// are left out.)
#[quickcheck]
fn removal_spans_exactly_the_anchored_extent(
    tokens: Vec<u8>,
    split: usize,
    nearest: bool,
    pick: u8,
) -> bool {
    let input = token_soup(tokens);
    let mode = if nearest {
        ScopeMode::NearestMatch
    } else {
        ScopeMode::Browser
    };
    let selector = [
        ".x:not(html):not(head):not(body)",
        "div",
        "p",
        "td, th, tr",
        "li",
        "svg, math",
        "template",
        "select, option",
        "table",
        "title, style, textarea",
    ][usize::from(pick) % 10];
    assert_bracketed_extent(input.as_bytes(), selector, mode, split);
    true
}

/// `remove` output equals every other edit's output with the bracketed
/// elements collapsed.
fn assert_bracketed_extent(input: &[u8], selector: &str, mode: ScopeMode, split: usize) {
    let removed = bracketed(input, selector, Edit::Remove, mode, split);
    for edit in [Edit::Append, Edit::Replace, Edit::Inner] {
        let other = bracketed(input, selector, edit, mode, split);
        assert_eq!(
            String::from_utf8_lossy(&removed),
            String::from_utf8_lossy(&collapse_brackets(&other)),
            "{selector} {edit:?} in {mode:?}: {}",
            String::from_utf8_lossy(input)
        );
    }
}

/// Pinned fuzz input: a tag cut off by the end of input (browsers drop it;
/// here it is an element without content) brackets consistently.
#[test]
fn unterminated_tag_at_eof_brackets_consistently() {
    let input = b"<y\x00b\xff~]\xff\xfcu\xff\xff\xffG\x00";
    for mode in [ScopeMode::Browser, ScopeMode::NearestMatch] {
        for split in 0..=input.len() {
            assert_bracketed_extent(input, "*", mode, split);
        }
    }
}
