//! Fuzz target for the [`rama_http::protocols::html::rewrite`] rewriter.
//!
//! Properties checked on arbitrary input and on a structured token soup, in
//! both scope modes:
//!
//!   1. **Passthrough identity** — with no handlers registered, the rewriter
//!      reproduces the input byte-for-byte.
//!   2. **Chunk-split stability** — rewriting in one `write`, in two `write`s
//!      and byte by byte yields identical output.
//!   3. **Suppression consistency** — `remove`, `replace` and
//!      `set_inner_content` swallow the same content.
//!   4. **No leak past the anchored extent** — what they swallow is exactly
//!      the span the `before`/`append`/`after` edits bracket.
//!   5. **Internal invariants** — built with `--cfg fuzzing`, the rewriter
//!      recounts its stack caches and edit bookkeeping after every tree
//!      change, and asserts the tokenizer's raw-text decision for every start
//!      tag matches what tree construction then does.
//!   6. **No panic** — arbitrary selectors and element mutations never panic.
//!
//! Run with:
//!     cargo +nightly fuzz run html_rewrite
#![no_main]
#![expect(
    clippy::unwrap_used,
    reason = "fuzzing: unexpected rewrite errors must fail the property"
)]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use rama::http::protocols::html::rewrite::{
    AttributeName, Element, ElementContentHandlers, HtmlRewriter, ScopeMode,
};
use rama::http::protocols::html::selector::Selector;

#[derive(Arbitrary, Debug)]
struct Input {
    html: Vec<u8>,
    selector: u8,
    op: u8,
    split: usize,
    nearest: bool,
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
    "head",
    "html",
    "ul li",
    "td",
    "p div",
    "table td table td",
    "li li",
    "dt",
    "button",
    "template",
    "svg",
    ".x",
    "tbody > tr",
    "body > div",
    "title, style, textarea",
    "select option",
    "math *",
    "colgroup",
    "td:nth-of-type(2)",
    "[type=hidden]",
    "li:nth-of-type(2) span",
    "span:nth-of-type(odd) > b",
    "script, style",
];

/// Selectors that never match `html`, `head` or `body`: those keep content
/// after their end anchors, which the extent check does not model.
const EXTENT_SELECTORS: &[&str] = &[
    ".x:not(html):not(head):not(body)",
    "div",
    "p",
    "td, th, tr",
    "li",
    "svg, math",
    "template",
    "select, option",
    "table",
    "title, style, textarea, xmp",
    "span, b",
    "script, style:nth-of-type(2)",
];

/// Structured tokens make scope transitions, foreign content, text modes and
/// document-level rules common even before a corpus develops.
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
    "</dt>",
    "<dd>",
    "<table>",
    "<table class=x>",
    "</table>",
    "<tr>",
    "</tr>",
    "<td>",
    "<td class=x>",
    "</td>",
    "<th>",
    "<tbody>",
    "</tbody>",
    "<col>",
    "<colgroup>",
    "</colgroup>",
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
    "</foreignObject>",
    "<desc>",
    "<title>",
    "</title>",
    "<mi>",
    "</mi>",
    "<annotation-xml encoding=text/html>",
    "<annotation-xml encoding=text&sol;html>",
    "</annotation-xml>",
    "<style>",
    "</style>",
    "<style class=x>",
    "</style x='>'>",
    "<textarea>",
    "</textarea>",
    "<xmp>",
    "</xmp>",
    "<script>",
    "</script>",
    "<script class=x>",
    "</script >",
    "</TITLE\t/>",
    "<noscript>",
    "<plaintext>",
    "<select>",
    "<option class=x>",
    "</select>",
    "<h1 class=x>",
    "<h2>",
    "</h1>",
    "<ruby>",
    "<rt>",
    "<form class=x>",
    "</form>",
    "<head>",
    "<head class=x>",
    "</head>",
    "<body>",
    "<body class=x>",
    "</body>",
    "<html>",
    "<html class=x>",
    "</html>",
    "<!DOCTYPE html>",
    "<!DOCTYPE html PUBLIC \"\" \"\">",
    "\u{feff}",
    "<![CDATA[",
    "]]>",
    "<!--",
    "-->",
    "<b>",
    "</b>",
    "<a>",
    "</a>",
    "<br>",
    "</br>",
    "<input type=hidden>",
    "<meta>",
    "<link>",
    "<frameset>",
    "<font color=red>",
    " ",
    "\n",
    "text",
    "<",
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

/// Rewrites `html` fed as `chunks`.
fn rewrite<'a>(
    chunks: impl IntoIterator<Item = &'a [u8]>,
    handlers: ElementContentHandlers<'_>,
    mode: ScopeMode,
) -> Vec<u8> {
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

fn op_handlers(selector: &Selector, op: u8) -> ElementContentHandlers<'static> {
    ElementContentHandlers::new().on(selector.clone(), move |el| {
        apply_op(el, op);
        Ok(())
    })
}

/// The edit applied between the brackets of [`bracket_handlers`].
#[derive(Clone, Copy)]
enum Bracketed {
    Append,
    Remove,
    Replace,
    Inner,
}

/// Brackets each matched element: `\x01` before it, `\x03` after it, and
/// `\x02` appended (or the element removed / replaced / emptied).
fn bracket_handlers(selector: &Selector, edit: Bracketed) -> ElementContentHandlers<'static> {
    ElementContentHandlers::new().on(selector.clone(), move |el| {
        el.before("\u{1}");
        match edit {
            Bracketed::Append => el.append("\u{2}"),
            Bracketed::Remove => el.remove(),
            Bracketed::Replace => el.replace("\u{2}"),
            Bracketed::Inner => el.set_inner_content("\u{2}"),
        }
        el.after("\u{3}");
        Ok(())
    })
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

fuzz_target!(|input: Input| {
    let raw = input.html.as_slice();
    let structured: String = raw
        .iter()
        .copied()
        .take(512)
        .map(|byte| TOKENS[usize::from(byte) % TOKENS.len()])
        .collect();
    let mode = if input.nearest {
        ScopeMode::NearestMatch
    } else {
        ScopeMode::Browser
    };

    for html in [raw, structured.as_bytes()] {
        // 1. No handlers => byte-identical passthrough, in both modes.
        for mode in [ScopeMode::Browser, ScopeMode::NearestMatch] {
            assert_eq!(
                rewrite([html], ElementContentHandlers::new(), mode),
                html,
                "no-handler rewrite changed the input in {mode:?}"
            );
        }

        let source = SELECTORS[usize::from(input.selector) % SELECTORS.len()];
        let selector: Selector = source.parse().unwrap();
        let at = input.split % html.len().saturating_add(1);
        let (a, b) = html.split_at(at);

        // 2 + 6. Chunk-split stability (and no panic) with a mutating handler.
        let one_shot = rewrite([html], op_handlers(&selector, input.op), mode);
        assert_eq!(
            one_shot,
            rewrite([a, b], op_handlers(&selector, input.op), mode),
            "chunk split changed the rewrite for {source:?} in {mode:?}",
        );
        if html.len() <= 2048 {
            assert_eq!(
                one_shot,
                rewrite(html.chunks(1), op_handlers(&selector, input.op), mode),
                "byte-by-byte writes changed the rewrite for {source:?} in {mode:?}",
            );
        }

        // 3 + 4. Remove, replace and inner content swallow exactly the extent
        // the bracketing edits see.
        let control = |b: u8| if matches!(b, 1..=3) { b'x' } else { b };
        let clean: Vec<u8> = html.iter().copied().map(control).collect();
        let source = EXTENT_SELECTORS[usize::from(input.op) % EXTENT_SELECTORS.len()];
        let selector: Selector = source.parse().unwrap();
        let (a, b) = clean.split_at(at.min(clean.len()));
        let removed = rewrite([a, b], bracket_handlers(&selector, Bracketed::Remove), mode);
        for edit in [Bracketed::Append, Bracketed::Replace, Bracketed::Inner] {
            let bracketed = rewrite([a, b], bracket_handlers(&selector, edit), mode);
            assert_eq!(
                removed,
                collapse_brackets(&bracketed),
                "removal and bracketed extent disagree for {source:?} in {mode:?}"
            );
        }
    }
});
