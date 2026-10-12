//! Streaming HTML rewriter throughput: realistic pages (generated in code)
//! with typical selector/action sets, plus adversarial inputs that must stay
//! linear in their size.

#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use std::fmt::Write as _;
use std::sync::OnceLock;

use divan::{Bencher, black_box, counter::BytesCount};
use rama::http::protocols::html::rewrite::{
    AttributeName, ElementContentHandlers, HtmlRewriter, ScopeMode,
};
use rama::http::protocols::html::selector::Selector;
use rama::http::protocols::html::tokenizer::{TokenSink, tokenize};

mod bench_alloc;

fn main() {
    divan::main();
}

/// Streaming chunk size used by the `chunked` variants (a typical body frame).
const CHUNK: usize = 16 * 1024;

/// Nesting depth / repetition count for the adversarial inputs.
const N: usize = 50_000;

fn sel(s: &str) -> Selector {
    s.parse().unwrap()
}

// --- realistic documents --------------------------------------------------

/// A blog/article page: head assets, nav lists, articles with inline
/// formatting, figures, code blocks and asides, some optional end tags left
/// out the way real-world markup does.
fn article_page() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s = String::from(
            "<!DOCTYPE html>\n<html lang=en><head><meta charset=utf-8>\
             <title>Blog</title><link rel=stylesheet href=/site.css>\
             <script src=\"https://cdn.example/analytics.js\" async></script>\
             <script src=\"/tracker.js\"></script></head>\n<body class=page>\
             <header><nav><ul>",
        );
        for i in 0..12 {
            write!(s, "<li><a href=\"/section/{i}\">Section {i}</a>").unwrap();
        }
        s.push_str("</ul></nav></header><main>");
        for a in 0..120 {
            write!(
                s,
                "<article id=post-{a} class=post><h2><a href=\"/post/{a}\">Post \
                 title {a}</a></h2><p class=meta>By <em>author</em> on \
                 <time datetime=2026-01-01>Jan 1</time>"
            )
            .unwrap();
            for p in 0..6 {
                writeln!(
                    s,
                    "<p>Paragraph {p} with <strong>bold</strong>, <em>emphasis</em>, \
                     <code>inline_code()</code> and a <a href=\"https://example.com/{a}/{p}\">\
                     link</a>. Lorem ipsum dolor sit amet, consectetur adipiscing elit."
                )
                .unwrap();
            }
            writeln!(
                s,
                "<figure><img src=\"/img/{a}.png\" alt=\"figure {a}\"><figcaption>Figure \
                 {a}</figcaption></figure><blockquote><p>Quoted text</blockquote>\
                 <pre><code>fn main() {{ println!(\"{a}\"); }}</code></pre>\
                 <div class=\"ad banner\"><a href=\"https://ads.example/{a}\"><img \
                 src=\"/ads/{a}.gif\"></a></div><ul class=tags><li>rust<li>html<li>\
                 streaming</ul></article>"
            )
            .unwrap();
        }
        s.push_str(
            "</main><aside><h3>Related</h3><ol><li>One<li>Two<li>Three</ol></aside>\
             <footer><p>&copy; 2026</footer></body></html>\n",
        );
        s.into_bytes()
    })
}

/// A table-heavy page: data tables with thead/tbody, cells whose end tags are
/// omitted, and a nested table per row group.
fn table_page() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s = String::from("<!DOCTYPE html><html><body><h1>Report</h1>");
        for t in 0..40 {
            write!(
                s,
                "<table class=data id=t{t}><caption>Table {t}</caption><thead><tr>\
                 <th>Name<th>Price<th>Qty<th>Notes</thead><tbody>"
            )
            .unwrap();
            for r in 0..60 {
                write!(
                    s,
                    "<tr><td>Item {r}<td class=price>{r}.99<td>{r}<td><span \
                     class=note>note</span>"
                )
                .unwrap();
                if r % 20 == 0 {
                    s.push_str("<table><tr><td>inner<td><b>nested</b></table>");
                }
            }
            s.push_str("</tbody></table>\n");
        }
        s.push_str("</body></html>");
        s.into_bytes()
    })
}

/// A script/style-heavy page: raw-text bodies dominate the bytes.
fn script_page() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s = String::from("<!DOCTYPE html><html><head>");
        for i in 0..80 {
            write!(
                s,
                "<style>.c{i} {{ color: red; }} .c{i} > a:hover {{ color: blue; }} \
                 @media (max-width: 600px) {{ .c{i} {{ display: none; }} }}</style>\
                 <script>var cfg{i} = {{\"a\": \"<div>\", \"b\": [1, 2, 3], \"c\": \
                 \"</p>\"}}; if (a < b && c > d) {{ document.write(\"<b>\"); }}</script>"
            )
            .unwrap();
        }
        s.push_str("</head><body>");
        for i in 0..200 {
            write!(
                s,
                "<div class=c{i}><script type=application/ld+json>{{\"@type\": \
                 \"Thing\", \"name\": \"x{i}\"}}</script><p>text {i}</p>\
                 <script src=\"https://tracker.example/t{i}.js\"></script></div>"
            )
            .unwrap();
        }
        s.push_str("</body></html>");
        s.into_bytes()
    })
}

/// An icon-heavy page: inline SVG sprites and MathML, foreign content the
/// tree tracks namespace by namespace, plus style blocks inside SVG.
fn foreign_page() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s = String::from("<!DOCTYPE html><html><head><title>Icons</title></head><body>");
        for i in 0..300 {
            write!(
                s,
                "<div class=card><svg viewBox=\"0 0 24 24\" class=icon><style>.a{{fill:red}}</style>\
                 <g><path d=\"M{i} 0L24 24\"/><circle cx=12 cy=12 r=4></circle></g>\
                 <foreignObject><p>label {i}</p></foreignObject><desc>icon {i}</desc></svg>\
                 <math><mi>x</mi><mo>=</mo><mn>{i}</mn></math><p>caption {i}</div>"
            )
            .unwrap();
        }
        s.push_str("</body></html>");
        s.into_bytes()
    })
}

/// A component page: `<template>` blocks holding table rows and cells,
/// lists whose items rely on `:nth-of-type` styling, implied table parts.
fn template_page() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s =
            String::from("<!DOCTYPE html><html><head><title>Components</title></head><body>");
        for i in 0..150 {
            write!(
                s,
                "<template id=row{i}><tr><td class=name>n<td class=price>{i}</tr></template>\
                 <template id=cell{i}><td>cell</td></template>\
                 <table><tr><td>a<td>b</table><ul class=list>"
            )
            .unwrap();
            for j in 0..8 {
                write!(s, "<li><span>item {j}</span><em>e</em><span>more</span>").unwrap();
            }
            s.push_str("</ul>");
        }
        s.push_str("</body></html>");
        s.into_bytes()
    })
}

// --- adversarial documents ------------------------------------------------

/// `<p><button>` then N nested spans then N p-closing `<div>`s: every div
/// asks "is a p in button scope?" against a deep stack.
fn adv_button_scope() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s = String::from("<p><button>");
        s.push_str(&"<span>".repeat(N));
        s.push_str(&"<div>".repeat(N));
        s.into_bytes()
    })
}

/// N stray end tags for an element hidden behind a scope boundary.
fn adv_stray_behind_boundary() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s = String::from("<div><span><table><tr><td>");
        s.push_str(&"<em>".repeat(N));
        s.push_str(&"</div></span>".repeat(N));
        s.into_bytes()
    })
}

/// N nested tables, each with an open cell, then N stray cell end tags.
fn adv_deep_tables() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s = "<table><tr><td>".repeat(N);
        s.push_str(&"<td>x".repeat(N));
        s.into_bytes()
    })
}

/// `</span>` storms behind special elements.
fn adv_span_storm() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s = String::from("<span>");
        s.push_str(&"<div>".repeat(N));
        s.push_str(&"</span><li>".repeat(N));
        s.into_bytes()
    })
}

/// Foreign content entered and left over and over, with raw-text tags
/// whose meaning depends on the namespace.
fn adv_foreign_breakout() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s = "<math><svg>".repeat(N / 2);
        s.push_str(&"<style>x</style><b><svg><desc><style>y</style></desc>".repeat(N / 2));
        s.into_bytes()
    })
}

/// Late document tags merged into the open root and body, and tagless
/// elements created by end tags.
fn adv_late_document_tags() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s = "<div>".repeat(N);
        s.push_str(&"<body class=b><html lang=x></p></br><head>".repeat(N));
        s.into_bytes()
    })
}

/// Deep list nesting with implied `<li>` closes at every level.
fn adv_nested_lists() -> &'static [u8] {
    static DOC: OnceLock<Vec<u8>> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut s = "<ul><li>a".repeat(N);
        s.push_str(&"<li>b".repeat(N));
        s.into_bytes()
    })
}

// --- handlers -------------------------------------------------------------

/// A typical privacy/ads rewrite: tag outbound links, drop trackers and ad
/// blocks, lazy-load images, inject into the body.
fn typical_handlers() -> ElementContentHandlers<'static> {
    ElementContentHandlers::new()
        .on(sel("a[href^=\"https://\"]"), |el| {
            el.set_attribute(AttributeName::from_static("rel"), "noopener");
            Ok(())
        })
        .on(sel("script[src*=\"tracker\"]"), |el| {
            el.remove();
            Ok(())
        })
        .on(sel(".ad"), |el| {
            el.remove();
            Ok(())
        })
        .on(sel("img"), |el| {
            el.set_attribute(AttributeName::from_static("loading"), "lazy");
            Ok(())
        })
        .on(sel("td.price"), |el| {
            el.append("$");
            Ok(())
        })
        .on(sel("body"), |el| {
            el.append("<!-- injected -->");
            Ok(())
        })
}

/// Structural selectors: per-type counting and descendant chains that
/// cross foreign content and templates.
fn structural_handlers() -> ElementContentHandlers<'static> {
    ElementContentHandlers::new()
        .on(sel("li:nth-of-type(2n) > span:nth-of-type(2)"), |el| {
            el.set_attribute(AttributeName::from_static("data-even"), "1");
            Ok(())
        })
        .on(sel("svg desc, math mi"), |el| {
            el.remove();
            Ok(())
        })
        .on(sel("template td.price, tbody > tr td:nth-child(2)"), |el| {
            el.append("$");
            Ok(())
        })
        .on(sel(".card p"), |el| {
            el.set_inner_content("caption");
            Ok(())
        })
}

/// A selector that matches nothing in these documents: measures the
/// tokenizer + open-element bookkeeping on its own.
fn idle_handlers() -> ElementContentHandlers<'static> {
    ElementContentHandlers::new().on(sel("x-never-present"), |_| Ok(()))
}

fn rewrite(
    doc: &[u8],
    handlers: ElementContentHandlers<'_>,
    chunk: usize,
    mode: ScopeMode,
) -> usize {
    let mut rewriter = HtmlRewriter::from_handlers(handlers).with_scope_mode(mode);
    let mut total = 0;
    for part in doc.chunks(chunk) {
        rewriter.write(part).unwrap();
        total += rewriter.take_output().len();
    }
    rewriter.end().unwrap();
    total + rewriter.take_output().len()
}

/// Which handler set a bench runs.
#[derive(Clone, Copy)]
enum Handlers {
    Typical,
    Structural,
    Idle,
}

fn run(
    bencher: Bencher<'_, '_>,
    doc: &'static [u8],
    handlers: Handlers,
    chunk: usize,
    mode: ScopeMode,
) {
    bencher
        .counter(BytesCount::of_slice(doc))
        .with_inputs(|| match handlers {
            Handlers::Typical => typical_handlers(),
            Handlers::Structural => structural_handlers(),
            Handlers::Idle => idle_handlers(),
        })
        .bench_values(|handlers| black_box(rewrite(black_box(doc), handlers, chunk, mode)));
}

fn page_doc(page: &str) -> &'static [u8] {
    match page {
        "article" => article_page(),
        "table" => table_page(),
        "foreign" => foreign_page(),
        "template" => template_page(),
        _ => script_page(),
    }
}

fn adversarial_doc(input: &str) -> &'static [u8] {
    match input {
        "button_scope" => adv_button_scope(),
        "stray_behind_boundary" => adv_stray_behind_boundary(),
        "deep_tables" => adv_deep_tables(),
        "span_storm" => adv_span_storm(),
        "foreign_breakout" => adv_foreign_breakout(),
        "late_document_tags" => adv_late_document_tags(),
        _ => adv_nested_lists(),
    }
}

#[divan::bench_group]
mod realistic {
    use super::*;

    const PAGES: &[&str] = &["article", "table", "script", "foreign", "template"];

    #[divan::bench(args = PAGES)]
    fn typical(bencher: Bencher<'_, '_>, page: &str) {
        run(
            bencher,
            page_doc(page),
            Handlers::Typical,
            usize::MAX,
            ScopeMode::Browser,
        );
    }

    #[divan::bench(args = PAGES)]
    fn typical_nearest(bencher: Bencher<'_, '_>, page: &str) {
        run(
            bencher,
            page_doc(page),
            Handlers::Typical,
            usize::MAX,
            ScopeMode::NearestMatch,
        );
    }

    #[divan::bench(args = PAGES)]
    fn typical_chunked(bencher: Bencher<'_, '_>, page: &str) {
        run(
            bencher,
            page_doc(page),
            Handlers::Typical,
            CHUNK,
            ScopeMode::Browser,
        );
    }

    #[divan::bench(args = PAGES)]
    fn structural(bencher: Bencher<'_, '_>, page: &str) {
        run(
            bencher,
            page_doc(page),
            Handlers::Structural,
            usize::MAX,
            ScopeMode::Browser,
        );
    }

    #[divan::bench(args = PAGES)]
    fn idle(bencher: Bencher<'_, '_>, page: &str) {
        run(
            bencher,
            page_doc(page),
            Handlers::Idle,
            usize::MAX,
            ScopeMode::Browser,
        );
    }

    #[divan::bench(args = PAGES)]
    fn idle_nearest(bencher: Bencher<'_, '_>, page: &str) {
        run(
            bencher,
            page_doc(page),
            Handlers::Idle,
            usize::MAX,
            ScopeMode::NearestMatch,
        );
    }
}

#[divan::bench_group]
mod adversarial {
    use super::*;

    const INPUTS: &[&str] = &[
        "button_scope",
        "stray_behind_boundary",
        "deep_tables",
        "span_storm",
        "nested_lists",
        "foreign_breakout",
        "late_document_tags",
    ];

    #[divan::bench(args = INPUTS)]
    fn typical(bencher: Bencher<'_, '_>, input: &str) {
        run(
            bencher,
            adversarial_doc(input),
            Handlers::Typical,
            usize::MAX,
            ScopeMode::Browser,
        );
    }

    #[divan::bench(args = INPUTS)]
    fn typical_nearest(bencher: Bencher<'_, '_>, input: &str) {
        run(
            bencher,
            adversarial_doc(input),
            Handlers::Typical,
            usize::MAX,
            ScopeMode::NearestMatch,
        );
    }
}

/// The tokenizer alone (a sink that ignores every token), separating its
/// cost from tree construction and selector matching.
#[divan::bench_group]
mod tokenizer_only {
    use super::*;

    struct Ignore;

    impl TokenSink for Ignore {}

    const PAGES: &[&str] = &["article", "table", "script", "foreign", "template"];

    #[divan::bench(args = PAGES)]
    fn tokenize_only(bencher: Bencher<'_, '_>, page: &str) {
        let doc = page_doc(page);
        bencher
            .counter(BytesCount::of_slice(doc))
            .bench(|| tokenize(black_box(doc), &mut Ignore).unwrap());
    }
}
