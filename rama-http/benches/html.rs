#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "benchmark fixtures fail fast"
)]
#![deny(warnings)]

use divan::{Bencher, black_box};
use rama_http::protocols::html::{
    rewrite::{AttributeName, ElementContentHandlers, HtmlRewriter},
    tokenizer::{TokenSink, Tokenizer},
};

fn main() {
    divan::main();
}

const INPUTS: &[&str] = &[
    "attrs_2k",
    "attrs_16k",
    "quoted_attrs_4k",
    "page",
    "script",
    "textarea",
];

fn input(name: &str) -> Vec<u8> {
    match name {
        "attrs_2k" => format!("<div{}>body</div>", " a".repeat(2_048)).into_bytes(),
        "attrs_16k" => format!("<div{}>body</div>", " a".repeat(16_384)).into_bytes(),
        "quoted_attrs_4k" => {
            format!("<div{}>body</div>", " data-x=\"a > b\"".repeat(4_096)).into_bytes()
        }
        "page" => page(),
        "script" => format!(
            "<script>{}</script>",
            "if (a < b) { c(\"<p>\"); }\n".repeat(4_096)
        )
        .into_bytes(),
        "textarea" => {
            format!("<textarea>{}</textarea>", "a < b &amp; <c>\n".repeat(8_192)).into_bytes()
        }
        _ => panic!("unknown input {name}"),
    }
}

/// About 300 KB of typical markup: short tags with a few attributes, inline
/// script and style, comments and entities.
fn page() -> Vec<u8> {
    let mut page = String::from(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Bench &amp; page</title>\
         <style>.item { color: red; } a > b { margin: 0 }</style>\
         <script>window.dataLayer = window.dataLayer || []; if (a < b) {}</script>\
         </head><body>",
    );
    for i in 0..1_500 {
        page.push_str(&format!(
            "<!-- item {i} --><div class=\"item card\" id=\"item-{i}\" data-index={i}>\
             <h2 class=title><a href=\"/items/{i}?ref=list&amp;page=2\" title='Item {i}'>Item {i}</a></h2>\
             <p>Some <b>bold</b> &amp; <i>italic</i> text &lt;here&gt; with &nbsp; entities.</p>\
             <img src=\"/img/{i}.png\" alt=\"\" loading=lazy width=64 height=64>\
             <ul><li>one</li><li>two</li><li>three</li></ul><br/></div>"
        ));
    }
    page.push_str("<script>console.log('done')</script></body></html>");
    page.into_bytes()
}

struct Sink;

impl TokenSink for Sink {}

/// Splits `input` into writes of `size` bytes, or one write when `size` is 0.
fn writes(input: &[u8], size: usize) -> impl Iterator<Item = &[u8]> {
    input.chunks(if size == 0 { input.len().max(1) } else { size })
}

/// `CHUNK` is the write size: 0 (the whole input at once), a network-sized
/// write, or a trickle.
#[divan::bench(args = INPUTS, consts = [0, 4096, 16])]
fn tokenize<const CHUNK: usize>(bencher: Bencher, name: &str) {
    let input = input(name);
    bencher.bench_local(|| {
        let mut tokenizer = Tokenizer::new();
        for chunk in writes(&input, CHUNK) {
            tokenizer.write(black_box(chunk), &mut Sink).unwrap();
        }
        tokenizer.end(&mut Sink).unwrap();
    });
}

#[divan::bench(args = INPUTS, consts = [0, 4096, 16])]
fn rewrite<const CHUNK: usize>(bencher: Bencher, name: &str) {
    let input = input(name);
    bencher.bench_local(|| {
        let handlers = ElementContentHandlers::new()
            .on("a[href]".parse().unwrap(), |el| {
                el.set_attribute(AttributeName::from_static("rel"), "noopener");
                Ok(())
            })
            .on("div.item".parse().unwrap(), |el| {
                el.append("<span>!</span>");
                Ok(())
            });
        let mut rewriter = HtmlRewriter::from_handlers(handlers);
        let mut written = 0;
        for chunk in writes(&input, CHUNK) {
            rewriter.write(black_box(chunk)).unwrap();
            written += rewriter.take_output().len();
        }
        rewriter.end().unwrap();
        written += rewriter.take_output().len();
        black_box(written)
    });
}
