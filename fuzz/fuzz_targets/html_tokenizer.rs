//! Fuzz target for the [`rama_http::protocols::html::tokenizer`].
//!
//! Three properties are checked on arbitrary bytes (in lenient mode, which
//! never errors):
//!
//!   1. **No panic** — tokenizing any byte sequence terminates cleanly.
//!   2. **Identity** — re-serializing the token stream reproduces the input.
//!   3. **Chunk-invariance** — splitting the input into two `write`s and
//!      ending yields identical bytes and an identical token structure
//!      (after coalescing adjacent text) to one-shot tokenization.
//!
//! Run with:
//!     cargo +nightly fuzz run html_tokenizer
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::http::protocols::html::tokenizer::{
    Cdata, Comment, Doctype, EndTag, StartTag, Text, TokenSink, Tokenizer,
};

#[derive(PartialEq, Eq, Debug)]
enum Ev {
    Start(Vec<u8>, bool),
    End(Vec<u8>),
    Text(Vec<u8>),
    Comment(Vec<u8>),
    Cdata(Vec<u8>),
    Doctype(Option<Vec<u8>>),
}

#[derive(Default)]
struct Sink {
    out: Vec<u8>,
    log: Vec<Ev>,
}

impl TokenSink for Sink {
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        self.out.extend_from_slice(tag.raw());
        self.log.push(Ev::Start(
            tag.tag().as_bytes().to_vec(),
            tag.is_self_closing(),
        ));
    }
    fn end_tag(&mut self, tag: &EndTag<'_>) {
        self.out.extend_from_slice(tag.raw());
        self.log.push(Ev::End(tag.tag().as_bytes().to_vec()));
    }
    fn text(&mut self, text: &Text<'_>) {
        self.out.extend_from_slice(text.raw());
        self.log.push(Ev::Text(text.as_bytes().to_vec()));
    }
    fn comment(&mut self, comment: &Comment<'_>) {
        self.out.extend_from_slice(comment.raw());
        self.log.push(Ev::Comment(comment.data().to_vec()));
    }
    fn cdata(&mut self, cdata: &Cdata<'_>) {
        self.out.extend_from_slice(cdata.raw());
        self.log.push(Ev::Cdata(cdata.data().to_vec()));
    }
    fn doctype(&mut self, doctype: &Doctype<'_>) {
        self.out.extend_from_slice(doctype.raw());
        self.log
            .push(Ev::Doctype(doctype.name().map(<[u8]>::to_vec)));
    }
}

/// Merges adjacent text events (text may stream in pieces).
fn coalesce(log: Vec<Ev>) -> Vec<Ev> {
    let mut out: Vec<Ev> = Vec::new();
    for event in log {
        match event {
            Ev::Text(mut cur) => {
                if let Some(Ev::Text(prev)) = out.last_mut() {
                    prev.append(&mut cur);
                } else {
                    out.push(Ev::Text(cur));
                }
            }
            other => out.push(other),
        }
    }
    out
}

fuzz_target!(|args: (u16, Vec<u8>)| {
    let (split_sel, data) = args;

    // One-shot (lenient mode never errors).
    let mut oneshot = Sink::default();
    if Tokenizer::new()
        .with_strict(false)
        .tokenize(&data, &mut oneshot)
        .is_err()
    {
        return;
    }
    assert_eq!(oneshot.out, data, "one-shot identity");

    // Streamed: split into two writes + end.
    let split = (split_sel as usize) % (data.len() + 1);
    let mut streamed = Sink::default();
    let mut tk = Tokenizer::new().with_strict(false);
    if tk.write(&data[..split], &mut streamed).is_err()
        || tk.write(&data[split..], &mut streamed).is_err()
        || tk.end(&mut streamed).is_err()
    {
        return;
    }

    assert_eq!(streamed.out, data, "streamed identity (split {split})");
    assert_eq!(
        coalesce(streamed.log),
        coalesce(oneshot.log),
        "structure mismatch (split {split})"
    );
});
