//! Fuzz target for the [`rama_http::protocols::html::tokenizer`].
//!
//! Three properties are checked on arbitrary bytes and on a structured token
//! soup (foreign content, text modes, CDATA), in lenient mode, which never
//! errors:
//!
//!   1. **No panic** — tokenizing any byte sequence terminates cleanly.
//!   2. **Identity** — re-serializing the token stream reproduces the input.
//!   3. **Chunk-invariance** — splitting the input into two `write`s, or
//!      writing it byte by byte, and ending yields identical bytes and an
//!      identical token structure (after coalescing adjacent text) to
//!      one-shot tokenization.
//!   4. **Name identity** — every tag's [`LocalNameHash`] is the identity of
//!      its name.
//!
//! Run with:
//!     cargo +nightly fuzz run html_tokenizer
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::http::protocols::html::tokenizer::{
    Cdata, Comment, Doctype, EndTag, HtmlTag, LocalNameHash, StartTag, Text, TokenSink, Tokenizer,
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

/// The name of a tag (from its raw bytes) has the identity it carries.
fn assert_identity(raw: &[u8], skip: usize, hash: LocalNameHash, tag: HtmlTag<'_>) {
    let name = raw.get(skip..).unwrap_or_default();
    let end = name
        .iter()
        .position(|b| b" \t\n\x0c\r/>".contains(b))
        .unwrap_or(name.len());
    let name = &name[..end];
    assert_eq!(hash, LocalNameHash::of(name), "identity of {name:?}");
    assert!(
        tag.as_bytes().eq_ignore_ascii_case(name),
        "classified {name:?}"
    );
}

impl TokenSink for Sink {
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        assert_identity(tag.raw(), 1, tag.name_hash(), tag.tag());
        self.out.extend_from_slice(tag.raw());
        self.log.push(Ev::Start(
            tag.tag().as_bytes().to_vec(),
            tag.is_self_closing(),
        ));
    }
    fn end_tag(&mut self, tag: &EndTag<'_>) {
        assert_identity(tag.raw(), 2, tag.name_hash(), tag.tag());
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

/// Tokens that steer the context tracker: foreign content, integration
/// points, text modes, CDATA and self-closing roots.
const TOKENS: &[&str] = &[
    "<svg>",
    "<svg/>",
    "</svg>",
    "<math>",
    "<math/>",
    "</math>",
    "<foreignObject>",
    "</foreignObject>",
    "<desc>",
    "</desc>",
    "<title>",
    "</title>",
    "<mi>",
    "</mi>",
    "<annotation-xml encoding=text/html>",
    "<annotation-xml encoding=text&sol;html>",
    "</annotation-xml>",
    "<font color=red>",
    "<b>",
    "<p>",
    "</p>",
    "<br>",
    "<style>",
    "</style>",
    "</style x='>'>",
    "<textarea>",
    "</textarea>",
    "<script>",
    "</script>",
    "</script >",
    "</TITLE\t/>",
    "<x-a-long-custom-name>",
    "</X-A-LONG-CUSTOM-NAME>",
    "<!--",
    "-->",
    "<xmp>",
    "</xmp>",
    "<plaintext>",
    "<select>",
    "</select>",
    "<template>",
    "</template>",
    "<![CDATA[",
    "]]>",
    "<!DOCTYPE html>",
    "<",
    "/",
    ">",
    "text",
    " ",
];

fn check(data: &[u8], split_sel: u16) {
    // One-shot (lenient mode never errors).
    let mut oneshot = Sink::default();
    if Tokenizer::new()
        .with_strict(false)
        .tokenize(data, &mut oneshot)
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
    let expected = coalesce(oneshot.log);
    assert_eq!(
        coalesce(streamed.log),
        expected,
        "structure mismatch (split {split})"
    );

    // Streamed byte by byte: every construct is completed in the retained
    // buffer.
    if data.len() <= 2048 {
        let mut bytes = Sink::default();
        let mut tk = Tokenizer::new().with_strict(false);
        for byte in data.chunks(1) {
            if tk.write(byte, &mut bytes).is_err() {
                return;
            }
        }
        if tk.end(&mut bytes).is_err() {
            return;
        }
        assert_eq!(bytes.out, data, "byte-by-byte identity");
        assert_eq!(coalesce(bytes.log), expected, "byte-by-byte structure");
    }
}

fuzz_target!(|args: (u16, Vec<u8>)| {
    let (split_sel, data) = args;
    check(&data, split_sel);
    let structured: String = data
        .iter()
        .take(512)
        .map(|&byte| TOKENS[usize::from(byte) % TOKENS.len()])
        .collect();
    check(structured.as_bytes(), split_sel);
});
