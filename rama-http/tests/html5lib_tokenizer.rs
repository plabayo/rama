//! Conformance test: the HTML tokenizer's *identity* property over the
//! vendored html5lib tokenizer corpus (`tests/html5lib-tokenizer/`).
//!
//! rama's tokenizer is byte-faithful and does not entity-decode, so we don't
//! compare token streams field-for-field against html5lib's entity-decoded
//! expected output. Instead, every test `input` must tokenize and
//! re-serialize back to the exact same bytes — the property a rewriter
//! relies on — over the full real-world adversarial corpus. (Structural
//! correctness is covered by the in-crate unit tests.)

#![cfg(feature = "html")]
#![expect(
    clippy::expect_used,
    reason = "integration test: panicking on unexpected input is the assertion"
)]

use std::fs;
use std::path::PathBuf;

use rama_http::protocols::html::tokenizer::{
    Cdata, Comment, Doctype, EndTag, StartTag, Text, TokenSink, Tokenizer,
};
use serde_json::Value;

/// Sink that re-serializes every token's raw bytes.
#[derive(Default)]
struct Identity {
    out: Vec<u8>,
}

impl TokenSink for Identity {
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        self.out.extend_from_slice(tag.raw());
    }
    fn end_tag(&mut self, tag: &EndTag<'_>) {
        self.out.extend_from_slice(tag.raw());
    }
    fn text(&mut self, text: &Text<'_>) {
        self.out.extend_from_slice(text.raw());
    }
    fn comment(&mut self, comment: &Comment<'_>) {
        self.out.extend_from_slice(comment.raw());
    }
    fn cdata(&mut self, cdata: &Cdata<'_>) {
        self.out.extend_from_slice(cdata.raw());
    }
    fn doctype(&mut self, doctype: &Doctype<'_>) {
        self.out.extend_from_slice(doctype.raw());
    }
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("html5lib-tokenizer")
}

/// Decodes the `\uXXXX` escapes present in `doubleEscaped` test inputs.
fn decode_double_escaped(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'u') {
            chars.next();
            let mut hex = String::new();
            while hex.len() < 4 {
                match chars.peek() {
                    Some(&h) if h.is_ascii_hexdigit() => {
                        hex.push(h);
                        chars.next();
                    }
                    _ => break,
                }
            }
            if let Ok(cp) = u32::from_str_radix(&hex, 16) {
                out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
            } else {
                out.push('\\');
                out.push('u');
                out.push_str(&hex);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn assert_identity(input: &[u8], origin: &str) {
    let mut sink = Identity::default();
    // Lenient mode never bails, so identity is checked even for the
    // ambiguity-guard cases.
    Tokenizer::new()
        .with_strict(false)
        .tokenize(input, &mut sink)
        .expect("lenient tokenizer never errors");
    assert_eq!(
        sink.out,
        input,
        "identity failed in {origin}: {:?}",
        String::from_utf8_lossy(input)
    );
}

#[test]
fn html5lib_tokenizer_identity() {
    let mut files = 0_usize;
    let mut cases = 0_usize;

    let mut entries: Vec<PathBuf> = fs::read_dir(corpus_dir())
        .expect("open html5lib-tokenizer corpus dir")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("test"))
        .collect();
    entries.sort();

    for path in entries {
        files += 1;
        let data = fs::read_to_string(&path).expect("read test file");
        let json: Value = serde_json::from_str(&data).expect("parse test JSON");
        let origin = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>")
            .to_owned();

        // Most files key on "tests"; xmlViolation.test keys on "xmlViolationTests".
        let tests = json
            .get("tests")
            .or_else(|| json.get("xmlViolationTests"))
            .and_then(Value::as_array);
        let Some(tests) = tests else { continue };

        for test in tests {
            let Some(input) = test.get("input").and_then(Value::as_str) else {
                continue;
            };
            let double_escaped = test
                .get("doubleEscaped")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let input = if double_escaped {
                decode_double_escaped(input)
            } else {
                input.to_owned()
            };
            assert_identity(input.as_bytes(), &origin);
            cases += 1;
        }
    }

    assert!(files > 0, "no html5lib .test files found in corpus dir");
    assert!(cases > 0, "no test cases found in html5lib corpus");
    eprintln!("html5lib tokenizer identity: {cases} inputs across {files} files");
}
