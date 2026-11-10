#![expect(
    clippy::expect_used,
    reason = "bench: panic-on-error validates the fixture outside timing"
)]

//! Incremental scalar tokenization at transport and one-byte chunk sizes.

use divan::{black_box, counter::BytesCount};
use rama::json::JsonError;
use rama::json::tokenizer::{Token, TokenSink, Tokenizer};
use rama::utils::octets::kib;

mod bench_alloc;

struct Count(usize);

impl TokenSink for Count {
    fn token(&mut self, token: Token<'_>) -> Result<(), JsonError> {
        self.0 += token.raw().len();
        Ok(())
    }
}

fn tokenize(input: &[u8], width: usize) -> usize {
    let mut tokenizer = Tokenizer::new();
    let mut sink = Count(0);
    for chunk in input.chunks(width) {
        tokenizer.write(chunk, &mut sink).expect("valid JSON");
    }
    tokenizer.end(&mut sink).expect("complete JSON");
    sink.0
}

fn scalar(number: bool, len: usize) -> Vec<u8> {
    if number {
        let mut input = b"0.".to_vec();
        input.resize(len - 2, b'7');
        input.extend_from_slice(b"e1");
        input
    } else {
        let mut input = vec![b'"'];
        input.resize(len - 1, b'a');
        input.push(b'"');
        input
    }
}

fn main() {
    for number in [false, true] {
        let input = scalar(number, kib(16));
        for width in [1, 64, kib(16)] {
            assert_eq!(tokenize(&input, width), input.len());
        }
    }
    divan::main();
}

#[divan::bench(args = [1, 64, 16384], consts = [false, true])]
fn incremental_scalar<const NUMBER: bool>(bencher: divan::Bencher, width: usize) {
    let input = scalar(NUMBER, kib(16));
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| tokenize(black_box(&input), width));
}

fn document(escaped: bool) -> Vec<u8> {
    if escaped {
        let mut input = vec![b'"'];
        for _ in 0..1024 {
            input.extend_from_slice(br#"a\n\u00e9\""#);
        }
        input.push(b'"');
        input
    } else {
        let entry = br#"{"id":1234,"value":-1.25e+2,"ok":true,"name":"short","tag":"x"},"#;
        let mut input = vec![b'['];
        for _ in 0..256 {
            input.extend_from_slice(entry);
        }
        input.pop();
        input.push(b']');
        input
    }
}

#[divan::bench(args = [1, 64, 16384], consts = [false, true])]
fn incremental_document<const ESCAPED: bool>(bencher: divan::Bencher, width: usize) {
    let input = document(ESCAPED);
    assert_eq!(tokenize(&input, width), input.len());
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| tokenize(black_box(&input), width));
}
