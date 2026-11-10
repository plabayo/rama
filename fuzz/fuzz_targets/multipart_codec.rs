//! `multipart/form-data` parser and encoder fuzz target.
//!
//! Run with:
//!     cargo +nightly fuzz run multipart_codec -- -max_len=4096 -timeout=10
#![expect(
    clippy::panic,
    reason = "a violated fuzz invariant must produce a crash artifact"
)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::bytes::Bytes;
use rama::http::HeaderMap;
use rama::http::protocols::multipart::{Boundary, Encoder, Event, ParseError, Parser};

const BOUNDARIES: [&str; 4] = ["b", "-", "AaB03x", "a b"];

/// Header fields and data of one part, the fields sorted.
type Part = (Vec<(String, Vec<u8>)>, Vec<u8>);

/// What a body parses to: its parts, whether the last one was ended, and the verdict.
#[derive(Debug, PartialEq)]
struct Outcome {
    parts: Vec<Part>,
    open: bool,
    result: Result<(), ParseError>,
}

// Any fragmentation of a body must parse to the same parts and verdict, no part can hold
// its own delimiter, and what parsed must survive being written out again.
fuzz_target!(|data: &[u8]| {
    let [shape, sizes, body @ ..] = data else {
        return;
    };
    let Ok(boundary) = Boundary::new(BOUNDARIES[usize::from(shape & 3)]) else {
        panic!("valid boundary was rejected");
    };

    let (whole, headers) = parse(&boundary, [body].into_iter());
    let sizes = [
        usize::from(sizes & 15).max(1),
        usize::from(sizes >> 4).max(1),
    ];
    let (pieces, _) = parse(&boundary, Pieces { rest: body, sizes });
    assert_eq!(pieces, whole);

    let mut delimiter = b"\r\n--".to_vec();
    delimiter.extend_from_slice(boundary.as_bytes());
    for (_, data) in &whole.parts {
        // the empty line of the head stands in for the CRLF of a delimiter
        let mut led = b"\r\n".to_vec();
        led.extend_from_slice(data);
        assert!(
            !led.windows(delimiter.len()).any(|w| w == delimiter),
            "part data holds the delimiter"
        );
    }

    if whole.result.is_err() {
        return;
    }
    assert!(!whole.open, "a body ended inside a part");
    let mut encoder = Encoder::new(&boundary);
    let mut encoded = Vec::new();
    for (headers, (_, data)) in headers.iter().zip(&whole.parts) {
        encoded.extend_from_slice(&encoder.part(headers));
        encoded.extend_from_slice(data);
    }
    encoded.extend_from_slice(&encoder.finish());
    let (again, _) = parse(&boundary, [encoded.as_slice()].into_iter());
    // a head written out can be a few bytes longer than the one read
    if again.result != Err(ParseError::HeadersTooLarge) {
        assert_eq!(again, whole);
    }
});

/// A body cut into pieces of alternating sizes.
struct Pieces<'a> {
    rest: &'a [u8],
    sizes: [usize; 2],
}

impl<'a> Iterator for Pieces<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let (piece, rest) = self.rest.split_at(self.sizes[0].min(self.rest.len()));
        self.rest = rest;
        self.sizes.swap(0, 1);
        Some(piece)
    }
}

fn parse<'a>(
    boundary: &Boundary,
    mut chunks: impl Iterator<Item = &'a [u8]>,
) -> (Outcome, Vec<HeaderMap>) {
    let mut parser = Parser::new(boundary);
    let mut headers = Vec::new();
    let mut outcome = Outcome {
        parts: Vec::new(),
        open: false,
        result: Ok(()),
    };
    let mut eof = false;
    loop {
        match parser.step() {
            Ok(Event::NeedInput) => {
                assert!(!eof, "input wanted past the end of the body");
                assert!(parser.wants_input());
                if let Some(chunk) = chunks.next() {
                    parser.feed(Bytes::copy_from_slice(chunk));
                } else {
                    parser.set_eof();
                    eof = true;
                }
            }
            Ok(Event::Part(part)) => {
                assert!(!outcome.open, "a part opened inside a part");
                assert!(part.len() <= Parser::MAX_HEADERS);
                let mut fields: Vec<_> = part
                    .iter()
                    .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                    .collect();
                fields.sort();
                outcome.parts.push((fields, Vec::new()));
                outcome.open = true;
                headers.push(part);
            }
            Ok(Event::Data(data)) => {
                assert!(outcome.open, "data outside a part");
                assert!(!data.is_empty(), "empty data event");
                if let Some((_, part)) = outcome.parts.last_mut() {
                    part.extend_from_slice(&data);
                }
            }
            Ok(Event::PartEnd) => {
                assert!(outcome.open, "a part ended outside a part");
                outcome.open = false;
            }
            Ok(Event::End) => {
                assert!(!parser.wants_input());
                assert!(matches!(parser.step(), Ok(Event::End)));
                return (outcome, headers);
            }
            Err(err) => {
                assert!(!parser.wants_input());
                assert_eq!(parser.step().err(), Some(err), "an error must repeat");
                outcome.result = Err(err);
                return (outcome, headers);
            }
        }
    }
}
