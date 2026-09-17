//! Test material shared by the SSE decoder and event-stream suites:
//! a reference implementation of the WHATWG event stream processing
//! model, and a generator of random valid event streams.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns unwrap to fail loudly"
)]

use rand::{RngExt as _, rngs::StdRng};

/// A stream exercising every tricky decoder path: BOM, CRLF/CR/LF mixed
/// terminators, multibyte UTF-8, comments, ids (incl. bare and NUL),
/// events, retry, unknown fields, bare/empty data, empty events,
/// and an unterminated trailing line.
pub(crate) const TRICKY: &str = "\u{feff}: hello ☃ stream\r\ndata: first ✓ line\ndata: sécond\r\nid: 42\nevent: añ-event\nretry: 1500\nunknown: field\n\r\ndata\ndata:\ndata: third 🚀\r\n\r\nid\ndata: bare\n\nid: bad\u{0}id\ndata: nul\n\n: only a comment\n\rdata: crterminated\r\r\ndata: tail is dropped";

/// Simple, obviously-correct reference decoder mirroring the WHATWG
/// event stream processing model (and rama's comment collection), used
/// to differentially validate the optimized decoder.
pub(crate) mod reference {
    use rama_http_types::body::sse::Event;

    pub(crate) fn decode(input: &str) -> Vec<Event<String>> {
        let input = input.strip_prefix('\u{feff}').unwrap_or(input);

        let mut lines = Vec::new();
        let mut cur = String::new();
        let mut chars = input.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    lines.push(std::mem::take(&mut cur));
                }
                '\n' => lines.push(std::mem::take(&mut cur)),
                c => cur.push(c),
            }
        }
        // unterminated trailing line is discarded

        let mut events = Vec::new();
        let mut event = Event::<String>::default();
        let mut data: Option<String> = None;
        for line in lines {
            if line.is_empty() {
                if let Some(mut data) = data.take() {
                    if data.ends_with('\n') {
                        data.pop();
                    }
                    event.set_data(data);
                }
                events.push(std::mem::take(&mut event));
                continue;
            }
            if let Some(comment) = line.strip_prefix(':') {
                event
                    .try_set_comment(comment.strip_prefix(' ').unwrap_or(comment))
                    .unwrap();
                continue;
            }
            let (name, value) = match line.split_once(':') {
                Some((name, value)) => (name, Some(value.strip_prefix(' ').unwrap_or(value))),
                None => (line.as_str(), None),
            };
            match name {
                "data" => {
                    let data = data.get_or_insert_default();
                    data.push_str(value.unwrap_or(""));
                    data.push('\n');
                }
                "event" => match value {
                    Some(v) => {
                        event.try_set_event(v).unwrap();
                    }
                    None => {
                        event = {
                            let mut fresh = Event::<String>::default();
                            if let Some(id) = event.id() {
                                fresh.try_set_id(id).unwrap();
                            }
                            for comment in event.comment() {
                                fresh.try_set_comment(comment).unwrap();
                            }
                            if let Some(retry) = event.retry() {
                                fresh.set_retry(retry.as_millis() as u64);
                            }
                            fresh
                        }
                    }
                },
                "id" => match value {
                    Some(v) if !v.contains('\u{0}') => {
                        event.try_set_id(v).unwrap();
                    }
                    Some(_) => {}
                    None => {
                        event.try_set_id("").unwrap();
                    }
                },
                "retry" => {
                    if let Some(v) = value
                        && !v.is_empty()
                        && v.bytes().all(|b| b.is_ascii_digit())
                        && let Ok(ms) = v.parse::<u64>()
                    {
                        event.set_retry(ms);
                    }
                }
                _ => {}
            }
        }
        events
    }
}

/// Generate a random valid SSE stream (returned as text), exercising
/// all field kinds, terminators, unicode data and edge cases.
pub(crate) fn generate_stream(rng: &mut StdRng) -> String {
    const DATA_CHARS: &[char] = &[
        'a', 'b', ' ', ':', 'é', '☃', '🚀', '\'', '"', 'x', '0', '\u{feff}',
    ];
    let mut out = String::new();
    if rng.random_bool(0.3) {
        out.push('\u{feff}');
    }
    let push_terminator = |out: &mut String, rng: &mut StdRng| {
        match rng.random_range(0..3) {
            0 => out.push('\n'),
            1 => out.push('\r'),
            _ => out.push_str("\r\n"),
        };
    };
    let push_text = |out: &mut String, rng: &mut StdRng| {
        for _ in 0..rng.random_range(0..20) {
            out.push(DATA_CHARS[rng.random_range(0..DATA_CHARS.len())]);
        }
    };
    for _ in 0..rng.random_range(0..12) {
        for _ in 0..rng.random_range(0..8) {
            match rng.random_range(0..8) {
                0 => {
                    out.push(':');
                    push_text(&mut out, rng);
                }
                1 => {
                    out.push_str("id");
                    if rng.random_bool(0.8) {
                        out.push_str(": ");
                        push_text(&mut out, rng);
                    }
                }
                2 => {
                    out.push_str("event: e");
                    push_text(&mut out, rng);
                }
                3 => out.push_str("retry: 1500"),
                4 => out.push_str("some-unknown-field: value"),
                5 => out.push_str("data"),
                _ => {
                    out.push_str("data:");
                    if rng.random_bool(0.8) {
                        out.push(' ');
                    }
                    push_text(&mut out, rng);
                }
            }
            push_terminator(&mut out, rng);
        }
        push_terminator(&mut out, rng);
    }
    if rng.random_bool(0.3) {
        out.push_str("data: unterminated trailing line");
    }
    out
}
