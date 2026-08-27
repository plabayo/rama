//! Chunk-boundary, regression and differential tests for the client-side
//! SSE decoder ([`EventStream`]): any way the same byte stream is sliced
//! into body chunks must decode into the identical sequence of events.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] fns unwrap to fail loudly"
)]

use rama_core::futures::{StreamExt, stream};
use rama_http_types::body::sse::{Event, EventStream};
use rand::{RngExt as _, SeedableRng, rngs::StdRng};
use std::convert::Infallible;

async fn decode(chunks: Vec<Vec<u8>>) -> Vec<Event<String>> {
    EventStream::<_, String>::new(stream::iter(chunks.into_iter().map(Ok::<_, Infallible>)))
        .map(|res| res.expect("decode sse event"))
        .collect()
        .await
}

fn split_into(bytes: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    bytes.chunks(chunk_size).map(<[u8]>::to_vec).collect()
}

/// A stream exercising every tricky decoder path: BOM, CRLF/CR/LF mixed
/// terminators, multibyte UTF-8, comments, ids (incl. bare and NUL),
/// events, retry, unknown fields, bare/empty data, empty events,
/// and an unterminated trailing line.
const TRICKY: &str = "\u{feff}: hello ☃ stream\r\ndata: first ✓ line\ndata: sécond\r\nid: 42\nevent: añ-event\nretry: 1500\nunknown: field\n\r\ndata\ndata:\ndata: third 🚀\r\n\r\nid\ndata: bare\n\nid: bad\u{0}id\ndata: nul\n\n: only a comment\n\rdata: crterminated\r\r\ndata: tail is dropped";

#[tokio::test]
async fn tricky_stream_decodes_as_expected() {
    let events = decode(vec![TRICKY.as_bytes().to_vec()]).await;

    assert_eq!(6, events.len(), "events: {events:?}");

    assert_eq!(Some("hello ☃ stream"), events[0].comment().next());
    assert_eq!(Some(&"first ✓ line\nsécond".to_owned()), events[0].data());
    assert_eq!(Some("42"), events[0].id());
    assert_eq!(Some("añ-event"), events[0].event());
    assert_eq!(1500, events[0].retry().unwrap().as_millis());

    assert_eq!(Some(&"\n\nthird 🚀".to_owned()), events[1].data());

    assert_eq!(Some(&"bare".to_owned()), events[2].data());
    assert_eq!(Some(""), events[2].id());

    // NUL id line is ignored entirely
    assert_eq!(Some(&"nul".to_owned()), events[3].data());
    assert_eq!(None, events[3].id());

    assert_eq!(Some("only a comment"), events[4].comment().next());
    assert_eq!(None, events[4].data());

    // a line terminated by a lone CR, with the following CRLF forming
    // the event-terminating empty line
    assert_eq!(Some(&"crterminated".to_owned()), events[5].data());
}

/// Exhaustive two-way splits: every possible chunk boundary position,
/// which by construction covers splitting before/after `\n`, between
/// `\r` and `\n`, before/after `:`, after `data`, inside multibyte
/// UTF-8 characters, inside the BOM, and between consecutive events.
#[tokio::test]
async fn every_two_way_split_is_equivalent() {
    let bytes = TRICKY.as_bytes();
    let expected = decode(vec![bytes.to_vec()]).await;
    for i in 0..=bytes.len() {
        let events = decode(vec![bytes[..i].to_vec(), bytes[i..].to_vec()]).await;
        assert_eq!(expected, events, "split at byte {i}");
    }
}

/// Three-way splits around every position (with a second boundary two
/// bytes later): catches state carried across more than one boundary,
/// e.g. a CRLF pair or UTF-8 sequence spread over three chunks.
#[tokio::test]
async fn three_way_splits_are_equivalent() {
    let bytes = TRICKY.as_bytes();
    let expected = decode(vec![bytes.to_vec()]).await;
    for i in 0..bytes.len() {
        let j = (i + 2).min(bytes.len());
        let events = decode(vec![
            bytes[..i].to_vec(),
            bytes[i..j].to_vec(),
            bytes[j..].to_vec(),
        ])
        .await;
        assert_eq!(expected, events, "splits at bytes {i} and {j}");
    }
}

fn medium_stream() -> String {
    let mut out = String::new();
    for event in 0..10 {
        out.push_str(&format!(": event {event}\nid: {event}\nevent: e{event}\n"));
        for line in 0..300 {
            out.push_str(&format!(
                "data: event {event} line {line} ☃ with some padding\n"
            ));
        }
        out.push('\n');
    }
    out
}

#[tokio::test]
async fn chunk_size_ladder_is_equivalent() {
    let encoded = medium_stream();
    let bytes = encoded.as_bytes();
    let expected = decode(vec![bytes.to_vec()]).await;
    assert_eq!(10, expected.len());

    for chunk_size in [
        1,
        2,
        3,
        512,
        4 * 1024,
        16 * 1024,
        64 * 1024,
        128 * 1024,
        256 * 1024,
        512 * 1024,
        1024 * 1024,
        bytes.len(),
    ] {
        let events = decode(split_into(bytes, chunk_size)).await;
        assert_eq!(expected, events, "chunk size {chunk_size}");
    }
}

/// The `rust-sse-bench` "gigantic" workload shape: 100 events of 3,000
/// `data:` lines of 153 bytes each, i.e. 461,999 payload bytes per event
/// and 46,199,900 payload bytes in total. Verified at a bench-realistic
/// chunk size against exact reconstruction: no missing, duplicated or
/// reordered bytes.
#[tokio::test]
async fn large_regression_exact_reconstruction() {
    const EVENTS: usize = 100;
    const LINES: usize = 3_000;

    let mut line = String::new();
    for i in 0..153 {
        line.push(char::from(b'a' + ((i * 7) % 26) as u8));
    }
    let payload = vec![line.as_str(); LINES].join("\n");
    assert_eq!(461_999, payload.len());

    let mut encoded = String::new();
    for _ in 0..EVENTS {
        for _ in 0..LINES {
            encoded.push_str("data: ");
            encoded.push_str(&line);
            encoded.push('\n');
        }
        encoded.push('\n');
    }

    let events = decode(split_into(encoded.as_bytes(), 400 * 1024)).await;

    assert_eq!(EVENTS, events.len());
    let mut total = 0;
    for (i, event) in events.iter().enumerate() {
        let data = event.data().expect("event data");
        assert_eq!(payload, *data, "event {i}");
        assert_eq!(1 + data.matches('\n').count(), LINES, "event {i}");
        total += data.len();
    }
    assert_eq!(46_199_900, total);
}

#[tokio::test]
async fn bom_is_only_stripped_at_stream_start() {
    // BOM in the middle of a line is data; only the leading one is dropped
    let input = "\u{feff}data: a\u{feff}b\n\n\u{feff}data: c\n\n".as_bytes();
    let expected = decode(vec![input.to_vec()]).await;
    assert_eq!(2, expected.len());
    assert_eq!(Some(&"a\u{feff}b".to_owned()), expected[0].data());
    // second BOM is part of the field name -> unknown field, ignored
    assert_eq!(None, expected[1].data());

    for chunk_size in [1, 2, 3, 4] {
        let events = decode(split_into(input, chunk_size)).await;
        assert_eq!(expected, events, "chunk size {chunk_size}");
    }
}

#[tokio::test]
async fn invalid_utf8_yields_error_after_preceding_events() {
    let mut bytes = b"data: ok\n\ndata: bad".to_vec();
    bytes.push(0xFF);
    bytes.extend_from_slice(b"\n\n");

    let mut stream = EventStream::<_, String>::new(stream::iter([Ok::<_, Infallible>(bytes)]));
    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(Some(&"ok".to_owned()), first.data());
    stream.next().await.unwrap().unwrap_err();
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn truncated_utf8_at_stream_end_is_an_error() {
    // "é" is [0xC3, 0xA9]: cut the second byte off at end of stream
    let bytes = b"data: ok\n\ndata: \xC3".to_vec();
    let mut stream = EventStream::<_, String>::new(stream::iter([Ok::<_, Infallible>(bytes)]));
    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(Some(&"ok".to_owned()), first.data());
    stream.next().await.unwrap().unwrap_err();
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn poll_budget_boundaries_preserve_crlf_and_utf8() {
    const CAP: usize = 1024 * 1024;

    // The first poll ends exactly on CR; its LF continuation must not be
    // mistaken for a second, empty line when overflow resumes.
    let mut crlf = b"data: ".to_vec();
    crlf.extend(std::iter::repeat_n(b'x', CAP - crlf.len() - 1));
    crlf.extend_from_slice(b"\r\n\r\n");
    let events = decode(vec![crlf]).await;
    assert_eq!(1, events.len());
    assert_eq!(CAP - b"data: ".len() - 1, events[0].data().unwrap().len());

    // The same artificial boundary may bisect a multibyte UTF-8 character.
    let mut utf8 = b"data: ".to_vec();
    utf8.extend(std::iter::repeat_n(b'x', CAP - utf8.len() - 1));
    utf8.extend_from_slice("é\n\n".as_bytes());
    let events = decode(vec![utf8]).await;
    assert_eq!(1, events.len());
    assert!(events[0].data().unwrap().ends_with('é'));
}

#[tokio::test]
async fn invalid_utf8_after_multiple_ready_batches_is_ordered() {
    const EVENTS: usize = 2 * 16 + 1;
    let mut bytes = Vec::new();
    for id in 0..EVENTS {
        bytes.extend_from_slice(format!("id: {id}\ndata: {id}\n\n").as_bytes());
    }
    bytes.push(0xff);

    let mut stream = EventStream::<_, String>::new(stream::iter([Ok::<_, Infallible>(bytes)]));
    for id in 0..EVENTS {
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(Some(id.to_string().as_str()), event.id());
        assert_eq!(Some(id.to_string().as_str()), stream.last_event_id());
    }
    stream.next().await.unwrap().unwrap_err();
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn transport_errors_pass_through_without_terminating() {
    let chunks = vec![
        Ok(b"data: a\n\n".to_vec()),
        Err("boom"),
        Ok(b"data: b\n\n".to_vec()),
    ];
    let mut stream = EventStream::<_, String>::new(stream::iter(chunks));
    assert_eq!(
        Some(&"a".to_owned()),
        stream.next().await.unwrap().unwrap().data()
    );
    stream.next().await.unwrap().unwrap_err();
    assert_eq!(
        Some(&"b".to_owned()),
        stream.next().await.unwrap().unwrap().data()
    );
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn transport_error_after_cooperative_yield_is_nonterminal() {
    const CAP: usize = 1024 * 1024;
    let chunks = vec![
        Ok(b"x\n".repeat(CAP + 1)),
        Err("boom"),
        Ok(b"data: after\n\n".to_vec()),
    ];
    let mut stream = EventStream::<_, String>::new(stream::iter(chunks));
    stream.next().await.unwrap().unwrap_err();
    assert_eq!(
        Some(&"after".to_owned()),
        stream.next().await.unwrap().unwrap().data()
    );
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn empty_chunks_are_ignored() {
    let chunks: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"data: a".to_vec(),
        b"".to_vec(),
        b"\n\n".to_vec(),
        b"".to_vec(),
    ];
    let events = decode(chunks).await;
    assert_eq!(1, events.len());
    assert_eq!(Some(&"a".to_owned()), events[0].data());
}

/// Simple, obviously-correct reference decoder mirroring the WHATWG
/// event stream processing model (and rama's comment collection), used
/// to differentially validate the optimized decoder.
mod reference {
    use rama_http_types::body::sse::Event;

    pub(super) fn decode(input: &str) -> Vec<Event<String>> {
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
fn generate_stream(rng: &mut StdRng) -> String {
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

/// Differential test: random valid streams, random chunk boundaries,
/// optimized decoder vs the reference decoder.
#[tokio::test]
async fn differential_random_streams_and_chunkings() {
    let mut rng = StdRng::seed_from_u64(0x5EED_5EED);
    for round in 0..200 {
        let encoded = generate_stream(&mut rng);
        let expected = reference::decode(&encoded);

        let bytes = encoded.as_bytes();
        for chunking in 0..8 {
            let mut chunks = Vec::new();
            let mut at = 0;
            while at < bytes.len() {
                let step = rng.random_range(1..=32.min(bytes.len() - at));
                chunks.push(bytes[at..at + step].to_vec());
                at += step;
            }
            let events = decode(chunks).await;
            assert_eq!(
                expected, events,
                "round {round} chunking {chunking} input {encoded:?}"
            );
        }
    }
}

/// The public last-event-ID checkpoint must move when an event is
/// yielded to the caller, never while later events of the same chunk
/// are still queued: persisting the checkpoint after event 1 and
/// reconnecting must not skip the unconsumed event 2.
#[tokio::test]
async fn last_event_id_advances_only_on_yield() {
    let input = "id: 1\ndata: a\n\nid: 2\ndata: b\n\nid: 3\ndata: c\n\n";
    let mut stream = EventStream::<_, String>::new(stream::iter([Ok::<_, Infallible>(input)]));

    assert_eq!(None, stream.last_event_id());

    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(Some("1"), first.id());
    assert_eq!(Some("1"), stream.last_event_id());

    // a caller-provided checkpoint between yields must stick until the
    // NEXT yielded event overrides it, queued events notwithstanding
    stream.try_set_last_event_id("restored").unwrap();
    assert_eq!(Some("restored"), stream.last_event_id());

    let second = stream.next().await.unwrap().unwrap();
    assert_eq!(Some("2"), second.id());
    assert_eq!(Some("2"), stream.last_event_id());

    let third = stream.next().await.unwrap().unwrap();
    assert_eq!(Some("3"), third.id());
    assert_eq!(Some("3"), stream.last_event_id());

    assert!(stream.next().await.is_none());
    assert_eq!(Some("3"), stream.last_event_id());
}

/// A single chunk packed with thousands of tiny events exercises the
/// bounded ready-queue (decode pauses at the soft cap and resumes from
/// the set-aside remainder): every event must still come out, in order.
#[tokio::test]
async fn many_tiny_events_in_one_chunk_decode_in_order() {
    const EVENTS: usize = 5_000;
    let mut encoded = String::new();
    for i in 0..EVENTS {
        encoded.push_str(&format!("id: {i}\ndata: payload {i}\n\n"));
    }

    let mut stream =
        EventStream::<_, String>::new(stream::iter([Ok::<_, Infallible>(encoded.into_bytes())]));
    for i in 0..EVENTS {
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(Some(format!("{i}").as_str()), event.id(), "event {i}");
        assert_eq!(Some(&format!("payload {i}")), event.data(), "event {i}");
        // the checkpoint tracks the yielded event, not decode progress
        assert_eq!(Some(format!("{i}").as_str()), stream.last_event_id());
    }
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn many_tiny_mixed_terminator_events_decode_in_order() {
    const EVENTS: usize = 100;
    let mut encoded = Vec::new();
    for i in 0..EVENTS {
        let terminator = [b"\n".as_slice(), b"\r".as_slice(), b"\r\n".as_slice()][i % 3];
        encoded.extend_from_slice(format!("id: {i}").as_bytes());
        encoded.extend_from_slice(terminator);
        encoded.extend_from_slice(format!("data: payload {i}").as_bytes());
        encoded.extend_from_slice(terminator);
        encoded.extend_from_slice(terminator);
    }

    let mut stream = EventStream::<_, String>::new(stream::iter([Ok::<_, Infallible>(encoded)]));
    for i in 0..EVENTS {
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(Some(i.to_string().as_str()), event.id());
        assert_eq!(Some(&format!("payload {i}")), event.data());
    }
    assert!(stream.next().await.is_none());
}

/// A huge event must not make the following tiny event's payload
/// pre-reserve (and retain) a comparable capacity.
#[tokio::test]
async fn huge_event_does_not_inflate_next_payload_capacity() {
    let big = "x".repeat(8 * 1024 * 1024);
    let encoded = format!("data: {big}\n\ndata: y\n\n");

    let mut stream =
        EventStream::<_, String>::new(stream::iter([Ok::<_, Infallible>(encoded.into_bytes())]));
    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(big.len(), first.data().unwrap().len());
    let second = stream.next().await.unwrap().unwrap();
    let data = second.into_data().unwrap();
    assert_eq!("y", data);
    assert!(
        data.capacity() < 4096,
        "tiny payload retained {} bytes of capacity",
        data.capacity()
    );
}

/// Floods of bare separators are the densest possible event stream: every
/// terminator dispatches an (empty) event, hammering the ready-cap pause /
/// resume path and, past 1 MiB, the per-poll byte budget. Each flavor must
/// decode completely, one event per separator.
#[tokio::test]
async fn dense_separator_floods_decode_completely() {
    const N: usize = 1024 * 1024 + 3;
    for (input, expected) in [
        (vec![b'\n'; N], N),
        (vec![b'\r'; N], N),
        (b"\r\n".repeat(N / 2), N / 2),
    ] {
        let events = decode(vec![input]).await;
        assert_eq!(expected, events.len());
        assert!(events.iter().all(|ev| ev.data().is_none()));
    }
}

/// The ready-event cap lands right after a scan block has grown large:
/// a ~511 KiB data line forces block growth up to the biggest block, then
/// a burst of empty lines hits the cap at its very start. Decoding must
/// resume without losing or duplicating events, every repetition.
#[tokio::test]
async fn ready_cap_inside_a_grown_scan_block_resumes_correctly() {
    const LINE_LEN: usize = 511 * 1024;
    const BURST: usize = 63;
    const REPS: usize = 4;

    let mut unit = b"data: ".to_vec();
    unit.extend(std::iter::repeat_n(b'x', LINE_LEN));
    unit.push(b'\n');
    unit.extend(std::iter::repeat_n(b'\n', BURST));
    let mut input = Vec::new();
    for _ in 0..REPS {
        input.extend_from_slice(&unit);
    }

    let events = decode(vec![input]).await;
    assert_eq!(REPS * BURST, events.len());
    for (i, event) in events.iter().enumerate() {
        if i % BURST == 0 {
            assert_eq!(Some(LINE_LEN), event.data().map(String::len), "event {i}");
        } else {
            assert_eq!(None, event.data(), "event {i}");
        }
    }
}

/// One huge line of multibyte characters: incomplete UTF-8 sequences
/// straddle scan-block edges and the per-poll byte budget alike, and must
/// reassemble exactly like physical chunk splits do.
#[tokio::test]
async fn huge_multibyte_line_reassembles_across_all_boundaries() {
    const CHARS: usize = 512 * 1024 + 1; // 2 bytes each: > 1 MiB budget
    let mut input = b"data: ".to_vec();
    input.extend_from_slice("é".repeat(CHARS).as_bytes());
    input.extend_from_slice(b"\n\n");

    let events = decode(vec![input]).await;
    assert_eq!(1, events.len());
    let data = events[0].data().unwrap();
    assert_eq!(CHARS * "é".len(), data.len());
    assert!(data.chars().all(|c| c == 'é'));
}
