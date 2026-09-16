//! Chunk-boundary, limit and differential tests for the push-driven SSE
//! decoder ([`EventDecoder`]): however the same byte stream is sliced into
//! pushes, it must decode into the identical sequence of events — the same
//! sequence [`EventStream`] yields for that stream.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] fns unwrap to fail loudly"
)]

mod sse_common;

use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::futures::{StreamExt, stream};
use rama_http_types::body::sse::{Event, EventDecoder, EventStream};
use rama_http_types::body::util::BodyExt as _;
use rama_http_types::{Body, BodyCaptureEvent};
use rand::{RngExt as _, SeedableRng, rngs::StdRng};
use sse_common::{TRICKY, generate_stream, reference};
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

/// Push every chunk, draining the events it completed before the next one.
fn decode(chunks: &[&[u8]]) -> Result<Vec<Event<String>>, BoxError> {
    let mut decoder = EventDecoder::<String>::new();
    let mut events = Vec::new();
    for chunk in chunks {
        decoder.push(chunk)?;
        for event in decoder.events() {
            events.push(event?);
        }
    }
    decoder.finish()?;
    Ok(events)
}

/// Same, but pushing everything first and draining once at the end.
fn decode_drain_once(chunks: &[&[u8]]) -> Result<Vec<Event<String>>, BoxError> {
    let mut decoder = EventDecoder::<String>::new();
    for chunk in chunks {
        decoder.push(chunk)?;
    }
    let events = decoder.events().collect::<Result<Vec<_>, _>>()?;
    decoder.finish()?;
    Ok(events)
}

async fn decode_with_stream(chunks: &[&[u8]]) -> Vec<Event<String>> {
    let chunks: Vec<Vec<u8>> = chunks.iter().map(|c| c.to_vec()).collect();
    EventStream::<_, String>::new(stream::iter(chunks.into_iter().map(Ok::<_, Infallible>)))
        .map(|res| res.expect("decode sse event"))
        .collect()
        .await
}

fn split_into(bytes: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    bytes.chunks(chunk_size).collect()
}

#[test]
fn tricky_stream_decodes_as_expected() {
    let events = decode(&[TRICKY.as_bytes()]).unwrap();
    assert_eq!(reference::decode(TRICKY), events);
}

#[test]
fn every_two_way_split_is_equivalent() {
    let bytes = TRICKY.as_bytes();
    let expected = reference::decode(TRICKY);

    for split in 0..=bytes.len() {
        let (head, tail) = bytes.split_at(split);
        assert_eq!(expected, decode(&[head, tail]).unwrap(), "split at {split}");
        assert_eq!(
            expected,
            decode_drain_once(&[head, tail]).unwrap(),
            "split at {split}, drained once",
        );
    }
}

#[test]
fn three_way_splits_are_equivalent() {
    let bytes = TRICKY.as_bytes();
    let expected = reference::decode(TRICKY);

    for first in 0..=bytes.len() {
        for second in first..=bytes.len() {
            let chunks = [&bytes[..first], &bytes[first..second], &bytes[second..]];
            assert_eq!(
                expected,
                decode(&chunks).unwrap(),
                "splits at {first} and {second}",
            );
        }
    }
}

#[test]
fn chunk_size_ladder_is_equivalent() {
    let bytes = TRICKY.as_bytes();
    let expected = reference::decode(TRICKY);

    for chunk_size in 1..=bytes.len() {
        let chunks = split_into(bytes, chunk_size);
        assert_eq!(
            expected,
            decode(&chunks).unwrap(),
            "chunk size {chunk_size}",
        );
    }
}

/// The decoder and the stream built on top of it must never disagree.
#[tokio::test]
async fn differential_against_event_stream_and_reference() {
    let mut rng = StdRng::seed_from_u64(0x5EED_D0DE);
    for round in 0..200 {
        let encoded = generate_stream(&mut rng);
        let expected = reference::decode(&encoded);

        let bytes = encoded.as_bytes();
        for chunking in 0..8 {
            let mut chunks = Vec::new();
            let mut at = 0;
            while at < bytes.len() {
                let step = rng.random_range(1..=32.min(bytes.len() - at));
                chunks.push(&bytes[at..at + step]);
                at += step;
            }
            assert_eq!(
                expected,
                decode(&chunks).unwrap(),
                "round {round} chunking {chunking} input {encoded:?}",
            );
            assert_eq!(
                expected,
                decode_drain_once(&chunks).unwrap(),
                "round {round} chunking {chunking} drained once, input {encoded:?}",
            );
            assert_eq!(
                decode_with_stream(&chunks).await,
                decode(&chunks).unwrap(),
                "round {round} chunking {chunking} input {encoded:?}",
            );
        }
    }
}

/// `finish` is documented as optional: it must never be the reason an event
/// exists. Proven over the same random corpus as the differential test.
#[test]
fn finish_never_contributes_an_event() {
    let mut rng = StdRng::seed_from_u64(0xF1_1213);
    for round in 0..200 {
        let encoded = generate_stream(&mut rng);
        let bytes = encoded.as_bytes();

        let mut chunks = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let step = rng.random_range(1..=32.min(bytes.len() - at));
            chunks.push(&bytes[at..at + step]);
            at += step;
        }

        let mut decoder = EventDecoder::<String>::new();
        let mut without_finish = Vec::new();
        for chunk in &chunks {
            decoder.push(chunk).unwrap();
            for event in decoder.events() {
                without_finish.push(event.unwrap());
            }
        }
        // whatever finish does, it adds no event
        let before = without_finish.len();
        decoder.finish().unwrap();
        let after: Vec<_> = decoder.events().map(Result::unwrap).collect();

        assert!(after.is_empty(), "round {round} input {encoded:?}");
        assert_eq!(
            reference::decode(&encoded),
            without_finish,
            "round {round} input {encoded:?}",
        );
        assert_eq!(before, without_finish.len());
    }
}

#[test]
fn bom_is_only_stripped_at_stream_start() {
    // a BOM inside a line is data; only the leading one is dropped
    let input = "\u{feff}data: a\u{feff}b\n\n\u{feff}data: c\n\n";
    for chunk_size in 1..=input.len() {
        let chunks = split_into(input.as_bytes(), chunk_size);
        let events = decode(&chunks).unwrap();
        assert_eq!(2, events.len(), "chunk size {chunk_size}");
        assert_eq!(Some(&"a\u{feff}b".to_owned()), events[0].data());
        // the second BOM is part of the field name -> unknown field, ignored
        assert_eq!(None, events[1].data(), "chunk size {chunk_size}");
    }
}

#[test]
fn invalid_utf8_yields_an_error_after_the_preceding_events() {
    let mut decoder = EventDecoder::<String>::new();
    decoder.push(b"data: ok\n\ndata: \xff\n\n").unwrap();

    let events: Vec<_> = decoder.events().collect();
    assert_eq!(2, events.len());
    assert_eq!(Some(&"ok".to_owned()), events[0].as_ref().unwrap().data());
    events[1].as_ref().unwrap_err();
}

#[test]
fn a_truncated_utf8_sequence_at_the_end_is_an_error() {
    let valid = "data: 🚀".as_bytes();
    for cut in 1..4 {
        let mut decoder = EventDecoder::<String>::new();
        decoder.push(&valid[..valid.len() - cut]).unwrap();
        assert_eq!(0, decoder.events().count());
        decoder.finish().unwrap_err();
    }
}

#[test]
fn a_huge_multibyte_line_reassembles_across_all_boundaries() {
    let payload = "☃".repeat(4096);
    let input = format!("data: {payload}\n\n");

    for chunk_size in [1, 2, 3, 5, 7, 64, 1024] {
        let chunks = split_into(input.as_bytes(), chunk_size);
        let events = decode(&chunks).unwrap();
        assert_eq!(1, events.len(), "chunk size {chunk_size}");
        assert_eq!(Some(&payload), events[0].data(), "chunk size {chunk_size}");
    }
}

/// A single push holding far more events than the internal ready cap must
/// still deliver every one of them, in order.
#[test]
fn many_tiny_events_in_one_push_decode_in_order() {
    let input: String = (0..10_000).map(|i| format!("data: {i}\n\n")).collect();

    let events = decode(&[input.as_bytes()]).unwrap();
    assert_eq!(10_000, events.len());
    for (i, event) in events.iter().enumerate() {
        assert_eq!(Some(&i.to_string()), event.data());
    }

    // and the same when nothing is drained until the very end
    let events = decode_drain_once(&[input.as_bytes()]).unwrap();
    assert_eq!(10_000, events.len());
}

#[test]
fn a_dense_separator_flood_decodes_completely() {
    let input = vec![b'\n'; 10_000];
    let events = decode(&[&input]).unwrap();
    assert_eq!(10_000, events.len());
    assert!(events.iter().all(|event| event.data().is_none()));
}

#[test]
fn empty_pushes_are_ignored() {
    let events = decode(&[b"", b"data: a", b"", b"\n\n", b""]).unwrap();
    assert_eq!(1, events.len());
    assert_eq!(Some(&"a".to_owned()), events[0].data());
}

#[test]
fn the_line_limit_holds_however_the_input_is_chunked() {
    let input = format!("data: a\n\ndata: {}\n\n", "x".repeat(4096));

    for chunk_size in [1, 3, 64, 4096, input.len()] {
        let mut decoder = EventDecoder::<String>::new().with_max_line_len(1024);
        let mut events = Vec::new();
        let mut error = None;
        for chunk in input.as_bytes().chunks(chunk_size) {
            let Ok(()) = decoder.push(chunk) else {
                break;
            };
            for event in decoder.events() {
                match event {
                    Ok(event) => events.push(event),
                    Err(err) => error = Some(err),
                }
            }
            if error.is_some() {
                break;
            }
        }
        assert!(error.is_some(), "chunk size {chunk_size}");
        // the event completed before the long line still came through
        assert_eq!(1, events.len(), "chunk size {chunk_size}");
        assert_eq!(Some(&"a".to_owned()), events[0].data());
    }
}

#[test]
fn the_event_limit_holds_however_the_input_is_chunked() {
    // no single line is long, but together they build one huge event
    let input: String = std::iter::repeat_n("data: xxxxxxxx\n", 1024)
        .chain(std::iter::once("\n"))
        .collect();

    for chunk_size in [1, 3, 64, input.len()] {
        let mut decoder = EventDecoder::<String>::new()
            .with_max_line_len(1024)
            .with_max_event_len(4096);
        let mut failed = false;
        for chunk in input.as_bytes().chunks(chunk_size) {
            if decoder.push(chunk).is_err() {
                failed = true;
                break;
            }
            if decoder.events().any(|event| event.is_err()) {
                failed = true;
                break;
            }
        }
        assert!(failed, "chunk size {chunk_size}");
    }
}

/// Events never depend on `finish`: they dispatch on the blank line, so a
/// caller with no end-of-body signal still sees every one of them.
#[test]
fn every_event_arrives_without_finish() {
    let input = "data: one

data: two

data: unterminated";

    let mut decoder = EventDecoder::<String>::new();
    decoder.push(input.as_bytes()).unwrap();
    let events: Vec<_> = decoder.events().map(Result::unwrap).collect();

    assert_eq!(2, events.len());
    assert_eq!(Some(&"one".to_owned()), events[0].data());
    assert_eq!(Some(&"two".to_owned()), events[1].data());

    // and dropping the decoder here, never finishing, is fine
    drop(decoder);
}

/// What `finish` buys, and the only thing it buys: a body that stopped
/// in the middle of a UTF-8 sequence is reported rather than ignored.
#[test]
fn only_finish_reports_a_body_that_ended_mid_utf8() {
    let input = "data: a\n\ndata: 🚀".as_bytes();
    let truncated = &input[..input.len() - 2];

    let mut decoder = EventDecoder::<String>::new();
    decoder.push(truncated).unwrap();
    assert_eq!(1, decoder.events().count());

    decoder.finish().unwrap_err();
}

/// The motivating use case: a body forwarded unchanged, inspected in
/// passing by pushing each frame into the decoder.
#[tokio::test]
async fn a_forwarded_body_can_be_inspected_frame_by_frame() {
    let chunks: Vec<Result<Bytes, Infallible>> = vec![
        Ok(Bytes::from_static(b"data: one\n\ndata: t")),
        Ok(Bytes::from_static(b"wo\n\nid: 3\ndata: three\n")),
        Ok(Bytes::from_static(b"\ndata: never terminated")),
    ];

    // `inspect_frame` never signals the end of the body, so the trailing
    // partial line comes back through `on_incomplete` when the decoder is
    // dropped along with the body
    let tail = Arc::new(OnceLock::new());
    let sink = Arc::clone(&tail);
    let mut decoder = EventDecoder::<String>::new().with_on_incomplete(Box::new(move |line| {
        drop(sink.set(line));
    }));
    let mut seen = Vec::new();

    let forwarded = {
        let body = Body::from_stream(stream::iter(chunks)).inspect_frame(|frame| {
            if let Some(data) = frame.data_ref() {
                decoder.push(data).unwrap();
                for event in decoder.events() {
                    seen.push(event.unwrap());
                }
            }
        });
        body.collect().await.unwrap().to_bytes()
    };

    // the body passed through untouched
    assert_eq!(
        &forwarded[..],
        b"data: one\n\ndata: two\n\nid: 3\ndata: three\n\ndata: never terminated",
    );
    // and every event was observed along the way
    assert_eq!(3, seen.len());
    assert_eq!(Some(&"one".to_owned()), seen[0].data());
    assert_eq!(Some(&"two".to_owned()), seen[1].data());
    assert_eq!(Some(&"three".to_owned()), seen[2].data());
    assert_eq!(Some("3"), decoder.last_event_id());

    // dropping the decoder is what hands the unterminated tail over
    assert!(tail.get().is_none());
    drop(decoder);
    assert_eq!(
        tail.get().map(Vec::as_slice),
        Some(&b"data: never terminated"[..]),
    );
}

/// `inspect_frame` never learns that the body ended. `capture` does, and
/// that terminal event is where `finish` belongs.
#[tokio::test]
async fn a_captured_body_can_be_finished_on_its_terminal_event() {
    let chunks: Vec<Result<Bytes, Infallible>> = vec![
        Ok(Bytes::from_static(b"data: one\n\nda")),
        Ok(Bytes::from_static(b"ta: two\n\n")),
    ];

    let decoder = Arc::new(Mutex::new(EventDecoder::<String>::new()));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let finished = Arc::new(AtomicBool::new(false));

    let body = Body::from_stream(stream::iter(chunks)).capture({
        let decoder = Arc::clone(&decoder);
        let seen = Arc::clone(&seen);
        let finished = Arc::clone(&finished);
        move |event| {
            let decoder = Arc::clone(&decoder);
            let seen = Arc::clone(&seen);
            let finished = Arc::clone(&finished);
            async move {
                let mut decoder = decoder.lock().await;
                match event {
                    BodyCaptureEvent::Frame(frame) => {
                        if let Some(data) = frame.data_ref() {
                            decoder.push(data).expect("push body chunk");
                            let mut seen = seen.lock().await;
                            for event in decoder.events() {
                                seen.push(event.expect("decode sse event"));
                            }
                        }
                    }
                    BodyCaptureEvent::End(_) => {
                        decoder.finish().expect("finish sse decoding");
                        finished.store(true, Ordering::Relaxed);
                    }
                }
            }
        }
    });

    body.collect().await.unwrap();

    assert!(finished.load(Ordering::Relaxed));
    let seen = seen.lock().await;
    assert_eq!(2, seen.len());
    assert_eq!(Some(&"one".to_owned()), seen[0].data());
    assert_eq!(Some(&"two".to_owned()), seen[1].data());
}
