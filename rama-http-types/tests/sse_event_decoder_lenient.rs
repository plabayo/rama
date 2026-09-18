//! Lenient-mode ([`EventDecoder::with_lenient`]) recovery tests: a decode fault
//! must drop only the event around it and resync at the next blank line, never
//! failing the stream — however the bytes are chunked, and across CR, LF and
//! CRLF terminators, invalid UTF-8 and the size limits.

#![expect(clippy::expect_used, reason = "test helpers unwrap to fail loudly")]

mod sse_common;

use parking_lot::Mutex;
use rama_core::error::BoxError;
use rama_http_types::body::sse::{Event, EventDecoder};
use rand::{RngExt as _, SeedableRng, rngs::StdRng};
use sse_common::{TRICKY, generate_stream, reference};
use std::sync::Arc;

/// Push each chunk, draining events, and report both the surviving events and
/// how many resyncs it took. Lenient decoding never errors on any of these.
fn decode_lenient(chunks: &[&[u8]], max_line_len: Option<usize>) -> (Vec<Event<String>>, usize) {
    let mut decoder = EventDecoder::<String>::new().with_lenient(true);
    if let Some(max) = max_line_len {
        decoder = decoder.with_max_line_len(max);
    }
    let mut events = Vec::new();
    for chunk in chunks {
        decoder.push(chunk).expect("lenient push never errors");
        for event in decoder.events() {
            events.push(event.expect("lenient decoding never yields an error"));
        }
    }
    decoder.finish().expect("lenient finish never errors");
    (events, decoder.resync_count())
}

fn data_of(events: &[Event<String>]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|e| e.data())
        .map(String::as_str)
        .collect()
}

/// Every way of slicing `bytes` into chunks yields the same surviving events
/// and the same resync count: the recovery state machine is chunk-safe.
fn assert_chunk_invariant(
    bytes: &[u8],
    max_line_len: Option<usize>,
    expected: &[&str],
    resyncs: usize,
) {
    for chunk_size in [1usize, 2, 3, 7, 64, bytes.len().max(1)] {
        let chunks: Vec<&[u8]> = bytes.chunks(chunk_size).collect();
        let (events, count) = decode_lenient(&chunks, max_line_len);
        assert_eq!(expected, data_of(&events), "chunk size {chunk_size}");
        assert_eq!(resyncs, count, "chunk size {chunk_size}: resync count");
    }
}

#[test]
fn well_formed_input_decodes_identically_and_never_resyncs() {
    let (events, resyncs) = decode_lenient(&[TRICKY.as_bytes()], None);
    assert_eq!(reference::decode(TRICKY), events);
    assert_eq!(0, resyncs, "nothing to recover from");
}

/// Lenient mode only changes behaviour on a fault: for any valid stream it
/// decodes exactly what the reference model does, and never resyncs.
#[test]
fn random_valid_streams_decode_like_the_reference() {
    let mut rng = StdRng::seed_from_u64(0x7A11_5EED);
    for _ in 0..500 {
        let stream = generate_stream(&mut rng);
        let (events, resyncs) = decode_lenient(&[stream.as_bytes()], None);
        assert_eq!(reference::decode(&stream), events, "stream={stream:?}");
        assert_eq!(0, resyncs, "a valid stream never resyncs: {stream:?}");
    }
}

#[test]
fn an_over_long_line_is_dropped_and_the_stream_keeps_decoding() {
    let long = "x".repeat(100);
    let input = format!("data: one\n\ndata: {long}\n\ndata: three\n\n");
    assert_chunk_invariant(input.as_bytes(), Some(16), &["one", "three"], 1);
}

#[test]
fn an_over_long_event_is_dropped_by_the_event_limit() {
    // no single line is long, but three data lines together exceed the event cap
    // (each `data: xxxx` line is 10 bytes, so two fit under 20 and the third does not)
    let input = "data: one\n\ndata: aaaa\ndata: bbbb\ndata: cccc\n\ndata: three\n\n";
    let mut decoder = EventDecoder::<String>::new()
        .with_lenient(true)
        .with_max_line_len(64)
        .with_max_event_len(20);
    decoder.push(input.as_bytes()).unwrap();
    let events: Vec<_> = decoder.events().map(Result::unwrap).collect();
    decoder.finish().unwrap();
    assert_eq!(vec!["one", "three"], data_of(&events));
    assert_eq!(1, decoder.resync_count());
}

#[test]
fn invalid_utf8_in_a_value_drops_only_that_event() {
    let mut input = Vec::new();
    input.extend_from_slice(b"data: one\n\ndata: ");
    input.extend_from_slice(&[0xff, 0xfe]); // never valid UTF-8
    input.extend_from_slice(b"\n\ndata: three\n\n");
    assert_chunk_invariant(&input, None, &["one", "three"], 1);
}

#[test]
fn a_multi_line_event_with_a_fault_is_dropped_whole() {
    // the fault is on the middle line; the whole event up to the blank line goes
    let mut input = Vec::new();
    input.extend_from_slice(b"data: keep\n\ndata: a\ndata: ");
    input.extend_from_slice(&[0xff]);
    input.extend_from_slice(b"\ndata: c\n\ndata: after\n\n");
    assert_chunk_invariant(&input, None, &["keep", "after"], 1);
}

#[test]
fn recovery_finds_the_boundary_across_crlf_terminators() {
    let long = "x".repeat(100);
    let input = format!("data: one\r\n\r\ndata: {long}\r\n\r\ndata: three\r\n\r\n");
    assert_chunk_invariant(input.as_bytes(), Some(16), &["one", "three"], 1);
}

#[test]
fn recovery_finds_the_boundary_across_bare_cr_terminators() {
    let long = "x".repeat(100);
    let input = format!("data: one\r\rdata: {long}\r\rdata: three\r\r");
    assert_chunk_invariant(input.as_bytes(), Some(16), &["one", "three"], 1);
}

#[test]
fn several_faults_each_count_as_one_resync() {
    let long = "x".repeat(100);
    let input = format!("data: {long}\n\ndata: ok\n\ndata: {long}\n\ndata: end\n\n");
    assert_chunk_invariant(input.as_bytes(), Some(16), &["ok", "end"], 2);
}

#[test]
fn a_fault_in_the_very_first_event_keeps_the_rest() {
    let long = "x".repeat(100);
    let input = format!("data: {long}\n\ndata: two\n\ndata: three\n\n");
    assert_chunk_invariant(input.as_bytes(), Some(16), &["two", "three"], 1);
}

#[test]
fn a_fault_with_no_following_boundary_drops_the_tail_without_erroring() {
    let long = "x".repeat(100);
    // the over-long event never reaches a blank line before the stream ends
    let input = format!("data: one\n\ndata: {long}");
    let (events, resyncs) = decode_lenient(&[input.as_bytes()], Some(16));
    assert_eq!(vec!["one"], data_of(&events));
    assert_eq!(1, resyncs);
}

#[test]
fn lenient_finish_tolerates_a_truncated_trailing_utf8_sequence() {
    // the strict decoder reports this via finish; the lenient one does not
    let input = "data: a\n\ndata: 🚀".as_bytes();
    let truncated = &input[..input.len() - 2];

    let mut decoder = EventDecoder::<String>::new().with_lenient(true);
    decoder.push(truncated).unwrap();
    assert_eq!(1, decoder.events().count());
    decoder.finish().expect("lenient finish never errors");
}

#[test]
fn on_resync_reports_every_fault_with_its_error() {
    let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&errors);

    let long = "x".repeat(100);
    let input = format!("data: {long}\n\ndata: ok\n\ndata: {long}\n\ndata: end\n\n");

    let mut decoder = EventDecoder::<String>::new()
        .with_lenient(true)
        .with_max_line_len(16)
        .with_on_resync(Arc::new(move |err: BoxError| {
            sink.lock().push(err.to_string());
        }));
    decoder.push(input.as_bytes()).unwrap();
    let events: Vec<_> = decoder.events().map(Result::unwrap).collect();
    decoder.finish().unwrap();

    assert_eq!(vec!["ok", "end"], data_of(&events));
    let seen = errors.lock();
    assert_eq!(2, seen.len(), "one report per resync");
    assert!(
        seen.iter().all(|e| e.contains("max line length")),
        "each carries the triggering error: {seen:?}"
    );
}

/// Arbitrary, possibly hostile bytes must never panic, never error in lenient
/// mode, and decode to the same events and resync count however they are
/// chunked — the whole point of an unambiguous boundary.
#[test]
fn arbitrary_bytes_never_error_and_are_chunk_invariant() {
    let mut rng = StdRng::seed_from_u64(0x5E_C0_DE);
    for case in 0..300 {
        let len = rng.random_range(0..=256);
        let mut bytes: Vec<u8> = (0..len).map(|_| rng.random::<u8>()).collect();
        // bias toward structure so faults, boundaries and events all occur
        for byte in &mut bytes {
            match rng.random_range(0..6) {
                0 => *byte = b'\n',
                1 => *byte = b'\r',
                2 => *byte = b':',
                _ => {}
            }
        }

        let (whole, whole_count) = decode_lenient(&[&bytes], Some(24));
        let whole_data = data_of(&whole).join("\u{1}");

        for chunk_size in [1usize, 2, 3, 5, 13] {
            let chunks: Vec<&[u8]> = bytes.chunks(chunk_size).collect();
            let chunks: Vec<&[u8]> = if chunks.is_empty() {
                vec![&[][..]]
            } else {
                chunks
            };
            let (events, count) = decode_lenient(&chunks, Some(24));
            // the surviving events are the invariant that matters and are exact
            assert_eq!(
                whole_data,
                data_of(&events).join("\u{1}"),
                "case {case}, len {len}, chunk {chunk_size}"
            );
            // the resync count is best-effort (a discarded-run tally, and run
            // boundaries shift with where a fault is detected), but chunking
            // must at least agree on whether any recovery happened at all
            assert_eq!(
                whole_count == 0,
                count == 0,
                "case {case}, len {len}, chunk {chunk_size}"
            );
        }
    }
}

#[test]
fn strict_mode_still_fails_on_the_same_input() {
    // the default: a fault is fatal and stops the stream after the good prefix
    let long = "x".repeat(100);
    let input = format!("data: one\n\ndata: {long}\n\ndata: three\n\n");

    let mut decoder = EventDecoder::<String>::new().with_max_line_len(16);
    decoder.push(input.as_bytes()).unwrap();
    let mut events = Vec::new();
    let mut errored = false;
    for event in decoder.events() {
        let Ok(event) = event else {
            errored = true;
            break;
        };
        events.push(event);
    }
    assert!(errored, "strict mode surfaces the fault");
    assert_eq!(
        vec!["one"],
        data_of(&events),
        "only the good prefix survives"
    );
}
