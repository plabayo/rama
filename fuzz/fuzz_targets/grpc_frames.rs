//! gRPC length-prefixed message decoding fuzz target.
//!
//! Goals: however the body is split into data frames, the decoder yields
//! exactly the messages a reference parse of the whole body finds, and ends
//! cleanly only when the body holds nothing but whole messages.
//!
//! Run with:
//!     cargo +nightly fuzz run grpc_frames -- -max_len=65536
#![expect(
    clippy::panic,
    reason = "a violated fuzz invariant must produce a crash artifact"
)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::bytes::{Buf as _, Bytes};
use rama::error::BoxError;
use rama::futures::{Stream as _, stream};
use rama::http::Body;
use rama::http::grpc::{
    Status, Streaming,
    codec::{DecodeBuf, Decoder},
};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

const MAX_MESSAGE: usize = 1024;

/// Hands out each message as received.
struct Raw;

impl Decoder for Raw {
    type Item = Bytes;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Bytes>, Status> {
        Ok(Some(src.copy_to_bytes(src.remaining())))
    }
}

/// Whole uncompressed messages at the front of `wire`, and whether nothing else follows.
fn reference(mut wire: &[u8]) -> (Vec<Bytes>, bool) {
    let mut messages = Vec::new();
    while let [flag, a, b, c, d, rest @ ..] = wire {
        let len = u32::from_be_bytes([*a, *b, *c, *d]) as usize;
        if *flag != 0 || len > MAX_MESSAGE || len > rest.len() {
            return (messages, false);
        }
        messages.push(Bytes::copy_from_slice(&rest[..len]));
        wire = &rest[len..];
    }
    (messages, wire.is_empty())
}

fuzz_target!(|data: &[u8]| {
    let Some((&split, wire)) = data.split_first() else {
        return;
    };
    let wire = Bytes::copy_from_slice(wire);
    let step = usize::from(split).max(1);
    let chunks: Vec<Bytes> = (0..wire.len())
        .step_by(step)
        .map(|at| wire.slice(at..(at + step).min(wire.len())))
        .collect();
    let body = Body::from_stream(stream::iter(chunks.into_iter().map(Ok::<_, BoxError>)));
    let mut streaming = Streaming::new_request(Raw, body, None, Some(MAX_MESSAGE));

    let (expected, clean) = reference(&wire);
    let mut cx = Context::from_waker(Waker::noop());
    let mut decoded = Vec::new();
    let ended_cleanly = loop {
        match Pin::new(&mut streaming).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(message))) => decoded.push(message),
            Poll::Ready(Some(Err(_))) => break false,
            Poll::Ready(None) => break true,
            Poll::Pending => panic!("in-memory grpc body pending"),
        }
    };
    if decoded != expected {
        panic!("decoded {decoded:?}, expected {expected:?}");
    }
    if ended_cleanly != clean {
        panic!("ended cleanly: {ended_cleanly}, expected {clean}");
    }
});
