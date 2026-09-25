//! Bounded synchronous fuzz entry points for transport-independent H3 state.

use super::{
    Error,
    connection::{Config, Shared},
    control::{Control, Role},
    frame::{FrameDecoder, FrameEvent},
    quic::RecvStream,
    stream::{Phase, Reader},
};
use rama_core::bytes::Bytes;
use rama_http_types::proto::h3::{Code, StreamType};
use std::task::{Context, Poll, Waker};

struct Fragmented {
    bytes: Bytes,
    fragment: usize,
    pending: bool,
}
impl RecvStream for Fragmented {
    fn poll_chunk(
        &mut self,
        cx: &mut Context<'_>,
        limit: usize,
    ) -> Poll<Result<Option<Bytes>, Error>> {
        self.pending = !self.pending;
        if self.pending {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok((!self.bytes.is_empty()).then(|| {
            self.bytes
                .split_to(limit.min(self.fragment).min(self.bytes.len()))
        })))
    }
    fn stop(&mut self, _code: Code) {
        self.bytes = Bytes::new();
    }
}

/// Exercise fragmented frame placement, stream registration, completion and cancellation.
/// The first three bytes select role, message phase and fragmentation. Remaining
/// bytes are wire input, with fixed memory/work caps independent of advertised lengths.
pub fn state(input: &[u8]) {
    compression_schedule(input);
    if input.len() < 3 {
        return;
    }
    let role = if input[0] & 1 == 0 {
        Role::Client
    } else {
        Role::Server
    };
    let fragment = usize::from(input[2] % 32) + 1;
    let bytes = Bytes::copy_from_slice(&input[3..input.len().min(rama_utils::octets::kib(64))]);
    let mut control = Control::new(role);
    for &kind in &input[..3] {
        let _result = control.register(StreamType::new(u64::from(kind & 7)));
    }
    let mut frames =
        FrameDecoder::with_input_limit(rama_utils::octets::kib(4), 32).with_header_events();
    for part in bytes.chunks(fragment) {
        if frames.feed(part).is_err() {
            break;
        }
        while let Ok(Some(event)) = frames.poll() {
            if control.receive(&event).is_err() {
                break;
            }
        }
    }
    let Ok(shared) = Shared::new(
        Config {
            max_frame_size: rama_utils::octets::kib(4),
            read_chunk_size: 32,
            ..Config::default()
        },
        role,
        Default::default(),
    ) else {
        return;
    };
    let mut reader = Reader::new(
        Fragmented {
            bytes,
            fragment,
            pending: false,
        },
        shared,
        0,
    );
    reader.phase = match input[1] % 4 {
        0 => Phase::Headers,
        1 => Phase::Body,
        2 => Phase::Trailers,
        _ => Phase::Tunnel,
    };
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..input
        .len()
        .saturating_mul(4)
        .min(rama_utils::octets::mib(1))
    {
        match reader.poll_event(&mut cx) {
            Poll::Ready(Ok(Some(FrameEvent::Headers(_)))) => {
                reader.phase = if reader.phase == Phase::Headers {
                    Phase::Body
                } else {
                    Phase::Trailers
                };
            }
            Poll::Ready(Err(_) | Ok(None)) => break,
            _ => (),
        }
    }
    // Abandoning a partial stream exercises STOP and queued QPACK cancellation.
}

// Correlated field sections exercise the live Shared decoder waiters, output
// reservations, cancellation retries and partial instruction delivery together.
#[expect(
    clippy::unwrap_used,
    reason = "correlated valid streams must succeed or explicitly exhaust their budget"
)]
fn compression_schedule(input: &[u8]) {
    use super::qpack::{DecoderConfig, Encoder, EncoderConfig};
    use rama_core::bytes::{Buf as _, BytesMut};
    use std::{future::Future, pin::Pin};
    let shared = Shared::new(
        Config {
            decoder: DecoderConfig {
                max_decoder_stream_bytes: 10,
                ..DecoderConfig::default()
            },
            max_requests: 4,
            ..Config::default()
        },
        Role::Server,
        Default::default(),
    )
    .unwrap();
    let mut encoder = Encoder::new(EncoderConfig {
        max_blocked_streams: 4,
        ..EncoderConfig::default()
    });
    let mut forward = BytesMut::new();
    let mut feedback = Bytes::new();
    let mut pending: [Option<Pin<Box<dyn Future<Output = _>>>>; 4] = std::array::from_fn(|_| None);
    let mut ids = [0, 4, 8, 12];
    let mut cx = Context::from_waker(Waker::noop());
    for &operation in input.iter().take(1024) {
        let slot = usize::from(operation >> 6);
        match operation & 3 {
            0 if pending[slot].is_none() && forward.len() < rama_utils::octets::kib(4) => {
                let section = encoder
                    .encode(ids[slot], [("x-scheduled", "repeated dynamic value")])
                    .unwrap();
                forward.extend_from_slice(&encoder.take_encoder_stream());
                pending[slot] = Some(Box::pin(shared.decode(ids[slot], section)));
            }
            1 if !forward.is_empty() => {
                let len = forward.len().min(usize::from((operation >> 2) & 7) + 1);
                if !shared
                    .feed_instructions(StreamType::QPACK_ENCODER, &forward[..len])
                    .unwrap()
                {
                    forward.advance(len);
                }
            }
            2 => {
                if feedback.is_empty() {
                    feedback = shared.take_output(false).unwrap();
                }
                let len = feedback.len().min(usize::from((operation >> 2) & 7) + 1);
                encoder
                    .feed_decoder_stream(&feedback.split_to(len))
                    .unwrap();
                shared.decoder_output_written(len).unwrap();
            }
            3 if pending[slot].is_some() => {
                pending[slot] = None;
                shared.cancel(ids[slot]);
                ids[slot] += 16;
            }
            _ => (),
        }
        if let Some(error) = shared.error() {
            assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
            return;
        }
        for slot in 0..4 {
            if let Some(future) = &mut pending[slot]
                && let Poll::Ready(fields) = future.as_mut().poll(&mut cx)
            {
                let fields = fields.unwrap();
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].value, "repeated dynamic value");
                pending[slot] = None;
                ids[slot] += 16;
            }
        }
    }
    for slot in 0..4 {
        pending[slot] = None;
        shared.cancel(ids[slot]);
        if let Some(error) = shared.error() {
            assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
            return;
        }
    }
    // Drain withheld transport bytes before pending cancellation output. Each
    // drain releases the exact reservation held by the live connection code.
    loop {
        if feedback.is_empty() {
            feedback = shared.take_output(false).unwrap();
        }
        if feedback.is_empty() {
            break;
        }
        let len = feedback.len();
        encoder.feed_decoder_stream(&feedback).unwrap();
        feedback = Bytes::new();
        shared.decoder_output_written(len).unwrap();
    }
    assert_eq!(encoder.tracked_section_count(), 0);
    assert_eq!(encoder.tracked_reference_count(), 0);
}
