//! Bounded synchronous fuzz entry points for transport-independent H3 state.

use super::{
    Error,
    connection::{Config, Shared},
    control::{Control, Role},
    datagram::{AbortRequest, DatagramConfig, DatagramLimits, Demux, ReceiveEnd, Semantics},
    frame::{FrameDecoder, FrameEvent},
    quic::RecvStream,
    stream::{Phase, Reader},
};
use ahash::{HashMap, HashSet};
use rama_core::bytes::Bytes;
use rama_http::datagram::ViolationPolicy;
use rama_http_types::proto::h3::{Code, StreamType};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, atomic::AtomicBool},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::Instant;

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

/// Records the requests the demux aborted, for the harness to end their receive side.
#[derive(Clone)]
struct RecordAbort(u64, Rc<RefCell<Vec<u64>>>);

impl AbortRequest for RecordAbort {
    fn abort_request(&self) {
        self.1.borrow_mut().push(self.0);
    }
}

/// What the harness knows of each delivered datagram, keyed by its sequence number.
struct Sent {
    stream: u64,
    // Delivered after the stream's receive side ended: it must never be yielded.
    after_end: bool,
}

/// Drive the datagram demultiplexer with arbitrary driver and consumer events.
///
/// Every delivered datagram must end exactly once: yielded, counted as a drop, released with
/// its stream, or still held. Yields keep per-stream delivery order and never include a
/// datagram delivered after its stream's receive side ended; the byte accounting matches
/// what is held, within the limits.
#[expect(
    clippy::unwrap_used,
    reason = "fuzz oracle: a violated invariant must crash the target"
)]
pub fn datagram_demux(input: &[u8]) {
    let mut input = input.iter().copied();
    let mut next = move || input.next();
    let (Some(queue_len), Some(pending_len), Some(budget), Some(flags)) =
        (next(), next(), next(), next())
    else {
        return;
    };
    let config = DatagramConfig {
        limits: DatagramLimits {
            queue_len: usize::from(queue_len % 6),
            pending_len: usize::from(pending_len % 6),
            max_buffered_bytes: usize::from(budget) * 4,
        },
        violations: if flags & 1 == 0 {
            ViolationPolicy::Ignore
        } else {
            ViolationPolicy::Reject
        },
    };
    let lifetime = Duration::from_millis(100);
    let start = Instant::now();
    let mut elapsed = Duration::ZERO;
    let aborted = Rc::new(RefCell::new(Vec::new()));
    let mut demux: Demux<RecordAbort> = Demux::default();
    let mut sent: HashMap<u32, Sent> = HashMap::default();
    let mut ended: HashSet<u64> = HashSet::default();
    let mut last_yield: HashMap<u64, u32> = HashMap::default();
    let (mut delivered, mut yielded, mut released) = (0u64, 0u64, 0u64);
    let mut registered: HashSet<u64> = HashSet::default();
    let mut next_stream = 0u64;
    let waker = Waker::noop();
    let cx = Context::from_waker(waker);

    while let (Some(op), Some(arg)) = (next(), next()) {
        let stream = u64::from(arg % 8) * 4;
        let now = start + elapsed;
        let action = match op % 8 {
            0 => {
                let seq = u32::try_from(delivered).unwrap();
                let mut payload = seq.to_be_bytes().to_vec();
                payload.resize(4 + usize::from(op >> 3), 0);
                sent.insert(
                    seq,
                    Sent {
                        stream,
                        after_end: ended.contains(&stream),
                    },
                );
                delivered += 1;
                demux.deliver(&config, stream, Bytes::from(payload), now, lifetime)
            }
            // Streams register once, in order, as the driver sees them.
            1 if stream >= next_stream => {
                next_stream = stream + 4;
                registered.insert(stream);
                let semantics = match op >> 3 & 3 {
                    0 => Semantics::Provisional,
                    1 => Semantics::Claimed,
                    _ => Semantics::None,
                };
                let abort = RecordAbort(stream, aborted.clone());
                demux.register(
                    &config,
                    stream,
                    semantics,
                    abort,
                    Arc::new(AtomicBool::new(false)),
                    now,
                )
            }
            2 => demux.decide(&config, stream, op & 8 != 0),
            3 => {
                released += demux.queued(stream) as u64;
                registered.remove(&stream);
                _ = demux.unregister(stream);
                Default::default()
            }
            4 if registered.contains(&stream) => {
                let end = match op >> 3 & 3 {
                    0 => ReceiveEnd::Finished,
                    1 => ReceiveEnd::Reset(0),
                    2 => ReceiveEnd::Aborted(0),
                    _ => ReceiveEnd::Released,
                };
                ended.insert(stream);
                _ = demux.receive_ended(stream, end);
                Default::default()
            }
            5 => {
                if let Poll::Ready(Ok(Some(payload))) = demux.poll_recv(stream, &cx) {
                    let seq = u32::from_be_bytes(payload[..4].try_into().unwrap());
                    let origin = &sent[&seq];
                    assert_eq!(origin.stream, stream, "yielded for another stream");
                    assert!(!origin.after_end, "yielded after the receive side ended");
                    let last = last_yield.insert(stream, seq);
                    assert!(last.is_none_or(|last| last < seq), "out of delivery order");
                    yielded += 1;
                }
                Default::default()
            }
            6 => {
                ended.extend(registered.iter().copied());
                _ = demux.close();
                Default::default()
            }
            7 => {
                elapsed += Duration::from_millis(u64::from(arg) * 4);
                Default::default()
            }
            _ => Default::default(),
        };
        action.run();
        // An aborted request's receive side ends, as the stream abort makes it.
        for stream in aborted.borrow_mut().drain(..) {
            ended.insert(stream);
            _ = demux.receive_ended(stream, ReceiveEnd::Aborted(0));
        }

        demux.assert_consistent(&config.limits);
        let drops = demux.drops();
        let dropped = drops.no_semantics
            + drops.invalid_id
            + drops.beyond_limit
            + drops.unknown_stream
            + drops.receive_closed
            + drops.queue_full
            + drops.over_budget
            + drops.expired;
        let held: usize = registered.iter().map(|stream| demux.queued(*stream)).sum();
        let held = (held + demux.pending_len()) as u64;
        assert_eq!(
            delivered,
            yielded + dropped + released + held,
            "a datagram was lost or counted twice"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::datagram_demux;

    /// The fuzz oracle over deterministic inputs, so its conservation checks run with every
    /// test pass and not only under a fuzzer.
    #[test]
    fn datagram_demux_sequences_keep_their_invariants() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..4000 {
            let len = usize::try_from(next() % 512).unwrap();
            let input: Vec<u8> = (0..len.div_ceil(8))
                .flat_map(|_| next().to_le_bytes())
                .take(len)
                .collect();
            datagram_demux(&input);
        }
    }
}
