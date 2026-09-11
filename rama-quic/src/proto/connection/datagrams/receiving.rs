//! What the receive side does with a DATAGRAM frame that arrives.
//!
//! The advertised `max_datagram_frame_size` bounds the encoded frame (RFC 9221 §3); what
//! holding one costs here is a separate matter. Frames are built and parsed rather than
//! described, so a case exercises the size that was really on the wire.

use super::*;
use crate::proto::{
    TransportErrorCode,
    frame::{Frame, Iter},
};

/// How a built frame carries its payload length.
#[derive(Clone, Copy)]
enum Length {
    /// No LEN: the frame runs to the end of the packet (type 0x30).
    Absent,
    /// A LEN varint of this many bytes. QUIC allows 1, 2, 4 or 8, and a wider one than the
    /// value needs is legal (RFC 9000 §16).
    Of(usize),
}

/// Build a DATAGRAM frame and read it back through the parser, so its measured size is the
/// one the decoder saw.
fn parse(payload: usize, length: Length) -> ArrivedDatagram {
    let mut buf = Vec::new();
    match length {
        Length::Absent => buf.push(0x30),
        Length::Of(width) => {
            buf.push(0x31);
            buf.extend_from_slice(&varint(payload as u64, width));
        }
    }
    buf.extend(std::iter::repeat_n(0xd1, payload));

    let frames: Vec<_> = Iter::new(Bytes::from(buf))
        .expect("the packet holds frames")
        .collect::<Result<Vec<_>, _>>()
        .expect("the frame parses");
    match frames.into_iter().next().expect("one frame") {
        Frame::Datagram(arrived) => arrived,
        other => panic!("a datagram was built, not {other:?}"),
    }
}

/// `value` as a QUIC varint in `width` bytes, which may be wider than it needs.
fn varint(value: u64, width: usize) -> Vec<u8> {
    let prefix = match width {
        1 => 0b00,
        2 => 0b01,
        4 => 0b10,
        8 => 0b11,
        other => panic!("{other} is not a varint width"),
    };
    let mut bytes = value.to_be_bytes()[8 - width..].to_vec();
    bytes[0] |= prefix << 6;
    bytes
}

/// The bytes a minimal encoding of this payload occupies.
fn minimal(payload: usize) -> usize {
    parse(payload, Length::Of(if payload < 64 { 1 } else { 2 })).encoded
}

fn refused(state: &mut DatagramState, arrived: ArrivedDatagram, window: usize) -> TransportError {
    state
        .received(arrived, Some(window))
        .expect_err("a frame over the advertised size is refused")
}

#[test]
fn a_frame_exactly_at_the_advertised_size_is_not_a_protocol_error() {
    // The budget bounds the frame and the storage alike, and an entry costs more than the
    // payload, so a frame of exactly the advertised size never fits. It is dropped, and
    // dropping is not the peer's error.
    let mut state = DatagramState::default();
    let payload = 200;
    let advertised = minimal(payload);
    let taken = state
        .received(parse(payload, Length::Of(2)), Some(advertised))
        .expect("a frame of exactly the advertised size is not a protocol error");
    assert!(!taken, "there was no room for it");
}

#[test]
fn a_frame_is_delivered_when_there_is_room_for_it() {
    let mut state = DatagramState::default();
    let payload = 200;
    let taken = state
        .received(parse(payload, Length::Of(2)), Some(4096))
        .expect("a frame inside the advertised size is not a protocol error");
    assert!(taken, "the reader is woken");
    assert_eq!(state.incoming.queue.len(), 1, "and it is queued");
    assert_eq!(
        state.incoming.queue[0].data.len(),
        payload,
        "with the payload that arrived"
    );
}

#[test]
fn a_frame_one_byte_over_the_advertised_size_is_a_protocol_violation() {
    let mut state = DatagramState::default();
    let payload = 200;
    let advertised = minimal(payload) - 1;
    let error = refused(&mut state, parse(payload, Length::Of(2)), advertised);
    assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
}

#[test]
fn a_wider_length_that_crosses_the_size_is_a_protocol_violation() {
    // The same payload, inside the advertised size when its length is written minimally and
    // over it when written in a legal wider varint. The frame on the wire is what counts.
    let payload = 200;
    let advertised = minimal(payload) + 1;
    let mut state = DatagramState::default();
    state
        .received(parse(payload, Length::Of(2)), Some(advertised))
        .expect("the minimal encoding fits");

    let wider = parse(payload, Length::Of(8));
    assert!(
        wider.encoded > advertised,
        "the wider length takes it over: {} against {advertised}",
        wider.encoded
    );
    let mut state = DatagramState::default();
    let error = refused(&mut state, wider, advertised);
    assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
}

#[test]
fn a_frame_without_a_length_is_measured_by_what_it_occupied() {
    let payload = 200;
    let arrived = parse(payload, Length::Absent);
    assert_eq!(
        arrived.encoded,
        1 + payload,
        "a type byte and the payload, with no length between them"
    );
    let mut state = DatagramState::default();
    let error = refused(
        &mut state,
        parse(payload, Length::Absent),
        arrived.encoded - 1,
    );
    assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
}

#[test]
fn a_frame_the_peer_may_send_is_not_a_protocol_error_for_want_of_room() {
    // Inside the advertised size on the wire, too large to hold once entry storage counts.
    let mut state = DatagramState::default();
    let payload = 250;
    let taken = state
        .received(parse(payload, Length::Of(2)), Some(256))
        .expect("a frame that will not fit is dropped, not fatal");
    assert!(!taken, "nothing was queued, so no reader is woken");
    assert!(state.incoming.queue.is_empty(), "and the queue stays empty");
}

#[test]
fn a_frame_too_large_for_an_empty_queue_leaves_what_is_queued() {
    let mut state = DatagramState::default();
    state
        .received(parse(16, Length::Of(1)), Some(256))
        .expect("a small datagram is queued");
    state
        .received(parse(250, Length::Of(2)), Some(256))
        .expect("one that cannot fit is dropped, not fatal");
    assert_eq!(
        state.incoming.queue.len(),
        1,
        "the readable datagram was kept"
    );
    assert_eq!(
        state.incoming.queue[0].data.len(),
        16,
        "and it is the one that arrived first"
    );
}

#[test]
fn a_zero_length_datagram_is_taken_and_is_not_disabled_support() {
    let mut state = DatagramState::default();
    state
        .received(parse(0, Length::Of(1)), Some(256))
        .expect("an empty datagram is valid");
    assert_eq!(state.incoming.queue.len(), 1, "and it is queued");
    let error = state
        .received(parse(0, Length::Of(1)), None)
        .expect_err("while no budget at all means the extension was never offered");
    assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
}
