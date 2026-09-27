use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const CONTROL: CapsuleType = match CapsuleType::new(0x1234) {
    Ok(ty) => ty,
    Err(_) => panic!("valid capsule type"),
};
const OTHER: CapsuleType = match CapsuleType::new(0x4242) {
    Ok(ty) => ty,
    Err(_) => panic!("valid capsule type"),
};

fn config(unknown: UnknownCapsules) -> CapsuleConfig {
    CapsuleConfig {
        max_datagram_size: 32,
        max_capsule_size: 16,
        capsule_types: Box::new([CONTROL]),
        unknown,
    }
}

fn capsule(ty: CapsuleType, value: &[u8]) -> Vec<u8> {
    encode_capsule(ty, value).unwrap().to_vec()
}

/// Events with forwarded value chunks joined, so any fragmentation compares equal.
#[derive(Debug, PartialEq, Eq)]
enum Normalized {
    Datagram(Vec<u8>),
    Capsule(CapsuleType, Vec<u8>),
    Unknown(CapsuleType, u64, Vec<u8>),
}

fn decode_chunks(config: CapsuleConfig, chunks: &[&[u8]]) -> (Vec<Normalized>, CapsuleDecoder) {
    let mut decoder = CapsuleDecoder::new(config);
    let mut events = Vec::new();
    for chunk in chunks {
        decoder.feed(Bytes::copy_from_slice(chunk)).unwrap();
        while let Some(event) = decoder.poll().unwrap() {
            match event {
                CapsuleEvent::Datagram(value) => events.push(Normalized::Datagram(value.to_vec())),
                CapsuleEvent::Capsule { ty, value } => {
                    events.push(Normalized::Capsule(ty, value.to_vec()));
                }
                CapsuleEvent::Unknown(header) => events.push(Normalized::Unknown(
                    header.ty,
                    header.length.into_inner(),
                    Vec::new(),
                )),
                CapsuleEvent::UnknownData(data) => match events.last_mut() {
                    Some(Normalized::Unknown(_, _, value)) => value.extend_from_slice(&data),
                    other => panic!("data without header: {other:?}"),
                },
            }
        }
        assert!(decoder.is_drained());
    }
    (events, decoder)
}

fn stream() -> Vec<u8> {
    [
        capsule(CapsuleType::DATAGRAM, b"first"),
        capsule(CapsuleType::DATAGRAM, b""),
        capsule(CONTROL, b"control"),
        capsule(OTHER, b"unknown value"),
        capsule(CapsuleType::new(0x17).unwrap(), b"grease"),
        capsule(CONTROL, b""),
        capsule(CapsuleType::DATAGRAM, &[7; 32]),
    ]
    .concat()
}

#[test]
fn endpoint_skips_unknown_and_greasing_capsules() {
    let (events, decoder) = decode_chunks(config(UnknownCapsules::Skip), &[&stream()]);
    assert_eq!(
        events,
        [
            Normalized::Datagram(b"first".to_vec()),
            Normalized::Datagram(Vec::new()),
            Normalized::Capsule(CONTROL, b"control".to_vec()),
            Normalized::Capsule(CONTROL, Vec::new()),
            Normalized::Datagram(vec![7; 32]),
        ]
    );
    decoder.finish().unwrap();
}

#[test]
fn intermediary_forwards_unknown_capsules_unmodified() {
    let (events, _) = decode_chunks(config(UnknownCapsules::Forward), &[&stream()]);
    let unknown: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Normalized::Unknown(ty, length, value) => Some((*ty, *length, value.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        unknown,
        [
            (OTHER, 13, b"unknown value".to_vec()),
            (CapsuleType::new(0x17).unwrap(), 6, b"grease".to_vec()),
        ]
    );
}

#[test]
fn every_fragmentation_produces_the_same_events() {
    let stream = stream();
    for unknown in [UnknownCapsules::Skip, UnknownCapsules::Forward] {
        let (expected, _) = decode_chunks(config(unknown), &[&stream]);
        let bytes: Vec<&[u8]> = stream.chunks(1).collect();
        assert_eq!(decode_chunks(config(unknown), &bytes).0, expected);
        for first in 0..=stream.len() {
            for second in first..=stream.len() {
                let (events, decoder) = decode_chunks(
                    config(unknown),
                    &[&stream[..first], &stream[first..second], &stream[second..]],
                );
                assert_eq!(events, expected, "split at {first}/{second}");
                decoder.finish().unwrap();
            }
        }
    }
}

#[test]
fn non_minimal_integers_are_accepted() {
    // DATAGRAM type as a 2-byte varint and length 3 as an 8-byte varint.
    let mut wire = vec![0x40, 0x00, 0xc0, 0, 0, 0, 0, 0, 0, 3];
    wire.extend_from_slice(b"abc");
    let (events, _) = decode_chunks(config(UnknownCapsules::Skip), &[&wire]);
    assert_eq!(events, [Normalized::Datagram(b"abc".to_vec())]);
}

#[test]
fn contiguous_values_share_input_storage() {
    let input = Bytes::from(stream());
    let mut decoder = CapsuleDecoder::new(config(UnknownCapsules::Skip));
    let start = input.as_ptr();
    decoder.feed(input).unwrap();
    let Some(CapsuleEvent::Datagram(first)) = decoder.poll().unwrap() else {
        panic!("expected datagram");
    };
    assert_eq!(first.as_ptr(), start.wrapping_add(2));
}

#[test]
fn oversized_datagrams_are_discarded_without_buffering() {
    let mut wire = CapsuleHeader::new(CapsuleType::DATAGRAM, VarInt::MAX.into_inner())
        .map(|header| {
            let mut encoded = BytesMut::new();
            header.encode(&mut encoded);
            encoded.to_vec()
        })
        .unwrap();
    let mut decoder = CapsuleDecoder::new(config(UnknownCapsules::Skip));
    assert_eq!(decoder.dropped_datagrams(), 0);
    decoder
        .feed(Bytes::from(std::mem::take(&mut wire)))
        .unwrap();
    // Fed but not yet polled.
    assert!(!decoder.is_drained());
    assert_eq!(decoder.poll().unwrap(), None);
    assert_eq!(decoder.dropped_datagrams(), 1);
    // A huge skipped body retains no memory while it streams past.
    for _ in 0..64 {
        decoder.feed(Bytes::from(vec![0; 4096])).unwrap();
        assert_eq!(decoder.poll().unwrap(), None);
        assert_eq!(decoder.value.capacity(), 0);
    }
    decoder.finish().unwrap_err();

    let (events, decoder) = decode_chunks(
        config(UnknownCapsules::Skip),
        &[&[
            capsule(CapsuleType::DATAGRAM, &[1; 33]),
            capsule(CapsuleType::DATAGRAM, b"next"),
            capsule(CapsuleType::DATAGRAM, &[2; 40]),
        ]
        .concat()],
    );
    assert_eq!(events, [Normalized::Datagram(b"next".to_vec())]);
    assert_eq!(decoder.dropped_datagrams(), 2);
}

#[test]
fn values_at_their_limits_are_delivered() {
    let (events, decoder) = decode_chunks(
        config(UnknownCapsules::Skip),
        &[&[
            capsule(CONTROL, &[3; 16]),
            capsule(CapsuleType::DATAGRAM, &[4; 32]),
        ]
        .concat()],
    );
    assert_eq!(
        events,
        [
            Normalized::Capsule(CONTROL, vec![3; 16]),
            Normalized::Datagram(vec![4; 32])
        ]
    );
    assert_eq!(decoder.dropped_datagrams(), 0);
}

#[test]
fn oversized_control_capsules_fail_before_their_value_arrives() {
    let mut header = BytesMut::new();
    CapsuleHeader::new(CONTROL, 17).unwrap().encode(&mut header);
    let mut decoder = CapsuleDecoder::new(config(UnknownCapsules::Skip));
    decoder.feed(header.freeze()).unwrap();
    assert_eq!(
        decoder.poll(),
        Err(CapsuleError::TooLarge {
            ty: CONTROL,
            length: 17
        })
    );
    assert_eq!(decoder.value.capacity(), 0);
}

#[test]
fn truncation_is_detected_at_every_offset() {
    let stream = stream();
    let mut boundaries = vec![0];
    let mut offset = 0;
    for piece in [
        capsule(CapsuleType::DATAGRAM, b"first"),
        capsule(CapsuleType::DATAGRAM, b""),
        capsule(CONTROL, b"control"),
        capsule(OTHER, b"unknown value"),
        capsule(CapsuleType::new(0x17).unwrap(), b"grease"),
        capsule(CONTROL, b""),
        capsule(CapsuleType::DATAGRAM, &[7; 32]),
    ] {
        offset += piece.len();
        boundaries.push(offset);
    }
    for end in 0..=stream.len() {
        for unknown in [UnknownCapsules::Skip, UnknownCapsules::Forward] {
            let (_, decoder) = decode_chunks(config(unknown), &[&stream[..end]]);
            assert_eq!(
                decoder.finish().is_ok(),
                boundaries.contains(&end),
                "end at {end}"
            );
        }
    }
    // A partial type integer alone is also truncation.
    let (_, decoder) = decode_chunks(config(UnknownCapsules::Skip), &[&[0x40]]);
    assert_eq!(decoder.finish(), Err(CapsuleError::Truncated));
}

#[test]
fn undrained_input_is_rejected_without_loss() {
    let mut decoder = CapsuleDecoder::new(config(UnknownCapsules::Skip));
    let wire = [capsule(CONTROL, b"a"), capsule(CONTROL, b"b")].concat();
    decoder.feed(Bytes::from(wire)).unwrap();
    assert_eq!(
        decoder.feed(Bytes::from_static(b"x")),
        Err(CapsuleError::InputNotDrained)
    );
    assert!(matches!(
        decoder.poll(),
        Ok(Some(CapsuleEvent::Capsule { .. }))
    ));
    assert!(matches!(
        decoder.poll(),
        Ok(Some(CapsuleEvent::Capsule { .. }))
    ));
    assert_eq!(decoder.poll(), Ok(None));
    decoder.feed(Bytes::new()).unwrap();
}

#[test]
fn encoding_matches_the_wire_format() {
    assert_eq!(
        &encode_capsule(CapsuleType::DATAGRAM, b"ab").unwrap()[..],
        b"\x00\x02ab"
    );
    assert_eq!(&encode_capsule(CONTROL, b"").unwrap()[..], b"\x52\x34\x00");
}

/// Deliver one capsule fed in `chunk`-sized pieces and return its value.
fn deliver(decoder: &mut CapsuleDecoder, wire: &[u8], chunk: usize) -> Bytes {
    let mut delivered = None;
    for piece in wire.chunks(chunk) {
        decoder.feed(Bytes::copy_from_slice(piece)).unwrap();
        while let Some(event) = decoder.poll().unwrap() {
            if let CapsuleEvent::Capsule { value, .. } | CapsuleEvent::Datagram(value) = event {
                delivered = Some(value);
            }
        }
    }
    delivered.unwrap()
}

#[test]
fn delivered_values_own_their_storage() {
    let big = CapsuleConfig {
        max_capsule_size: 64 * 1024,
        ..config(UnknownCapsules::Skip)
    };
    let large = capsule(CONTROL, &vec![5; 64 * 1024]);
    let small = capsule(CONTROL, &[6; 16]);
    let mut decoder = CapsuleDecoder::new(big);
    // Repeated equal sizes, fragmented: each value is the only owner of its storage, so
    // dropping it frees everything the decoder allocated for it.
    for _ in 0..4 {
        let value = deliver(&mut decoder, &large, 1400);
        assert!(value.is_unique());
    }
    // A small value after a large one keeps no large buffer alive either.
    let value = deliver(&mut decoder, &large, 1400);
    drop(value);
    let value = deliver(&mut decoder, &small, 4);
    assert!(value.is_unique());
    // Contiguous input: the value is a slice of the fed chunk, which the decoder releases.
    let value = deliver(&mut decoder, &large, large.len());
    assert!(value.is_unique());
}

/// Counts drops of the storage behind fed input.
struct Owned(Vec<u8>, Arc<AtomicUsize>);

impl AsRef<[u8]> for Owned {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        self.1.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn skipped_input_is_released_once_consumed() {
    let unknown = capsule(CapsuleType::new(0x2d).unwrap(), &[1; 40]);
    let oversized = capsule(CapsuleType::DATAGRAM, &[2; 40]);
    for wire in [unknown, oversized] {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut decoder = CapsuleDecoder::new(config(UnknownCapsules::Skip));
        decoder
            .feed(Bytes::from_owner(Owned(wire, dropped.clone())))
            .unwrap();
        assert_eq!(decoder.poll().unwrap(), None);
        decoder.finish().unwrap();
        // Skipped to the end: the decoder no longer holds the input.
        assert_eq!(dropped.load(Ordering::Acquire), 1);
    }
}
