#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::bytes::Bytes;
use rama::http::datagram::capsule::{CapsuleConfig, CapsuleDecoder, CapsuleEvent, UnknownCapsules};
use rama::http::proto::capsule::CapsuleType;

// Any fragmentation of the data stream must yield the same capsules and truncation verdict
// as an independent whole-input parse (RFC 9297 §3.2), never buffering beyond the limits.
fuzz_target!(|data: &[u8]| {
    let Some((&shape, stream)) = data.split_first() else {
        return;
    };
    let config = CapsuleConfig {
        max_datagram_size: 64,
        max_capsule_size: 32,
        capsule_types: Box::new([CapsuleType::new(0x01).unwrap()]),
        unknown: if shape & 1 == 0 {
            UnknownCapsules::Skip
        } else {
            UnknownCapsules::Forward
        },
    };
    let chunk = usize::from(shape >> 1).max(1);
    let whole = decode(config.clone(), &[stream]);
    assert_eq!(whole, reference(&config, stream));
    let pieces: Vec<&[u8]> = stream.chunks(chunk).collect();
    assert_eq!(decode(config, &pieces), whole);
});

/// A QUIC variable-length integer (RFC 9000 §16), or `None` when the input ends inside it.
fn varint(input: &mut &[u8]) -> Option<u64> {
    let first = *input.first()?;
    let len = 1usize << (first >> 6);
    let bytes = input.get(..len)?;
    *input = &input[len..];
    Some(
        bytes[1..]
            .iter()
            .fold(u64::from(first & 0x3f), |value, byte| (value << 8) | u64::from(*byte)),
    )
}

/// The events and verdict a conforming decoder yields for the whole stream at once.
fn reference(config: &CapsuleConfig, mut input: &[u8]) -> (Vec<(u64, Vec<u8>)>, Option<bool>) {
    let mut events = Vec::new();
    while !input.is_empty() {
        let (Some(ty), Some(length)) = (varint(&mut input), varint(&mut input)) else {
            return (events, Some(false));
        };
        let registered = config.capsule_types.iter().any(|known| known.value() == ty);
        // A registered control capsule over the limit is refused as soon as its length is known.
        if registered && length > config.max_capsule_size as u64 {
            return (events, None);
        }
        let Some(value) = usize::try_from(length).ok().and_then(|len| input.get(..len)) else {
            // Forwarded unknown capsules stream out whatever arrived before the end.
            if !registered && ty != 0 && config.unknown == UnknownCapsules::Forward {
                events.push((ty, input.to_vec()));
            }
            return (events, Some(false));
        };
        input = &input[value.len()..];
        match ty {
            0 if value.len() <= config.max_datagram_size => events.push((0, value.to_vec())),
            // Oversized DATAGRAM capsules are discarded (RFC 9297 §3.5).
            0 => (),
            _ if registered => events.push((ty, value.to_vec())),
            _ if config.unknown == UnknownCapsules::Forward => events.push((ty, value.to_vec())),
            _ => (),
        }
    }
    (events, Some(true))
}

fn decode(config: CapsuleConfig, chunks: &[&[u8]]) -> (Vec<(u64, Vec<u8>)>, Option<bool>) {
    let limit = config.max_datagram_size.max(config.max_capsule_size);
    let mut decoder = CapsuleDecoder::new(config);
    let mut events: Vec<(u64, Vec<u8>)> = Vec::new();
    for chunk in chunks {
        decoder.feed(Bytes::copy_from_slice(chunk)).unwrap();
        loop {
            match decoder.poll() {
                Ok(Some(CapsuleEvent::Datagram(value))) => {
                    assert!(value.len() <= limit);
                    events.push((0, value.to_vec()));
                }
                Ok(Some(CapsuleEvent::Capsule { ty, value })) => {
                    assert!(value.len() <= limit);
                    events.push((ty.value(), value.to_vec()));
                }
                Ok(Some(CapsuleEvent::Unknown(header))) => {
                    events.push((header.ty.value(), Vec::new()));
                }
                Ok(Some(CapsuleEvent::UnknownData(data))) => {
                    events.last_mut().unwrap().1.extend_from_slice(&data);
                }
                Ok(None) => break,
                Err(_) => return (events, None),
            }
        }
    }
    let finished = decoder.finish().is_ok();
    (events, Some(finished))
}
