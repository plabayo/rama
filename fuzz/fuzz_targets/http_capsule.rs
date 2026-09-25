#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::bytes::Bytes;
use rama::http::datagram::capsule::{CapsuleConfig, CapsuleDecoder, CapsuleEvent, UnknownCapsules};
use rama::http::proto::capsule::CapsuleType;

// Differential check: any fragmentation of the data stream must yield the same capsules,
// the same truncation verdict and never buffer beyond the configured limits.
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
    let pieces: Vec<&[u8]> = stream.chunks(chunk).collect();
    assert_eq!(decode(config, &pieces), whole);
});

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
