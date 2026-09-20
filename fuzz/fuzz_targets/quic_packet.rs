#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::quic::fuzzing::PacketParams;
use rama::quic::proto::{
    Version,
    packet::{FixedLengthConnectionIdParser, PartialDecode},
};

fuzz_target!(|data: PacketParams| {
    let len = data.buf.len();
    let supported_versions = [Version::V1, Version::V2];
    if let Ok(decoded) = PartialDecode::new(
        data.buf,
        &FixedLengthConnectionIdParser::new(data.local_cid_len),
        &supported_versions,
        data.grease_quic_bit,
    ) {
        match decoded.1 {
            Some(x) => assert_eq!(len, decoded.0.len() + x.len()),
            None => assert_eq!(len, decoded.0.len()),
        }
    }
});
