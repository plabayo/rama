#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::http::proto::h3::qpack::{
    DecoderInstruction, EncoderInstruction, FieldLine, HeaderPrefix,
};

// Exercise the QPACK representation decoders directly: encoder- and decoder-stream instructions,
// the field-section prefix, and field-line representations. Decoding must never panic or
// over-allocate; a successful decode of each unit must re-encode to bytes that decode identically.
fuzz_target!(|data: &[u8]| {
    // encoder-stream instructions
    {
        let mut cursor = data;
        while let Ok(inst) = EncoderInstruction::decode(&mut cursor, 4096) {
            let mut buf = rama::bytes::BytesMut::new();
            inst.encode(&mut buf);
            let mut again = &buf[..];
            let round = EncoderInstruction::decode(&mut again, 4096).expect("re-decode");
            assert_eq!(inst, round);
        }
    }
    // decoder-stream instructions
    {
        let mut cursor = data;
        while let Ok(inst) = DecoderInstruction::decode(&mut cursor) {
            let mut buf = rama::bytes::BytesMut::new();
            inst.encode(&mut buf);
            let mut again = &buf[..];
            let round = DecoderInstruction::decode(&mut again).expect("re-decode");
            assert_eq!(inst, round);
        }
    }
    // field-line representations
    {
        let mut cursor = data;
        while let Ok(line) = FieldLine::decode(&mut cursor, 4096) {
            let mut buf = rama::bytes::BytesMut::new();
            line.encode(&mut buf);
            let mut again = &buf[..];
            let round = FieldLine::decode(&mut again, 4096).expect("re-decode");
            assert_eq!(line, round);
        }
    }
    // field-section prefix
    {
        let mut cursor = data;
        let _ = HeaderPrefix::decode(&mut cursor, 64, 100);
    }
});
