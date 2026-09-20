#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama_http_types::proto::h3::Settings;

// Decode an arbitrary SETTINGS payload; on success it must re-encode to a payload that decodes to
// the same settings (valid inputs round-trip; invalid inputs return an error without panicking).
fuzz_target!(|data: &[u8]| {
    if let Ok(settings) = Settings::decode(data) {
        let mut buf = rama_core::bytes::BytesMut::new();
        if settings.encode_payload(&mut buf).is_some() {
            let reparsed = Settings::decode(&buf).expect("re-encoded settings must decode");
            assert_eq!(settings, reparsed);
        }
    }
});
