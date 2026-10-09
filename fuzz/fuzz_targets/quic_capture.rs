#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::quic::proto::capture;

fuzz_target!(|data: &[u8]| {
    if let Ok(observed) = capture::observe(data) {
        let mut previous_end = 0;
        for packet in observed.packets {
            assert_eq!(packet.range.start, previous_end);
            assert!(packet.range.end > packet.range.start);
            assert!(packet.range.end <= data.len());
            previous_end = packet.range.end;
        }
        assert_eq!(previous_end + observed.trailing, data.len());
    }
    if let Ok(parameters) = capture::transport_parameters(data) {
        let _ = capture::version_information(&parameters);
    }
});
