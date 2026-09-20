#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::http::core::h3::frame::{DEFAULT_MAX_FRAME_SIZE, FrameDecoder};

// Feed arbitrary bytes to the bounded incremental frame decoder and drain events until it needs
// more input or errors. The decoder must never allocate an unbounded amount, panic or loop.
fuzz_target!(|data: &[u8]| {
    let mut dec = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
    // deliver in a few chunks to exercise fragmentation across the state machine
    for chunk in data.chunks(7) {
        if dec.feed(chunk).is_err() {
            return;
        }
        loop {
            match dec.poll() {
                Ok(Some(_event)) => continue,
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
    let _ = dec.is_at_frame_boundary();
});
