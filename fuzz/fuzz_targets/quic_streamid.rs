#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use rama::quic::proto::{Dir, MAX_STREAM_COUNT, Side, StreamId, VarInt};

#[derive(Arbitrary, Debug)]
struct StreamIdParams {
    side: Side,
    dir: Dir,
    index: u64,
}

fuzz_target!(|data: StreamIdParams| {
    // The constructor takes a 60-bit stream index, not an arbitrary u64.
    let index = data.index % MAX_STREAM_COUNT;
    let s = StreamId::new(data.side, data.dir, index);
    assert_eq!(s.initiator(), data.side);
    assert_eq!(s.dir(), data.dir);
    assert_eq!(s.index(), index);
    assert_eq!(StreamId::from(VarInt::from(s)), s);
});
