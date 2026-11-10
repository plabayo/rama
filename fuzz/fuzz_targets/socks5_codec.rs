//! SOCKS5 message decoding fuzz target.
//!
//! Goals: arbitrary bytes never panic any SOCKS5 message reader, and every
//! decoded message encodes to bytes that decode to the same message.
//!
//! Run with:
//!     cargo +nightly fuzz run socks5_codec -- -max_len=1024
#![expect(
    clippy::panic,
    reason = "a violated fuzz invariant must produce a crash artifact"
)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::proxy::socks5::proto::{client, server, udp::UdpHeader};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Polls a future over in-memory IO once; it never needs to wait.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("in-memory socks5 io pending"),
    }
}

macro_rules! roundtrip {
    ($ty:ty, $data:expr) => {{
        let mut input: &[u8] = $data;
        if let Ok(message) = ready(<$ty>::read_from(&mut input)) {
            let mut encoded = Vec::new();
            if ready(message.write_to(&mut encoded)).is_ok() {
                let mut encoded_input: &[u8] = &encoded;
                match ready(<$ty>::read_from(&mut encoded_input)) {
                    Ok(again) if again == message => {}
                    other => panic!(
                        "{} does not round trip: {message:?} -> {other:?}",
                        stringify!($ty)
                    ),
                }
            }
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    roundtrip!(client::Header, data);
    roundtrip!(client::Request, data);
    roundtrip!(client::UsernamePasswordRequest, data);
    roundtrip!(server::Header, data);
    roundtrip!(server::Reply, data);
    roundtrip!(server::UsernamePasswordResponse, data);
    let mut input = data;
    _ = std::hint::black_box(UdpHeader::read_from_sync(&mut input));
});
