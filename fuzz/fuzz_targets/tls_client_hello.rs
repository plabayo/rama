//! TLS ClientHello parsing fuzz target.
//!
//! Goals: arbitrary bytes never panic the record, handshake or prefix parsers,
//! and every fingerprint computed from a parsed ClientHello stays panic free.
//!
//! Run with:
//!     cargo +nightly fuzz run tls_client_hello -- -max_len=65536
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::tls::client::{
    ClientHello, parse_client_hello, parse_client_hello_handshake,
    parse_client_hello_handshake_prefix,
};
use rama::tls::fingerprint::{Ja3, Ja4, PeetPrint};

fn fingerprints(hello: &ClientHello) {
    _ = std::hint::black_box(Ja3::compute_from_client_hello(hello).map(|ja3| ja3.to_string()));
    _ = std::hint::black_box(Ja4::compute_from_client_hello(hello).map(|ja4| ja4.to_string()));
    _ = std::hint::black_box(
        PeetPrint::compute_from_client_hello(hello).map(|peet| peet.to_string()),
    );
}

fuzz_target!(|data: &[u8]| {
    if let Ok(hello) = parse_client_hello(data) {
        fingerprints(&hello);
    }
    if let Ok(hello) = parse_client_hello_handshake(data) {
        fingerprints(&hello);
    }
    _ = std::hint::black_box(parse_client_hello_handshake_prefix(data));
});
