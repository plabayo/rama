use std::assert_matches;

use super::*;

/// A ClientHello handshake message of `len` bytes in total, with a recognizable body.
fn message(len: usize) -> Vec<u8> {
    let body = len - 4;
    let mut message = vec![0x01, (body >> 16) as u8, (body >> 8) as u8, body as u8];
    message.extend((0..body).map(|index| index as u8));
    message
}

fn limits(client_hello_bytes: usize, crypto_fragments: usize) -> CaptureLimits {
    CaptureLimits {
        client_hello_bytes,
        crypto_fragments,
        ..CaptureLimits::default()
    }
}

fn assemble(fragments: &[(usize, &[u8])], limits: &CaptureLimits) -> Result<Vec<u8>, CaptureError> {
    let mut assembly = ClientHelloAssembly::new(limits);
    for &(offset, data) in fragments {
        assembly.take_in(offset as u64, data)?;
    }
    assembly
        .client_hello()
        .map(<[u8]>::to_vec)
        .ok_or(CaptureError::Malformed("incomplete"))
}

#[test]
fn fragments_in_any_order_and_repeated_yield_the_message() {
    let hello = message(100);
    let (a, rest) = hello.split_at(3);
    let (b, c) = rest.split_at(50);
    let orders: [&[(usize, &[u8])]; 4] = [
        &[(0, a), (3, b), (53, c)],
        &[(53, c), (3, b), (0, a)],
        &[(3, b), (0, a), (3, b), (53, c), (0, &hello)],
        &[(0, &hello)],
    ];
    for fragments in orders {
        assert_eq!(
            assemble(fragments, &CaptureLimits::default()).unwrap(),
            hello
        );
    }
}

#[test]
fn a_gap_leaves_the_message_incomplete() {
    let hello = message(100);
    let mut assembly = ClientHelloAssembly::new(&CaptureLimits::default());
    assembly.take_in(0, &hello[..40]).unwrap();
    assembly.take_in(60, &hello[60..]).unwrap();
    assert!(assembly.client_hello().is_none());
    assert_eq!(assembly.received(), &hello[..40]);
    assembly.take_in(40, &hello[40..60]).unwrap();
    assert_eq!(assembly.client_hello().unwrap(), hello);
}

#[test]
fn every_byte_seen_twice_must_agree() {
    let hello = message(100);
    let mut changed = hello.clone();
    changed[70] ^= 1;
    // Against the contiguous stream, against held data, and after completion.
    let cases: [&[(usize, &[u8])]; 3] = [
        &[(0, &hello[..80]), (60, &changed[60..])],
        &[
            (60, &hello[60..]),
            (60, &changed[60..90]),
            (0, &hello[..60]),
        ],
        &[(0, &hello), (70, &changed[70..71])],
    ];
    for fragments in cases {
        assert_matches!(
            assemble(fragments, &CaptureLimits::default()),
            Err(CaptureError::Malformed("conflicting CRYPTO overlap"))
        );
    }
}

#[test]
fn data_past_the_message_is_ignored() {
    let hello = message(100);
    let mut stream = hello.clone();
    stream.extend_from_slice(&[0xff; 64]);
    let fragments: [(usize, &[u8]); 2] = [(0, &stream), (120, &[0xee; 8])];
    assert_eq!(
        assemble(&fragments, &CaptureLimits::default()).unwrap(),
        hello
    );
}

#[test]
fn only_a_client_hello_is_assembled() {
    let mut not_hello = message(100);
    not_hello[0] = 0x02;
    assert_matches!(
        assemble(&[(0, &not_hello)], &CaptureLimits::default()),
        Err(CaptureError::Malformed("expected ClientHello"))
    );
}

#[test]
fn the_message_and_held_fragments_are_bounded() {
    let hello = message(100);
    for (limit, fits) in [(99, false), (100, true), (101, true)] {
        let result = assemble(&[(0, &hello)], &limits(limit, 128));
        assert_eq!(result.is_ok(), fits, "limit {limit}");
    }
    // Two fragments beyond the gap at offset zero, with room for one.
    let fragments: [(usize, &[u8]); 3] = [(50, &hello[50..60]), (70, &hello[70..80]), (0, &hello)];
    assert_matches!(
        assemble(&fragments, &limits(1024, 1)),
        Err(CaptureError::LimitExceeded("CRYPTO fragments"))
    );
    assert_eq!(assemble(&fragments, &limits(1024, 2)).unwrap(), hello);
}

#[test]
fn the_buffer_never_outgrows_the_message_bound() {
    let hello = message(100);
    let limits = limits(100, 128);
    let mut assembly = ClientHelloAssembly::new(&limits);
    // Overlapping retransmissions and fragments beyond the bound add nothing to hold.
    for (offset, data) in [
        (10, &hello[10..90]),
        (20, &hello[20..100]),
        (10, &hello[10..100]),
        (90, &hello[90..100]),
    ] {
        assembly.take_in(offset, data).unwrap();
        assert!(
            assembly.buffer.capacity() <= 100,
            "{}",
            assembly.buffer.capacity()
        );
    }
    assembly.take_in(0, &hello).unwrap();
    assert_eq!(assembly.client_hello().unwrap(), hello);
    assert_eq!(assembly.buffer.capacity(), hello.len());
}

#[test]
fn the_header_sizes_the_buffer_once() {
    let hello = message(3000);
    let mut assembly = ClientHelloAssembly::new(&CaptureLimits::default());
    assembly.take_in(0, &hello[..100]).unwrap();
    assert_eq!(assembly.buffer.capacity(), hello.len());
    let allocation = assembly.buffer.as_ptr();
    for start in (100..hello.len()).step_by(100) {
        assembly
            .take_in(start as u64, &hello[start..(start + 100).min(hello.len())])
            .unwrap();
    }
    assert_eq!(assembly.client_hello().unwrap(), hello);
    assert_eq!(
        assembly.buffer.as_ptr(),
        allocation,
        "no reallocation after the header"
    );
}

#[test]
fn fragments_straddling_the_bound_or_the_declared_end_are_clipped() {
    let limits = limits(100, 128);
    // Before the header, a fragment runs past the message bound.
    let hello = message(100);
    let mut straddling = hello[90..].to_vec();
    straddling.extend([0xee; 20]);
    let mut assembly = ClientHelloAssembly::new(&limits);
    assembly.take_in(90, &straddling).unwrap();
    assert!(
        assembly.buffer.capacity() <= 100,
        "{}",
        assembly.buffer.capacity()
    );
    assembly.take_in(0, &hello[..90]).unwrap();
    assert_eq!(assembly.client_hello().unwrap(), hello);
    // After the header, a fragment runs past the declared end.
    let hello = message(60);
    let mut straddling = hello[50..].to_vec();
    straddling.extend([0xee; 30]);
    let mut assembly = ClientHelloAssembly::new(&limits);
    assembly.take_in(0, &hello[..10]).unwrap();
    assembly.take_in(50, &straddling).unwrap();
    assert!(
        assembly.buffer.capacity() <= 100,
        "{}",
        assembly.buffer.capacity()
    );
    assembly.take_in(10, &hello[10..50]).unwrap();
    assert_eq!(assembly.client_hello().unwrap(), hello);
}
