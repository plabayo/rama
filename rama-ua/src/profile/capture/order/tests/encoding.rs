use super::*;

#[test]
fn protocol_order_has_fixed_canonical_bytes_and_digest() {
    let limits = OrderCaptureLimits::default();
    let canonical = capture(
        OrderNamespace::QuicParameter,
        &[(1, b"\x0a"), (15, b"nonce")],
    )
    .canonical(limits)
    .unwrap();
    assert_eq!(
        canonical.id.0,
        [
            155, 244, 168, 134, 169, 159, 190, 119, 170, 196, 54, 189, 115, 173, 103, 59, 156, 225,
            205, 73, 227, 106, 64, 82, 249, 67, 156, 142, 100, 120, 223, 6
        ]
    );
    assert_eq!(canonical.bytes.as_ref(), b"\x72\x61\x6d\x61\x2d\x70\x72\x6f\x66\x69\x6c\x65\x00\x00\x02\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x0a\x00\x00\x00\x00\x00\x00\x00\x0f\x01\x00\x00\x00\x00\x00\x00\x00\x05");
    let decoded = OrderedProtocolCapture::from_canonical(&canonical, limits).unwrap();
    assert_eq!(decoded.canonical(limits).unwrap().bytes, canonical.bytes);
}
