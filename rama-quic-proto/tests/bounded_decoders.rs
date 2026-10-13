use rama_core::bytes::Buf as _;
use rama_quic_proto::{
    ConnectionId, MAX_CID_SIZE,
    packet::{ConnectionIdParser as _, FixedLengthConnectionIdParser, PacketNumber},
};

#[test]
fn cid_buffer_decode_checks_length_and_available_bytes_without_consuming() {
    let bytes = [0xab; MAX_CID_SIZE + 2];
    for requested in (0..=MAX_CID_SIZE + 1).chain([usize::MAX]) {
        for available in 0..=bytes.len() {
            let mut input = &bytes[..available];
            let original = input;
            let result = ConnectionId::from_buf(&mut input, requested);
            if requested <= MAX_CID_SIZE && requested <= available {
                assert_eq!(result.unwrap().as_ref(), &bytes[..requested]);
                assert_eq!(input, &original[requested..]);
            } else {
                assert!(
                    result.is_err(),
                    "requested={requested}, available={available}"
                );
                assert_eq!(input, original);
            }
        }
    }

    let mut fragmented = (&bytes[..3]).chain(&bytes[3..MAX_CID_SIZE]);
    assert_eq!(
        ConnectionId::from_buf(&mut fragmented, MAX_CID_SIZE)
            .unwrap()
            .as_ref(),
        &bytes[..MAX_CID_SIZE]
    );
    assert_eq!(fragmented.remaining(), 0);
}

#[test]
fn fixed_cid_parser_rejects_oversized_configuration_without_truncating() {
    for requested in [MAX_CID_SIZE + 1, usize::MAX] {
        let bytes = [7; MAX_CID_SIZE + 2];
        let mut input = bytes.as_slice();
        FixedLengthConnectionIdParser::new(requested)
            .parse(&mut input)
            .unwrap_err();
        assert_eq!(input, bytes);
    }
}

#[test]
fn packet_number_decode_checks_every_width_and_short_input() {
    let bytes = [0x12, 0x34, 0x56, 0x78, 0x90];
    for width in 1..=4 {
        for available in 0..=bytes.len() {
            let mut input = &bytes[..available];
            let original = input;
            let result = PacketNumber::decode(width, &mut input);
            if available < width {
                assert!(result.is_err(), "width={width}, available={available}");
                assert_eq!(input, original);
            } else {
                let mut encoded = Vec::new();
                result.unwrap().encode(&mut encoded);
                assert_eq!(encoded, bytes[..width]);
                assert_eq!(input, &original[width..]);
            }
        }
    }

    let mut fragmented = (&bytes[..1]).chain(&bytes[1..3]);
    let number = PacketNumber::decode(3, &mut fragmented).unwrap();
    assert_eq!(number.len(), 3);
    assert_eq!(fragmented.remaining(), 0);
}

#[test]
fn packet_number_decode_rejects_invalid_width_without_consuming() {
    let bytes = [0; 8];
    for width in [0, 5, 8, usize::MAX] {
        let mut input = bytes.as_slice();
        PacketNumber::decode(width, &mut input).unwrap_err();
        assert_eq!(input, bytes);
    }
}
