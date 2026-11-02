use super::*;
use crate::std::vec::Vec;
use core::net::Ipv4Addr;
use icmp::*;
use icmp::{Icmpv6Echo, Icmpv6EchoKind};

#[test]
fn checksum_preserves_odd_slice_boundaries() {
    let bytes = [0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7];
    assert_eq!(internet_checksum(&bytes), 0x220d); // RFC 1071 §3.
    for len in 0..=bytes.len() {
        for split in 0..=len {
            let mut checksum = InternetChecksum::new();
            checksum.update(&bytes[..split]);
            checksum.update(&[]);
            checksum.update(&bytes[split..len]);
            assert_eq!(checksum.finish(), internet_checksum(&bytes[..len]));
        }
    }
}

fn ipv4() -> Ipv4Header {
    Ipv4Header::new(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(198, 51, 100, 1),
        IpProtocol::UDP,
    )
}

fn ipv6(protocol: IpProtocol) -> Ipv6Header {
    Ipv6Header::new(
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
        protocol,
    )
}

#[test]
fn ipv4_edits_preserve_options_payload_and_checksum() {
    let mut bytes = [0; 128];
    let mut h = ipv4();
    h.traffic_class = 0xa2;
    h = h.with_identification(1234);
    let len = h
        .encode(&[1, 1, 0, 0], b"some payload", &mut bytes)
        .unwrap();
    let p = Ipv4Packet::parse(&bytes).unwrap();
    assert_eq!(p.as_bytes().len(), len);
    assert_eq!(p.header().len(), 24);
    assert_eq!(p.options(), &[1, 1, 0, 0]);
    assert_eq!(p.payload(), b"some payload");
    assert_eq!(p.fragment().identification, 1234);
    decrement_hop_limit(&mut bytes).unwrap();
    set_traffic_class(&mut bytes, 0xb3).unwrap();
    let p = Ipv4Packet::parse(&bytes).unwrap();
    assert_eq!(p.hop_limit(), 63);
    assert_eq!(p.traffic_class(), 0xb3);
    assert_eq!(p.source(), h.source);
    assert_eq!(p.destination(), h.destination);
    assert_eq!(p.options(), &[1, 1, 0, 0]);
    assert_eq!(p.payload(), b"some payload");
    bytes[8] ^= 1;
    assert_eq!(
        Ipv4Packet::parse(&bytes).unwrap_err(),
        IpPacketError::Checksum
    );
}

#[test]
fn encoding_and_exhausted_hop_limit_do_not_partially_mutate() {
    let mut output = [0xa5; 64];
    let saved = output;
    ipv4()
        .encode(&[3, 1, 0, 0], b"data", &mut output)
        .unwrap_err();
    assert_eq!(output, saved);
    let mut h = ipv4();
    h.try_with_fragment(1, false).unwrap_err();
    assert_eq!(output, saved);
    h.hop_limit = 1;
    h.encode(&[], b"data", &mut output).unwrap();
    let saved = output;
    assert_eq!(
        decrement_hop_limit(&mut output),
        Err(IpPacketError::HopLimit)
    );
    assert_eq!(output, saved);
    ipv6(IpProtocol::UDP)
        .try_with_flow_label(1 << 20)
        .unwrap_err();
    assert_eq!(output, saved);
}

#[test]
fn ipv6_extensions_and_non_initial_fragments_are_explicit() {
    let mut bytes = [0; 128];
    // Destination Options -> Fragment -> UDP.
    let payload = [
        44, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 1, 0, 0, 0, 42, 1, 2, 3, 4, 5, 6, 7, 8,
    ];
    let mut h = ipv6(IpProtocol::DESTINATION_OPTIONS);
    h = h.try_with_flow_label(0xabcde).unwrap();
    h.traffic_class = 0x89;
    h.encode(&payload, &mut bytes).unwrap();
    let p = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(p.extensions().count(), 2);
    assert_eq!(p.protocol(), Some(IpProtocol::UDP));
    assert_eq!(p.upper_layer_payload(), Some(&payload[16..]));
    assert_eq!(
        p.fragment(),
        Some(IpFragment {
            identification: 42,
            offset: 0,
            more: true
        })
    );
    set_traffic_class(&mut bytes, 0x42).unwrap();
    decrement_hop_limit(&mut bytes).unwrap();
    let p = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(p.flow_label(), 0xabcde);
    assert_eq!(p.traffic_class(), 0x42);
    assert_eq!(p.hop_limit(), 63);
    bytes[51] = 8; // non-initial fragment, no more fragments
    let p = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(p.protocol(), Some(IpProtocol::UDP));
    assert_eq!(p.upper_layer_payload(), None);
    bytes[48] = 60; // extension header unavailable in this fragment
    let p = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(p.protocol(), None);
    assert_eq!(p.extensions().count(), 2);
}

#[test]
fn invalid_extension_chains_and_lengths_are_rejected() {
    let mut bytes = [0; 512];
    for payload in [
        &[17, 1, 0, 0, 0, 0, 0, 0][..],
        &[17, 0, 0xc2, 4, 0, 1, 0, 0],
        &[17, 0, 2, 7, 0, 0, 0, 0],
    ] {
        ipv6(IpProtocol::HOP_BY_HOP)
            .encode(payload, &mut bytes)
            .unwrap();
        Ipv6Packet::parse(&bytes).unwrap_err();
    }
    ipv6(IpProtocol::DESTINATION_OPTIONS)
        .encode(
            &[0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0],
            &mut bytes,
        )
        .unwrap();
    assert_eq!(
        Ipv6Packet::parse(&bytes).unwrap_err(),
        IpPacketError::Header
    );
    let mut chain = [0; 33 * 8];
    for ext in chain.as_chunks_mut::<8>().0 {
        ext[0] = 60;
    }
    chain[32 * 8] = 17;
    ipv6(IpProtocol::DESTINATION_OPTIONS)
        .encode(&chain, &mut bytes)
        .unwrap();
    assert_eq!(
        Ipv6Packet::parse(&bytes).unwrap_err(),
        IpPacketError::ExtensionLimit
    );
}

#[test]
fn malformed_lengths_never_reach_packet_accessors() {
    let mut packet = [0; 128];
    let n = ipv4().encode(&[], b"payload", &mut packet).unwrap();
    for len in 0..n {
        IpPacket::parse(&packet[..len]).unwrap_err();
    }
    let n = ipv6(IpProtocol::new(252))
        .encode(b"payload", &mut packet)
        .unwrap();
    for len in 0..n {
        IpPacket::parse(&packet[..len]).unwrap_err();
    }
    let p = IpPacket::parse(&packet[..n]).unwrap();
    assert_eq!(p.protocol(), Some(IpProtocol::new(252)));
}

#[test]
fn icmp_errors_have_valid_checksums_and_bounded_quotations() {
    let mut original = [0; 1800];
    let mut reply = [0; 1280];
    let n = ipv4().encode(&[], &[7; 1700], &mut original).unwrap();
    let n = encode_icmp_error(
        IpPacket::parse(&original[..n]).unwrap(),
        ipv4().destination.into(),
        IcmpErrorKind::PacketTooBig { mtu: 1280 },
        &mut reply,
    )
    .unwrap()
    .unwrap();
    assert_eq!(n, 576);
    let p = IpPacket::parse(&reply[..n]).unwrap();
    assert_eq!(p.destination(), ipv4().source);
    let body = p.upper_layer_payload().unwrap();
    assert_eq!(internet_checksum(body), 0);
    assert_eq!(&body[..2], &[3, 4]);
    assert_eq!(
        IpPacketQuote::parse(&body[8..]).unwrap().destination,
        ipv4().destination
    );
    assert_eq!(
        encode_icmp_error(
            p,
            ipv4().source.into(),
            IcmpErrorKind::NoRoute,
            &mut original
        )
        .unwrap(),
        None
    );
    let h = ipv6(IpProtocol::UDP);
    let n = h.encode(&[7; 1700], &mut original).unwrap();
    let n = encode_icmp_error(
        IpPacket::parse(&original[..n]).unwrap(),
        h.destination.into(),
        IcmpErrorKind::PacketTooBig { mtu: 1280 },
        &mut reply,
    )
    .unwrap()
    .unwrap();
    assert_eq!(n, 1280);
    let p = IpPacket::parse(&reply[..n]).unwrap();
    let body = p.upper_layer_payload().unwrap();
    assert_eq!(icmpv6_checksum(h.destination, h.source, body).unwrap(), 0);
    assert_eq!(body[0], 2);
    assert_eq!(IpPacketQuote::parse(&body[8..]).unwrap().source, h.source);
}

#[test]
fn arbitrary_inputs_and_single_byte_mutations_are_panic_free() {
    fn inspect(bytes: &[u8]) {
        if let Ok(p) = IpPacket::parse(bytes) {
            let _ = (
                p.source(),
                p.destination(),
                p.protocol(),
                p.hop_limit(),
                p.traffic_class(),
                p.fragment(),
                p.upper_layer_payload(),
            );
            if let IpPacket::V6(p) = p {
                for ext in p.extensions() {
                    assert!(ext.bytes.len() >= 8);
                }
            }
        }
        _ = icmp::IpPacketQuote::parse(bytes);
    }
    let mut seed = 1u64;
    for len in 0..300 {
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            bytes.push(seed as u8);
        }
        inspect(&bytes);
    }
    let mut bytes = [0; 80];
    let n = ipv6(IpProtocol::DESTINATION_OPTIONS)
        .encode(&[17, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3], &mut bytes)
        .unwrap();
    for i in 0..n {
        for value in 0..=255 {
            let mut b = bytes;
            b[i] = value;
            inspect(&b[..n]);
        }
    }
}

#[test]
fn fragment_size_includes_the_reconstructed_header() {
    let mut h = ipv4();
    h = h.try_with_fragment(65512, false).unwrap();
    let mut bytes = [0; 128];
    h.encode(&[], &[0; 8], &mut bytes).unwrap_err();
    h = h.try_with_fragment(65504, false).unwrap();
    let n = h.encode(&[], &[0; 8], &mut bytes).unwrap();
    Ipv4Packet::parse(&bytes[..n]).unwrap();
    let mut payload = [0; 32];
    payload[0] = IpProtocol::FRAGMENT.value(); // eight-byte unfragmentable options
    payload[8] = IpProtocol::UDP.value();
    payload[10..12].copy_from_slice(&65520u16.to_be_bytes());
    let n = ipv6(IpProtocol::DESTINATION_OPTIONS)
        .encode(&payload, &mut bytes)
        .unwrap();
    assert_eq!(
        Ipv6Packet::parse(&bytes[..n]).unwrap_err(),
        IpPacketError::Length
    );
}

#[test]
fn checksum_matches_independent_odd_length_and_carry_vectors() {
    for (bytes, expected) in [
        (&[][..], 0xffff),
        (&[1][..], 0xfeff),
        (&[0xff][..], 0x00ff),
        (&[1, 2, 3][..], 0xfbfd),
        (&[0xff, 0xff, 0xff][..], 0x00ff),
    ] {
        assert_eq!(internet_checksum(bytes), expected);
    }
    // A wide scalar sum is independent of the incremental implementation's
    // per-word carry folding and buffering across odd slice boundaries.
    fn reference(bytes: &[u8]) -> u16 {
        let mut sum: u64 = bytes
            .chunks(2)
            .map(|pair| (u64::from(pair[0]) << 8) + u64::from(pair.get(1).copied().unwrap_or(0)))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
    let bytes: Vec<_> = (0..131_073).map(|i| (i * 37 + 19) as u8).collect();
    for len in [1, 2, 3, 511, 512, 513, 65_535, 131_072, 131_073] {
        let expected = reference(&bytes[..len]);
        assert_eq!(internet_checksum(&bytes[..len]), expected);
        let mut incremental = InternetChecksum::new();
        for part in bytes[..len].chunks(37) {
            incremental.update(part);
            incremental.update(&[]);
        }
        assert_eq!(incremental.finish(), expected);
    }
}

#[test]
fn ecn_ignores_dscp_bits() {
    assert_eq!(EcnCodepoint::from_bits(0b1111_1100), EcnCodepoint::NotEct);
    assert_eq!(EcnCodepoint::from_bits(0b1111_1101), EcnCodepoint::Ect1);
    assert_eq!(EcnCodepoint::from_bits(0b1111_1110), EcnCodepoint::Ect0);
    assert_eq!(EcnCodepoint::from_bits(0b1111_1111), EcnCodepoint::Ce);
}

#[test]
fn extension_registry_and_reserved_bits_are_shared_with_quotes() {
    for extension in [0, 43, 44, 51, 60, 135, 139, 140, 253, 254] {
        let length = if extension == 51 { 12 } else { 8 };
        let mut payload = [0; 24];
        payload[0] = IpProtocol::UDP.value();
        if extension == 51 {
            payload[1] = 1;
            payload[2..4].fill(0xff); // AH reserved bits are ignored on receipt.
        }
        if extension == 44 {
            payload[1] = 0xff;
            payload[3] = 6; // Fragment reserved bits are ignored on receipt.
        }
        let mut bytes = [0; 80];
        let size = ipv6(IpProtocol::new(extension))
            .encode(&payload[..length + 8], &mut bytes)
            .unwrap();
        let packet = Ipv6Packet::parse(&bytes[..size]).unwrap();
        assert_eq!(
            packet.protocol(),
            Some(IpProtocol::UDP),
            "extension {extension}"
        );
        assert_eq!(packet.extensions().count(), 1);
        let quote = icmp::IpPacketQuote::parse(&bytes[..40 + length]).unwrap();
        assert_eq!(quote.protocol, packet.protocol());
        icmp::IpPacketQuote::parse(&bytes[..40 + length - 1]).unwrap_err();
    }
    let mut bytes = [0; 80];
    let size = ipv6(IpProtocol::ESP).encode(&[0; 8], &mut bytes).unwrap();
    assert_eq!(Ipv6Packet::parse(&bytes[..size]).unwrap().protocol(), None);
}

#[test]
fn forwarded_ipv4_checksum_matches_reencoding_including_zero_boundaries() {
    let mut input = [0; 32];
    let mut output = [0; 32];
    let mut expected = [0; 32];
    for id in 0..=u16::MAX {
        let mut header = ipv4().with_identification(id);
        header.hop_limit = 2;
        let size = header
            .encode(&[1, 1, 0, 0], b"payload", &mut input)
            .unwrap();
        let packet = IpPacket::parse(&input[..size]).unwrap();
        assert_eq!(
            packet.encode_forwarded(output.as_mut_slice()).unwrap(),
            size
        );
        header.hop_limit -= 1;
        header
            .encode(&[1, 1, 0, 0], b"payload", &mut expected)
            .unwrap();
        assert_eq!(output[..size], expected[..size], "identification {id}");
    }
}

#[test]
fn quoted_header_validation_does_not_accept_malformed_options() {
    let mut bytes = [0; 64];
    ipv4()
        .encode(&[1, 1, 0, 0], b"payload", &mut bytes)
        .unwrap();
    bytes[20..24].copy_from_slice(&[3, 1, 0, 0]);
    bytes[10..12].fill(0);
    let checksum = internet_checksum(&bytes[..24]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    assert_eq!(
        icmp::IpPacketQuote::parse(&bytes[..24]),
        Err(IpPacketError::Header)
    );
}

#[test]
fn typed_echo_checks_checksum_code_and_fragmentation_without_copying() {
    let header = ipv6(IpProtocol::ICMPV6);
    let echo = Icmpv6Echo {
        kind: Icmpv6EchoKind::Request,
        identifier: 32,
        sequence: 7,
        data: b"payload!",
    };
    let mut bytes = [0; 128];
    let size = echo
        .encode(header.source, header.destination, &mut bytes)
        .unwrap();
    let parsed = Icmpv6Echo::parse(Ipv6Packet::parse(&bytes[..size]).unwrap()).unwrap();
    assert_eq!(parsed.kind, Icmpv6EchoKind::Request);
    assert_eq!(parsed.identifier, 32);
    assert_eq!(parsed.sequence, 7);
    assert_eq!(parsed.data, b"payload!");
    assert_eq!(parsed.data.as_ptr(), bytes[48..].as_ptr());
    let mut reply = [0; 128];
    parsed
        .reply()
        .encode(header.destination, header.source, &mut reply)
        .unwrap();
    assert_eq!(
        Icmpv6Echo::parse(Ipv6Packet::parse(&reply[..size]).unwrap())
            .unwrap()
            .kind,
        Icmpv6EchoKind::Reply
    );
    bytes[6] = IpProtocol::UDP.value();
    assert_eq!(
        Icmpv6Echo::parse(Ipv6Packet::parse(&bytes[..size]).unwrap()).unwrap_err(),
        IpPacketError::Field
    );
    bytes[6] = IpProtocol::ICMPV6.value();
    let mut fragment_body = vec![IpProtocol::ICMPV6.value(), 0, 0, 1, 0, 0, 0, 1];
    fragment_body.extend_from_slice(&bytes[40..size]);
    let mut fragmented = [0; 128];
    let fragment_size = ipv6(IpProtocol::FRAGMENT)
        .encode(&fragment_body, &mut fragmented)
        .unwrap();
    assert_eq!(
        Icmpv6Echo::parse(Ipv6Packet::parse(&fragmented[..fragment_size]).unwrap()).unwrap_err(),
        IpPacketError::Field
    );
    bytes[size - 1] ^= 1;
    Icmpv6Echo::parse(Ipv6Packet::parse(&bytes[..size]).unwrap()).unwrap_err();
    bytes[41] = 1;
    Icmpv6Echo::parse(Ipv6Packet::parse(&bytes[..size]).unwrap()).unwrap_err();
}

#[test]
fn ipv6_forwarding_preserves_extensions_and_input() {
    let mut bytes = [0; 128];
    let payload = [17, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4];
    let mut header = ipv6(IpProtocol::DESTINATION_OPTIONS);
    header.hop_limit = 3;
    let n = header.encode(&payload, &mut bytes).unwrap();
    let original = bytes;
    let mut forwarded = [0; 128];
    assert_eq!(
        IpPacket::parse(&bytes[..n])
            .unwrap()
            .encode_forwarded(forwarded.as_mut_slice())
            .unwrap(),
        n
    );
    assert_eq!(bytes, original);
    assert_eq!(forwarded[7], 2);
    forwarded[7] = 3;
    assert_eq!(&forwarded[..n], &bytes[..n]);
    header.hop_limit = 1;
    let n = header.encode(&payload, &mut bytes).unwrap();
    let before = forwarded;
    assert_eq!(
        IpPacket::parse(&bytes[..n])
            .unwrap()
            .encode_forwarded(forwarded.as_mut_slice()),
        Err(IpPacketError::HopLimit)
    );
    assert_eq!(forwarded, before);
}

#[test]
fn ipv6_fragment_bounds_exclude_the_fragment_header() {
    let mut output = [0; 128];
    // An empty non-final fragment is invalid, regardless of its Next Header.
    let empty_fragment = [17, 0, 0, 1, 0, 0, 0, 1];
    let n = ipv6(IpProtocol::FRAGMENT)
        .encode(&empty_fragment, &mut output)
        .unwrap();
    assert_eq!(
        Ipv6Packet::parse(&output[..n]).unwrap_err(),
        IpPacketError::Length
    );
    // Eight bytes before Fragment, eight bytes after it. Reassembly counts the
    // unfragmentable header but excludes Fragment itself (RFC 8200 section 4.5).
    for (offset, valid) in [(65512u16, true), (65520, false)] {
        let mut body = [0; 24];
        body[0] = IpProtocol::FRAGMENT.value();
        body[8] = IpProtocol::UDP.value();
        body[10..12].copy_from_slice(&offset.to_be_bytes());
        let n = ipv6(IpProtocol::DESTINATION_OPTIONS)
            .encode(&body, &mut output)
            .unwrap();
        if valid {
            Ipv6Packet::parse(&output[..n]).unwrap();
        } else {
            assert_eq!(
                Ipv6Packet::parse(&output[..n]).unwrap_err(),
                IpPacketError::Length
            );
        }
    }
}

#[test]
fn opaque_and_absent_ipv6_payloads_are_not_upper_layer_messages() {
    let mut bytes = [0; 64];
    for protocol in [IpProtocol::ESP, IpProtocol::NO_NEXT_HEADER, IpProtocol::UDP] {
        let n = ipv6(protocol).encode(b"opaque!!", &mut bytes).unwrap();
        let packet = Ipv6Packet::parse(&bytes[..n]).unwrap();
        assert_eq!(
            packet.upper_layer_payload(),
            if protocol == IpProtocol::UDP {
                Some(&b"opaque!!"[..])
            } else {
                None
            }
        );
        assert_eq!(
            packet.protocol(),
            if protocol == IpProtocol::ESP {
                None
            } else {
                Some(protocol)
            }
        );
    }
}

#[test]
fn forwarding_accepts_exact_buffers_and_preserves_short_buffers() {
    let mut input = [0; 128];
    for ipv6_packet in [false, true] {
        let n = if ipv6_packet {
            ipv6(IpProtocol::UDP)
                .encode(b"payload", &mut input)
                .unwrap()
        } else {
            ipv4().encode(&[], b"payload", &mut input).unwrap()
        };
        let packet = IpPacket::parse(&input[..n]).unwrap();
        let mut output = [0xa5; 128];
        assert_eq!(packet.encode_forwarded(&mut output[..n]), Ok(n));
        let forwarded = IpPacket::parse(&output[..n]).unwrap();
        assert_eq!(forwarded.hop_limit(), packet.hop_limit() - 1);
        assert_eq!(forwarded.source(), packet.source());
        assert_eq!(forwarded.destination(), packet.destination());
        assert!(output[n..].iter().all(|byte| *byte == 0xa5));
        for capacity in [0, n - 1] {
            output.fill(0xa5);
            assert_eq!(
                packet.encode_forwarded(&mut output[..capacity]),
                Err(IpPacketError::Truncated)
            );
            assert_eq!(output, [0xa5; 128]);
        }
        let mut appended = Vec::from([0xaa]);
        assert_eq!(packet.encode_forwarded(&mut appended), Ok(n));
        assert_eq!(appended[0], 0xaa);
        assert_eq!(appended.len(), n + 1);
        assert_eq!(
            IpPacket::parse(&appended[1..]).unwrap().hop_limit(),
            packet.hop_limit() - 1
        );
    }
}
