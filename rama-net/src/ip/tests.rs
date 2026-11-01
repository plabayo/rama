use super::*;
use crate::std::vec::Vec;
use core::net::Ipv4Addr;

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
    h.fragment.identification = 1234;
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
    h.fragment.offset = 1;
    h.encode(&[], b"data", &mut output).unwrap_err();
    assert_eq!(output, saved);
    h.fragment.offset = 0;
    h.hop_limit = 1;
    h.encode(&[], b"data", &mut output).unwrap();
    let saved = output;
    assert_eq!(
        decrement_hop_limit(&mut output),
        Err(IpPacketError::HopLimit)
    );
    assert_eq!(output, saved);
    let mut h = ipv6(IpProtocol::UDP);
    h.flow_label = 1 << 20;
    assert_eq!(h.encode(b"data", &mut output), Err(IpPacketError::Field));
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
    h.flow_label = 0xabcde;
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
    let n = ipv6(IpProtocol::new(253))
        .encode(b"payload", &mut packet)
        .unwrap();
    for len in 0..n {
        IpPacket::parse(&packet[..len]).unwrap_err();
    }
    let p = IpPacket::parse(&packet[..n]).unwrap();
    assert_eq!(p.protocol(), Some(IpProtocol::new(253)));
}

#[test]
fn icmp_errors_have_valid_checksums_and_bounded_quotations() {
    use icmp::*;
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
    h.fragment.offset = 65512;
    let mut bytes = [0; 128];
    h.encode(&[], &[0; 8], &mut bytes).unwrap_err();
    h.fragment.offset = 65504;
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
