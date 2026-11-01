//! Checked IP views and edits must remain valid for arbitrary wire bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rama::net::ip::{
    IpPacket, decrement_hop_limit,
    icmp::{IcmpErrorKind, IpPacketQuote, encode_icmp_error},
    set_traffic_class,
};

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65575 {
        return;
    }
    _ = IpPacketQuote::parse(bytes);
    if let Ok(packet) = IpPacket::parse(bytes) {
        let mut edited = packet.as_bytes().to_vec();
        let old_hop = packet.hop_limit();
        if decrement_hop_limit(&mut edited).is_ok() {
            assert_eq!(IpPacket::parse(&edited).unwrap().hop_limit(), old_hop - 1);
        } else {
            assert_eq!(edited, packet.as_bytes());
        }
        set_traffic_class(&mut edited, bytes.last().copied().unwrap_or(0)).unwrap();
        let again = IpPacket::parse(&edited).unwrap();
        assert_eq!(again.source(), packet.source());
        assert_eq!(again.destination(), packet.destination());
        if let IpPacket::V6(p) = packet {
            assert!(p.extensions().count() <= 32);
        }
        let mut output = [0; 1280];
        if let Ok(Some(n)) = encode_icmp_error(
            packet,
            packet.destination(),
            IcmpErrorKind::HopLimitExceeded,
            &mut output,
        ) {
            assert!(IpPacket::parse(&output[..n]).is_ok());
        }
    }
});
