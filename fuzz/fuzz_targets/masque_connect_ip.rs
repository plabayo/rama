//! Bounded wire/state sequences, including nonminimal varints and rejected updates.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rama::proxy::masque::connect_ip::{
    ADDRESS_ASSIGN, ADDRESS_REQUEST, ConnectIpCapsule, ConnectIpScope, ConnectIpState,
    ConnectIpStateLimits, ROUTE_ADVERTISEMENT, decode_ip_datagram,
};

fuzz_target!(|bytes: &[u8]| {
    _ = decode_ip_datagram(bytes);
    if let Ok(s) = std::str::from_utf8(bytes) {
        _ = ConnectIpScope::from_template_values(Some(s), Some(s));
    }
    let mut state = ConnectIpState::new(ConnectIpStateLimits {
        max_entries: 16,
        max_request_ids: 32,
    });
    let mut rest = bytes;
    for _ in 0..64 {
        if rest.len() < 3 {
            break;
        }
        let operation = rest[0];
        let n = usize::from(u16::from_be_bytes([rest[1], rest[2]])).min(rest.len() - 3);
        let raw = &rest[3..3 + n];
        rest = &rest[3 + n..];
        let ty = [ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT][usize::from(operation % 3)];
        if let Ok(capsule) = ConnectIpCapsule::decode(ty, raw, 16) {
            let encoded = capsule.encode(16).unwrap();
            assert_eq!(ConnectIpCapsule::decode(ty, &encoded, 16).unwrap(), capsule);
            let before = format!("{state:?}");
            let result = if operation & 4 == 0 {
                state.receive(&capsule)
            } else {
                state.sent(&capsule)
            };
            if result.is_err() {
                assert_eq!(format!("{state:?}"), before);
            }
            assert!(state.pending_requests() <= 32);
            assert!(state.local_addresses().len() <= 16);
            assert!(state.peer_routes().len() <= 16);
        }
    }
});
