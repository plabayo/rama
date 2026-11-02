//! Bounded wire/state sequences, including nonminimal varints and rejected updates.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rama::proxy::masque::connect_ip::{
    ADDRESS_ASSIGN, ADDRESS_REQUEST, ConnectIpCapsule, ConnectIpScope, ConnectIpState,
    ConnectIpStateLimits, ConnectIpTemplate, ROUTE_ADVERTISEMENT, decode_ip_datagram,
};
use rama::{http::Version, net::uri::UriTemplate};
use std::sync::LazyLock;

static TEMPLATE: LazyLock<Result<(ConnectIpTemplate, UriTemplate), &'static str>> =
    LazyLock::new(|| {
        let pattern = "https://proxy.example/proxy{?target,ipproto}";
        Ok((
            ConnectIpTemplate::try_new(pattern).map_err(|_error| "static CONNECT-IP template")?,
            UriTemplate::try_new(pattern).map_err(|_error| "static URI template")?,
        ))
    });

fuzz_target!(|bytes: &[u8]| {
    _ = decode_ip_datagram(bytes);
    assert_eq!(TEMPLATE.as_ref().map(|_| ()), Ok(()));
    if let (Ok(s), Ok((template, wire_template))) = (std::str::from_utf8(bytes), &*TEMPLATE) {
        let request = template.request(&ConnectIpScope::default(), Version::HTTP_3);
        assert_eq!(
            request.as_ref().map(|_| ()),
            Ok(()),
            "static wildcard request"
        );
        if let Ok(mut request) = request {
            let uri = wire_template.expand(|_| Some(s));
            if let Ok(uri) = uri.parse() {
                *request.uri_mut() = uri;
                _ = template.match_request(&request);
            }
        }
    }
    let mut state = ConnectIpState::new(ConnectIpStateLimits {
        max_entries: const { std::num::NonZeroU16::new(16).unwrap() },
        max_request_ids: const { std::num::NonZeroU32::new(32).unwrap() },
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
            let roundtrip = capsule
                .encode(16)
                .and_then(|encoded| ConnectIpCapsule::decode(ty, &encoded, 16));
            assert_eq!(
                roundtrip.as_ref(),
                Ok(&capsule),
                "accepted capsules must round-trip within the same entry limit",
            );
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
