//! Fuzz target for CONNECT-UDP parsing: proxy addresses with path templates, template
//! variable values and HTTP Datagram payloads.
//!
//! Goals: nothing panics; a parsed [`ProxyAddress`] round-trips through its display
//! form; a decoded context-0 payload never exceeds the UDP limit.
//!
//! Run with:
//!     cargo +nightly fuzz run masque_connect_udp
#![no_main]

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary},
    fuzz_target,
};
use rama::{
    net::address::ProxyAddress,
    proxy::masque::connect_udp::{
        ConnectUdpTarget, ContextId, MAX_UDP_PAYLOAD, decode_context_payload,
    },
};

#[derive(Arbitrary, Debug)]
struct Input {
    proxy: String,
    target_host: String,
    target_port: String,
    datagram: Vec<u8>,
}

fuzz_target!(|input: Input| {
    if let Ok(address) = input.proxy.parse::<ProxyAddress>() {
        let displayed = address.to_string();
        let again = displayed.parse::<ProxyAddress>();
        assert!(again.is_ok(), "{displayed:?} does not parse back");
        if let Ok(again) = again
            && address.credential.is_none()
        {
            assert_eq!(again, address, "{displayed:?}");
        }
    }
    _ = ConnectUdpTarget::from_template_values(&input.target_host, &input.target_port);
    if let Ok((context, payload)) = decode_context_payload(&input.datagram) {
        assert!(context != ContextId::UDP || payload.len() <= MAX_UDP_PAYLOAD);
    }
});
