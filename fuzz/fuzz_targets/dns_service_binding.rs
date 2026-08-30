//! Fuzz the SVCB/HTTPS RDATA parser with arbitrary, untrusted DNS bytes.
//!
//! The parser must remain bounded by the DNS record-size limit and must never
//! panic, read out of bounds, or hang for malformed names, parameter framing,
//! parameter values, and cross-parameter consistency constraints.
//!
//! Run with:
//!     cargo +nightly fuzz run dns_service_binding -- -max_len=65536
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(binding) = rama::dns::wire::ServiceBinding::parse_rdata(data) else {
        return;
    };

    assert_ne!(binding.is_alias_mode(), binding.is_service_mode());
    assert!(binding.target().as_wire().len() <= rama::dns::wire::Name::MAX_WIRE_LEN);
    assert_eq!(
        rama::dns::wire::Name::from_wire(binding.target().as_wire())
            .ok()
            .as_ref(),
        Some(binding.target())
    );

    let mut previous = None;
    for param in binding.params() {
        let key = u16::from(param.key());
        assert!(previous.is_none_or(|previous| previous < key));
        assert_eq!(binding.param(param.key()), Some(param));
        previous = Some(key);
    }
});
