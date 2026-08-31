#![no_main]

//! Fuzz standalone and compressed RFC 1035 DNS names.
//!
//! ```text
//! cargo +nightly fuzz run dns_name -- -max_len=65535
//! ```

use libfuzzer_sys::fuzz_target;
use rama::dns::wire::Name;

fuzz_target!(|data: &[u8]| {
    if let Ok(name) = Name::from_wire(data) {
        assert_eq!(name.as_wire(), data);
    }

    if data.is_empty() {
        return;
    }
    let offset = usize::from(data[0]) % data.len();
    let Ok((name, consumed)) = Name::from_message(data, offset) else {
        return;
    };

    assert!(consumed > 0);
    assert!(offset + consumed <= data.len());
    assert!(name.as_wire().len() <= Name::MAX_WIRE_LEN);
    let reparsed = Name::from_wire(name.as_wire()).ok();
    assert_eq!(reparsed.as_ref().map(Name::as_wire), Some(name.as_wire()));
});
