#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::http::{headers::Priority, structured_fields::parse_dictionary};

fuzz_target!(|input: &[u8]| {
    let dictionary = parse_dictionary(input, |_, _| {});
    let priority = Priority::parse(input);
    assert_eq!(dictionary.is_ok(), priority.is_ok());
    if let Ok(priority) = priority {
        assert_eq!(
            Priority::parse(priority.field_value().as_bytes()).unwrap(),
            priority
        );
    }
});
