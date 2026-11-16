#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::http::utils::http_date::{
    HTTP_DATE_LEN, MAX_HTTP_DATE_UNIX_SECS, format_http_date, parse_http_date,
};

fuzz_target!(|input: &[u8]| {
    if let Some(secs) = parse_http_date(input) {
        assert!(secs <= MAX_HTTP_DATE_UNIX_SECS);
        assert_eq!(parse_http_date(&format_http_date(secs)), Some(secs));
    }

    if let Some(bytes) = input.first_chunk::<8>() {
        let secs = u64::from_le_bytes(*bytes);
        let formatted = format_http_date(secs);
        assert_eq!(formatted.len(), HTTP_DATE_LEN);
        assert_eq!(
            parse_http_date(&formatted),
            Some(secs.min(MAX_HTTP_DATE_UNIX_SECS))
        );
    }
});
