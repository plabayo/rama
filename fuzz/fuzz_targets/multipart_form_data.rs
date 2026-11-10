//! `Content-Disposition: form-data` parameter parser fuzz target.
//!
//! Run with:
//!     cargo +nightly fuzz run multipart_form_data -- -max_len=1024
#![expect(
    clippy::panic,
    reason = "a violated fuzz invariant must produce a crash artifact"
)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::http::header::CONTENT_DISPOSITION;
use rama::http::protocols::multipart::FormData;
use rama::http::{HeaderMap, HeaderValue};

// A value reads the same from a header map as on its own, and the names it yields read
// back unchanged once quoted.
fuzz_target!(|data: &[u8]| {
    let parsed = FormData::parse(data).ok().map(FormData::into_parts);

    if let Ok(value) = HeaderValue::from_bytes(data) {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_DISPOSITION, value);
        let from_headers = FormData::from_headers(&headers)
            .ok()
            .map(FormData::into_parts);
        assert_eq!(from_headers, parsed);
    }

    let Some((name, file_name)) = parsed else {
        return;
    };
    let mut quoted = String::from("form-data");
    for (param, value) in [("name", &name), ("filename", &file_name)] {
        if let Some(value) = value {
            quoted.push_str("; ");
            quoted.push_str(param);
            quoted.push_str("=\"");
            for c in value.chars() {
                if matches!(c, '"' | '\\') {
                    quoted.push('\\');
                }
                quoted.push(c);
            }
            quoted.push('"');
        }
    }
    let Ok(again) = FormData::parse(quoted.as_bytes()) else {
        panic!("a quoted disposition was rejected");
    };
    assert_eq!(again.into_parts(), (name, file_name));
});
