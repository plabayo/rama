#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::http::headers::x_robots_tag::robots_tag_parse_iter;

fuzz_target!(|input: String| {
    let _: Vec<_> = robots_tag_parse_iter(input.as_bytes()).collect();
});
