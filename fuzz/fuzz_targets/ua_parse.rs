#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::ua::UserAgent;

fuzz_target!(|ua: String| {
    _ = UserAgent::new(ua);
});
