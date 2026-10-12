//! Fuzz target for the request-head and idle deadlines of the HTTP servers.
//!
//! Goals: a head's allowance matches the documented rule (grace, then the
//! minimum average rate, capped by the ceiling) and only grows with its bytes,
//! and the per-connection state machine (heads, idle windows earned by a
//! request, drains, RTT samples) agrees at every observation with a reference
//! that recomputes each deadline from the whole history.
//!
//! Run with:
//!     cargo +nightly fuzz run http_deadlines
#![no_main]

use std::time::Duration;

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary},
    fuzz_target,
};
use rama::http::core::server::conn::{
    HeaderReadTimeout, IdleTimeout, fuzz_conn_deadlines, fuzz_head_allowance,
};

#[derive(Arbitrary, Debug)]
struct Input {
    grace: u64,
    ceiling: u64,
    min_rate: u32,
    rtt: Option<u64>,
    arrivals: Vec<u64>,
    head_enabled: bool,
    idle: Option<(u32, u32)>,
    /// (delay in ms, event kind, event value) steps of one connection.
    steps: Vec<(u16, u8, u16)>,
}

fuzz_target!(|input: Input| {
    let config = HeaderReadTimeout {
        grace: Duration::from_millis(input.grace),
        ceiling: Duration::from_millis(input.ceiling),
        min_rate: input.min_rate,
    };
    let rtt = input.rtt.map(Duration::from_millis);
    let grace = config
        .grace
        .saturating_add(rtt.map_or(Duration::ZERO, |rtt| {
            rtt.saturating_mul(4).min(config.grace)
        }))
        .min(config.ceiling);
    let mut total = 0u64;
    let mut previous = Duration::ZERO;
    for bytes in input.arrivals.into_iter().take(1024) {
        total = total.saturating_add(bytes);
        let got = fuzz_head_allowance(&config, rtt, total);
        let rate = if input.min_rate == 0 {
            config.ceiling.as_nanos()
        } else {
            u128::from(total) * 1_000_000_000 / u128::from(input.min_rate) + 1
        };
        let expected = rate.max(grace.as_nanos()).min(config.ceiling.as_nanos());
        assert_eq!(got.as_nanos(), expected);
        assert!(got >= previous);
        assert!(got >= grace && got <= config.ceiling);
        previous = got;
    }

    let idle = input.idle.map(|(first, idle)| IdleTimeout {
        first_request: Duration::from_millis(u64::from(first)),
        idle: Duration::from_millis(u64::from(idle)),
    });
    let head = input.head_enabled.then_some(config);
    let steps = &input.steps[..input.steps.len().min(256)];
    assert!(fuzz_conn_deadlines(idle, head, steps));
});
