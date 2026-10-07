//! Client hint headers.

use std::time::Duration;

use crate::{
    AcceptCh, CriticalCh, Downlink, Ect, Rtt, SaveData,
    fuzz::{
        ValuesExercise,
        parts::client_hints,
        support::{display, sink},
    },
};

pub(super) const HEADERS: &[ValuesExercise] = &[
    decode!(AcceptCh, |h| {
        client_hints(&h.0);
    }),
    decode!(CriticalCh, |h| {
        client_hints(&h.0);
    }),
    decode!(SaveData, |h| {
        sink((h.is_on(), bool::from(h)));
    }),
    decode!(Ect, |h| {
        display(&h);
        sink(h.as_str());
    }),
    decode!(Rtt, |h| {
        sink((h.as_millis(), h.as_duration(), Duration::from(h)));
    }),
    decode!(Downlink, |h| {
        sink((h.as_mbps(), f64::from(h)));
    }),
];
