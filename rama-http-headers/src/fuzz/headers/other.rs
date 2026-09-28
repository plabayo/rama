//! Datastar, exotic, privacy and X-Robots-Tag headers.

use crate::{
    DatastarRequest, XRobotsTag,
    exotic::XClacksOverhead,
    fuzz::{
        ValuesExercise,
        parts::robots_tag,
        support::{display, roundtrip, sink},
    },
    privacy::{Dnt, SecGpc},
};

pub(super) const HEADERS: &[ValuesExercise] = &[
    decode!(DatastarRequest),
    decode!(XClacksOverhead, |h| {
        display(&h);
        sink(h.as_str());
    }),
    decode!(Dnt),
    decode!(SecGpc),
    decode!(XRobotsTag, |h| {
        for tag in h.0.iter() {
            robots_tag(tag);
        }
        robots_tag(h.first_tag());
        roundtrip(&XRobotsTag::new(h.into_first_tag()));
    }),
];
