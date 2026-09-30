//! Every typed header, grouped like the crate's own modules.

use super::ValuesExercise;

mod client_hints;
mod common;
mod forwarded;
mod other;

pub(super) const GROUPS: &[&[ValuesExercise]] = &[
    common::HEADERS,
    client_hints::HEADERS,
    forwarded::HEADERS,
    other::HEADERS,
];
